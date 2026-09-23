package capture

import (
	"fmt"
	"log"
	"net"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FullPacketSnapLen is the capture length used whenever packets are
// inspected beyond their headers (nDPI): the largest IPv4 packet plus its
// link header, in practice every packet the capture sees whole.
//
// A frame-sized snap length is not enough. Offloads hand the capture
// coalesced super-packets (GSO on the veth of a router in a container, GRO
// on a physical NIC): a post-quantum ClientHello (X25519MLKEM768, 1.5 to
// 2 KB, sent by current browsers and curl) arrives as ONE packet bigger than
// the MTU. Even without offloads a full-size 1500-byte IP packet is a
// 1514-byte Ethernet frame. Cut short, the ClientHello never reassembles in
// nDPI and the flow loses its server name.
const FullPacketSnapLen int32 = 65535

// SnapLen is the capture length to open the interface with: the configured
// snap_len for header-only (port) classification, at least
// FullPacketSnapLen when payload is inspected.
func SnapLen(configured int32, inspectsPayload bool) int32 {
	if inspectsPayload && configured < FullPacketSnapLen {
		return FullPacketSnapLen
	}
	return configured
}

// Engine captures packets from a network interface and feeds them to an Aggregator.
type Engine struct {
	handle     *pcap.Handle
	agg        *aggregator.Aggregator
	classifier classifier.Classifier
	iface      string
	done       chan struct{}
}

// New creates a new capture engine.
func New(iface string, snapLen int32, promisc bool, bpfFilter string, agg *aggregator.Aggregator, cls classifier.Classifier) (*Engine, error) {
	// Open the pcap handle.
	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("opening interface %q: %w", iface, err)
	}

	// Apply BPF filter if set.
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("setting BPF filter %q: %w", bpfFilter, err)
		}
		log.Printf("capture: BPF filter set: %s", bpfFilter)
	}

	return &Engine{
		handle:     handle,
		agg:        agg,
		classifier: cls,
		iface:      iface,
		done:       make(chan struct{}),
	}, nil
}

// Run starts the packet capture loop. It blocks until Stop() is called.
func (e *Engine) Run() {
	log.Printf("capture: starting on interface %s", e.iface)

	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-e.done:
			log.Println("capture: stopped")
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			// Check if we were stopped.
			select {
			case <-e.done:
				log.Println("capture: stopped")
				return
			default:
			}
			// Log non-fatal errors and continue.
			log.Printf("capture: error reading packet: %v", err)
			continue
		}

		e.processPacket(packet)
	}
}

// processPacket extracts Ethernet MACs, the L3 src/dst IPs, and packet length,
// then records the packet in the aggregator. Non-IP and non-Ethernet frames
// are dropped.
func (e *Engine) processPacket(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	var srcIP, dstIP net.IP
	var packetLen int

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
		packetLen = int(ipv4.Length)
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6.SrcIP
		dstIP = ipv6.DstIP
		packetLen = int(ipv6.Length) + 40 // IPv6 Length excludes the 40-byte fixed header.
	} else {
		return
	}

	var srcPort, dstPort uint16
	var transportProto uint8
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		transportProto = classifier.ProtoTCP
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		transportProto = classifier.ProtoUDP
	}

	// nDPI needs the full IP packet (header + everything below) to inspect.
	// For port-based classification this is ignored.
	var ipPacket []byte
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		ipPacket = networkBytes(netLayer.LayerContents(), netLayer.LayerPayload())
	}

	result := e.classifier.Classify(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket)

	if packetLen > 0 {
		e.agg.RecordPacket(eth.SrcMAC, eth.DstMAC, srcIP, dstIP, packetLen, aggregator.FlowInfo{
			Protocol:     result.Protocol,
			ServerName:   result.ServerName,
			Category:     result.Category,
			ToServer:     result.ToServer,
			NameExpected: result.NameExpected,
		})
	}
}

// networkBytes returns the IP packet (header + payload) as one slice. The
// decoder cuts both from the same capture buffer back to back, so this is
// normally a re-slice of that buffer with no copy (with full-packet capture
// a copy would be up to 64 KB per coalesced packet); if they are not
// adjacent it falls back to a copy. The result is only valid until the next
// packet is read, which suits Classify: it borrows the slice for the call.
func networkBytes(header, payload []byte) []byte {
	if len(header) == 0 {
		return nil
	}
	if len(payload) == 0 {
		return header
	}
	n := len(header) + len(payload)
	if cap(header) >= n {
		if whole := header[:n]; &whole[len(header)] == &payload[0] {
			return whole
		}
	}
	out := make([]byte, n)
	copy(out, header)
	copy(out[len(header):], payload)
	return out
}

// Stop signals the capture loop to exit and closes the pcap handle.
func (e *Engine) Stop() {
	select {
	case <-e.done:
		// Already stopped.
		return
	default:
		close(e.done)
		e.handle.Close()
	}
}
