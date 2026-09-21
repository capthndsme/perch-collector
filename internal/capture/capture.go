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
	// For port-based classification this is ignored. We assemble it as a
	// contiguous []byte from the NetworkLayer; this allocates per packet
	// but spares us the slicing fragility around VLAN/QinQ headers in
	// `packet.Data()`.
	var ipPacket []byte
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		h := netLayer.LayerContents()
		p := netLayer.LayerPayload()
		if len(h) > 0 {
			ipPacket = make([]byte, len(h)+len(p))
			copy(ipPacket, h)
			copy(ipPacket[len(h):], p)
		}
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
