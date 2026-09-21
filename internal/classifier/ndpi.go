//go:build ndpi
// +build ndpi

// Package classifier — nDPI implementation. Compiled ONLY when the
// build tag `ndpi` is set (and cgo is enabled). See ndpi_stub.go for
// the no-op fallback used by default builds.
//
// Build:
//
//	go build -tags ndpi ./...
//
// Requires nDPI 5.0: headers and libndpi are located through pkg-config
// (`libndpi.pc`). Distro packages are still 4.x, so scripts/build-ndpi.sh
// builds 5.0 into a prefix and `make build-ndpi NDPI_PREFIX=<prefix>`
// points pkg-config at it.
package classifier

/*
#cgo pkg-config: libndpi

#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>
#include <ndpi_typedefs.h>
#include <ndpi_protocol_ids.h>
#include <ndpi_define.h>

// Written against the nDPI 5 API. Older headers stop here with one
// readable line instead of a wall of signature errors.
#if NDPI_MAJOR < 5
#error "perch-collector's nDPI binding requires nDPI >= 5.0 (scripts/build-ndpi.sh builds it into a prefix)"
#endif

// Wrapper: allocate a zeroed ndpi_flow_struct of the runtime-determined
// size. Pure-Go cgo can't sizeof() it (size is private to the lib's
// build), so we wrap calloc here.
static struct ndpi_flow_struct *gc_ndpi_alloc_flow(void) {
    u_int32_t sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
    return (struct ndpi_flow_struct *)calloc(1, sz);
}

// Wrapper: free the per-flow detection state, then the flow itself.
// Defensive on NULL so the eviction path can pass any UserData.
static void gc_ndpi_free_flow(struct ndpi_flow_struct *f) {
    if (f == NULL) return;
    ndpi_free_flow_data(f);
    free(f);
}

// Wrapper: feed one packet. nDPI 5 lets the caller state the packet
// direction and whether the flow's first packet was seen. We know
// neither for certain (the collector may join a flow mid-stream and the
// port heuristic is only a hint), so both stay "unknown" and the library
// works them out itself, exactly as ndpiReader does.
//
// cgo pointer rules, deliberately bent: `pkt` points into the Go packet
// buffer and `&info` into this C stack frame, and nDPI keeps both
// (mod->packet.iph/payload/..., mod->input_info) after the call returns,
// which the rules say C must not do. Nothing dereferences them between
// calls: the library only reads them inside ndpi_detection_process_packet
// and overwrites them at the start of the next call (its own contract;
// ndpiReader relies on it the same way). Copying the packet into C memory
// would cost a malloc+memcpy per packet for no safety gain, so leave it.
static ndpi_protocol gc_ndpi_process_packet(struct ndpi_detection_module_struct *mod,
                                            struct ndpi_flow_struct *f,
                                            const unsigned char *pkt, unsigned short len,
                                            u_int64_t now_ms) {
    struct ndpi_flow_input_info info;
    memset(&info, 0, sizeof(info));
    info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;
    info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
    return ndpi_detection_process_packet(mod, f, pkt, len, now_ms, &info);
}

// Wrapper: category name for a detection result. ndpi_get_proto_category
// prefers the category nDPI stamped on the flow itself (hostname / IP-list
// based, e.g. an ad domain over TLS) and falls back to the protocol's
// default. Returns "" for "Unspecified" so Go can treat it as unknown.
static const char *gc_ndpi_category_name(struct ndpi_detection_module_struct *mod, ndpi_protocol p) {
    ndpi_protocol_category_t c = ndpi_get_proto_category(mod, p);
    if (c == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) return "";
    const char *name = ndpi_category_get_name(mod, c);
    return name ? name : "";
}

// Wrapper: the default category of a bare protocol id (no flow context).
static const char *gc_ndpi_proto_default_category_name(struct ndpi_detection_module_struct *mod, u_int16_t id) {
    ndpi_protocol p;
    memset(&p, 0, sizeof(p));
    p.proto.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    p.proto.app_protocol = id;
    p.category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;
    return gc_ndpi_category_name(mod, p);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/capthndsme/perch-collector/internal/flow"
)

// ndpiMaxPacketsPerFlow caps the number of packets we feed into nDPI
// before giving up and locking in a label. The spec recommends ~20
// packets for the encrypted-app classifiers (TLS SNI is in the first
// ClientHello, QUIC fingerprints similarly need a few packets); 24 covers
// nDPI's own QUIC budget (1 + 20 extra packets) so a QUIC flow is not
// cut off one packet short of the library's decision.
const ndpiMaxPacketsPerFlow = 24

// ndpiPartialExtraPackets lives in ndpi_partial.go (untagged) so the config
// layer can set it in every build.

// NDPIClassifier wraps a single libndpi detection module behind a
// per-flow state table. Per the library's contract, the detection
// module is NOT thread-safe, so all cgo calls are serialised through
// `mu`. With a single capture goroutine this is essentially uncontended.
type NDPIClassifier struct {
	mod    unsafe.Pointer // *C.struct_ndpi_detection_module_struct
	table  *flow.Table
	mu     sync.Mutex
	closed atomic.Bool

	// evictedFlows counts flows whose native state was released by
	// table eviction (idle, cap or Close) rather than by finalisation.
	evictedFlows atomic.Uint64

	// Falls back to port-based labelling whenever nDPI doesn't have a
	// confident answer (yet, or after giveup).
	port *PortClassifier
}

// NewNDPIClassifier constructs and finalizes a libndpi detection
// module (nDPI 5 enables every built-in protocol by default), plus a
// flow table sized by `maxFlows` / `idleSeconds`. On any cgo failure
// (allocation, finalization) the constructor returns an error so callers
// can fall back to port-based classification.
func NewNDPIClassifier(maxFlows, idleSeconds int) (*NDPIClassifier, error) {
	return newNDPIClassifier(maxFlows, time.Duration(idleSeconds)*time.Second, 0)
}

// newNDPIClassifier is NewNDPIClassifier with the flow table's idle
// timeout and sweep interval as durations (0 sweep = the table's
// default), so tests can drive eviction in milliseconds.
func newNDPIClassifier(maxFlows int, idle, sweep time.Duration) (*NDPIClassifier, error) {
	mod := C.ndpi_init_detection_module(nil)
	if mod == nil {
		return nil, errors.New("ndpi_init_detection_module returned NULL")
	}
	if rc := C.ndpi_finalize_initialization(mod); rc != 0 {
		C.ndpi_exit_detection_module(mod)
		return nil, fmt.Errorf("ndpi_finalize_initialization failed (rc=%d)", int(rc))
	}

	c := &NDPIClassifier{
		mod:  unsafe.Pointer(mod),
		port: NewPortClassifier(),
	}
	c.table = flow.NewTable(maxFlows, idle, c.freeFlowFromTable)
	c.table.SetSweepInterval(sweep)
	c.table.Run()

	log.Printf("classifier: nDPI %s (api %d) initialized (max_flows=%d idle=%s partial_extra_packets=%d)",
		NDPIVersion(), NDPIAPIVersion(), maxFlows, idle, ndpiPartialExtraPackets.Load())
	return c, nil
}

// NDPIVersion is the release string of the linked libndpi
// (ndpi_revision(), e.g. "5.0.0").
func NDPIVersion() string {
	return C.GoString(C.ndpi_revision())
}

// NDPIAPIVersion is the linked libndpi's API version number
// (ndpi_get_api_version()).
func NDPIAPIVersion() int {
	return int(C.ndpi_get_api_version())
}

// Classify runs nDPI detection for a single packet. A flow is "done"
// once the library reports its classification as final, the flow has
// used up its inspection budget, or it has carried a usable partial
// label for ndpiPartialExtraPackets more packets; ndpi_detection_giveup
// then settles it (the last nDPI call on every flow) and its native state
// is freed. From that point the cached label answers every packet without
// cgo. While a flow is still being inspected, the packet is attributed to
// the library's partial label if it already has one (TLS with its SNI is
// known from the ClientHello on), else to the port-based label, so
// per-packet attribution isn't lost during the first packets of a
// connection.
//
// Concurrency: serialises through c.mu because libndpi's detection
// module is not thread-safe per-detector. Every Entry field except the
// table-owned LastSeen is read and written under c.mu only; the table's
// eviction callback takes c.mu too. The lookup happens outside c.mu, so
// an entry may be evicted in between: its Evicted flag is checked under
// c.mu before any native state is attached to it.
func (c *NDPIClassifier) Classify(srcIP, dstIP []byte, srcPort, dstPort uint16, transportProto uint8, ipPacket []byte) Result {
	if c.closed.Load() {
		return c.port.Classify(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket)
	}
	// Non-TCP/UDP: nDPI doesn't have a flow concept for it, mirror the
	// port-based classifier's "other" semantics.
	if transportProto != ProtoTCP && transportProto != ProtoUDP {
		return Result{Protocol: "other"}
	}
	// nDPI needs the IP packet to inspect. If the capture truncated it
	// to bare headers (snap_len too low), there's no payload to dissect,
	// so we just port-fallback.
	if len(ipPacket) < 20 {
		return c.port.Classify(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket)
	}

	now := time.Now()
	key, dstIsHi := flow.MakeKeyDir(srcIP, dstIP, srcPort, dstPort, transportProto)
	// The table stamps LastSeen on every lookup, so a long-lived flow that
	// finished inspection long ago is still never idle while it carries
	// traffic (its SNI would otherwise be lost to an idle eviction).
	entry, created := c.table.GetOrCreateAt(key, now)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under the lock: Close may have run since the check above
	// and torn the module down; never touch nDPI or allocate then.
	if c.closed.Load() || c.mod == nil {
		return c.port.Classify(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket)
	}

	if created {
		// Fix the server side once per flow: the first packet's destination,
		// unless the ports say the source is the service (we joined mid-flow).
		entry.ServerHi = dstIsHi
		if !ServerSideIsDst(srcPort, dstPort) {
			entry.ServerHi = !dstIsHi
		}
	}
	toServer := dstIsHi == entry.ServerHi

	if entry.Done {
		// Fast path for finalized flows — no cgo, no lock contention.
		if entry.Label != "" {
			return Result{Protocol: entry.Label, ServerName: entry.ServerName, Category: entry.Category, ToServer: toServer, NameExpected: entry.NameExpected}
		}
		return c.portResult(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket, entry.ServerName, entry.Category, toServer)
	}

	// The sweeper may have evicted this entry between the lookup and
	// taking c.mu (eviction frees UserData under c.mu, so it is nil now).
	// Anything attached from here on would never be freed: answer from
	// the port table and let the next packet start a fresh flow.
	if entry.Evicted() {
		return c.portResult(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket, "", "", toServer)
	}

	// Allocate the libndpi flow struct lazily on first sight.
	if entry.UserData == nil {
		entry.UserData = unsafe.Pointer(C.gc_ndpi_alloc_flow())
		if entry.UserData == nil {
			// calloc failure — degrade to port-based and stop trying.
			entry.Done = true
			entry.Label = ""
			return c.portResult(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket, "", "", toServer)
		}
	}

	mod := (*C.struct_ndpi_detection_module_struct)(c.mod)
	flowPtr := (*C.struct_ndpi_flow_struct)(entry.UserData)
	pkt := (*C.uchar)(unsafe.Pointer(&ipPacket[0]))
	pktLen := C.ushort(len(ipPacket))
	nowMs := C.u_int64_t(uint64(now.UnixMilli()))

	proto := C.gc_ndpi_process_packet(mod, flowPtr, pkt, pktLen, nowMs)
	entry.PacketCount++
	r := c.resolve(proto, flowPtr, srcPort, dstPort, transportProto)

	// Every result carries the flow's classification state. CLASSIFIED:
	// the library has all it wants and expects no more packets.
	// MONITORING: the label is final, the library would merely like to
	// keep extracting metadata (an opt-in mode, off here). PARTIAL: a
	// label that may still be refined (TLS after the ClientHello while
	// the ServerHello is awaited, STUN before the call app behind it is
	// known). INSPECTING: nothing yet.
	final := proto.state == C.NDPI_STATE_CLASSIFIED || proto.state == C.NDPI_STATE_MONITORING
	if !final {
		// A usable partial label (with the server name, for families that
		// carry one) starts the extra-packet allowance that bounds how
		// long the native state lives; see ndpiPartialExtraPackets.
		if entry.PartialAt == 0 && r.label != "" && (r.serverName != "" || !r.named) {
			entry.PartialAt = entry.PacketCount
		}
		switch {
		case entry.PacketCount >= ndpiMaxPacketsPerFlow:
			final = true
		case entry.PartialAt != 0 && entry.PacketCount-entry.PartialAt >= ndpiPartialExtraPackets.Load():
			final = true
		}
	}
	if final {
		if proto.state != C.NDPI_STATE_CLASSIFIED {
			// The last call on every flow: keeps a partial label,
			// otherwise guesses by port / IP (dpi.guess_on_giveup, on by
			// default), and seeds the library's caches (BitTorrent, Ookla,
			// mining) from what it saw. The label may thus be a guess.
			proto = C.ndpi_detection_giveup(mod, flowPtr)
			r = c.resolve(proto, flowPtr, srcPort, dstPort, transportProto)
		}
		entry.Done = true
		entry.Label = r.label
		entry.ServerName = r.serverName
		entry.Category = r.category
		entry.NameExpected = r.nameExpected
		// Free per-flow detection state immediately; we still keep the
		// Entry around so the cached label answers subsequent packets.
		C.gc_ndpi_free_flow(flowPtr)
		entry.UserData = nil
	}
	if r.label != "" {
		return Result{Protocol: r.label, ServerName: r.serverName, Category: r.category, ToServer: toServer, NameExpected: r.nameExpected}
	}
	return c.portResult(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket, r.serverName, r.category, toServer)
}

// resolved is what the binding derives from one nDPI result.
type resolved struct {
	label, serverName, category string
	named                       bool // the detected family carries a server name (TLS/HTTP/QUIC)
	nameExpected                bool
}

// resolve maps an nDPI result plus the flow's metadata to our label
// namespace. Caller must hold c.mu.
func (c *NDPIClassifier) resolve(proto C.ndpi_protocol, f *C.struct_ndpi_flow_struct, srcPort, dstPort uint16, transportProto uint8) resolved {
	app, master := uint16(proto.proto.app_protocol), uint16(proto.proto.master_protocol)
	var r resolved
	if app != ndpiProtocolUnknown {
		r.label = ndpiLabel(app, master)
		if r.label == "" {
			// Recognised protocol id but not in our label table — surface
			// the lib's lowercase name verbatim, per spec §3.4.
			r.label = c.protocolName(app)
		}
	}
	r.named = isNamedServerProtocol(master) || isNamedServerProtocol(app)
	if r.named {
		r.serverName = namedServer(f)
	}
	r.category = c.categoryName(proto)
	// A guessed-by-IP result (e.g. "apple" on TCP 443 with no hello seen)
	// still counts as name-carrying when the ports say TLS/HTTP/QUIC.
	r.nameExpected = r.named || NameExpectedForPorts(srcPort, dstPort, transportProto)
	return r
}

// portResult is the port-based fallback with the flow's known direction,
// server name and category (if any) carried along.
func (c *NDPIClassifier) portResult(srcIP, dstIP []byte, srcPort, dstPort uint16, transportProto uint8, ipPacket []byte, serverName, category string, toServer bool) Result {
	r := c.port.Classify(srcIP, dstIP, srcPort, dstPort, transportProto, ipPacket)
	r.ServerName = serverName
	r.Category = category
	r.ToServer = toServer
	return r
}

// categoryName resolves the slug for a detection result's category.
// Caller must hold c.mu (the detection module is not thread-safe).
func (c *NDPIClassifier) categoryName(p C.ndpi_protocol) string {
	if c.mod == nil {
		return ""
	}
	cs := C.gc_ndpi_category_name((*C.struct_ndpi_detection_module_struct)(c.mod), p)
	if cs == nil {
		return ""
	}
	return normalizeCategory(C.GoString(cs))
}

// ProtocolCategories enumerates every protocol nDPI knows, mapped to our
// label namespace, with the category the library assigns it by default.
// Labels that several nDPI ids share (e.g. "google") keep the first
// category seen in id order. Sorted by label; nil when nDPI is closed.
func (c *NDPIClassifier) ProtocolCategories() []ProtocolCategory {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() || c.mod == nil {
		return nil
	}
	mod := (*C.struct_ndpi_detection_module_struct)(c.mod)
	n := int(C.ndpi_get_num_protocols(mod))
	seen := make(map[string]struct{}, n)
	out := make([]ProtocolCategory, 0, n)
	for id := 1; id < n; id++ {
		label := ndpiLabel(uint16(id), ndpiProtocolUnknown)
		if label == "" {
			label = c.protocolName(uint16(id))
		}
		if label == "" || label == "unknown" {
			continue
		}
		if _, dup := seen[label]; dup {
			continue
		}
		cs := C.gc_ndpi_proto_default_category_name(mod, C.u_int16_t(id))
		category := ""
		if cs != nil {
			category = normalizeCategory(C.GoString(cs))
		}
		if category == "" {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, ProtocolCategory{Protocol: label, Category: category})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Protocol < out[j].Protocol })
	return out
}

// namedServer returns the flow's host_server_name (TLS SNI, HTTP Host,
// QUIC SNI). Only meaningful for protocols where that field names the
// *server* (see isNamedServerProtocol); for DNS it would be the query
// name, so callers gate on the protocol first.
func namedServer(f *C.struct_ndpi_flow_struct) string {
	name := C.GoString(&f.host_server_name[0])
	return strings.ToLower(strings.TrimSpace(name))
}

func isNamedServerProtocol(id uint16) bool {
	switch id {
	case uint16(C.NDPI_PROTOCOL_TLS), uint16(C.NDPI_PROTOCOL_HTTP),
		uint16(C.NDPI_PROTOCOL_QUIC), uint16(C.NDPI_PROTOCOL_HTTP_PROXY):
		return true
	}
	return false
}

// Close terminates the flow table (which drains every entry through
// freeFlowFromTable) and tears down the libndpi detection module.
// Subsequent Classify calls degrade gracefully to port-based.
func (c *NDPIClassifier) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.table.Stop()
	c.mu.Lock()
	if c.mod != nil {
		C.ndpi_exit_detection_module((*C.struct_ndpi_detection_module_struct)(c.mod))
		c.mod = nil
	}
	c.mu.Unlock()
}

// FlowCount exposes the current per-classifier flow-table size for
// debug/metrics endpoints. Cheap, lock-free read isn't possible, but
// the call rate is meant to be sub-Hz.
func (c *NDPIClassifier) FlowCount() int {
	return c.table.Len()
}

// freeFlowFromTable is the flow.Table eviction callback. Native state
// is still attached only to flows that never finalised (Done frees it
// right away), so those get the ndpi_detection_giveup every flow owes
// the library as its last call (it seeds the BitTorrent / Ookla / mining
// caches and applies the port / IP guess), then are freed.
//
// Called from the table's sweeper goroutine, NOT from the capture
// goroutine, and from Close's drain — so we take our own lock for cgo
// safety and read UserData only under it.
func (c *NDPIClassifier) freeFlowFromTable(e *flow.Entry) {
	if e == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f := (*C.struct_ndpi_flow_struct)(e.UserData)
	if f == nil {
		return
	}
	if c.mod != nil {
		C.ndpi_detection_giveup((*C.struct_ndpi_detection_module_struct)(c.mod), f)
	}
	C.gc_ndpi_free_flow(f)
	e.UserData = nil
	c.evictedFlows.Add(1)
}

// protocolName fetches the canonical lowercase nDPI name for a
// protocol id we don't have an explicit label for. Used for the long
// tail of nDPI detections (e.g. obscure gaming/IM apps) so they still
// surface as something more useful than "https".
func (c *NDPIClassifier) protocolName(id uint16) string {
	if c.mod == nil {
		return ""
	}
	cs := C.ndpi_get_proto_name(
		(*C.struct_ndpi_detection_module_struct)(c.mod),
		C.u_int16_t(id),
	)
	if cs == nil {
		return ""
	}
	name := C.GoString(cs)
	// Lowercase and normalize separators so the label namespace stays
	// consistent with the static map (e.g. "Microsoft365" → "microsoft365",
	// "Google Drive" → "google-drive").
	return normalizeName(name)
}

// normalizeName forces the spec's lowercase-dash label convention.
func normalizeName(s string) string {
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'A' && b <= 'Z':
			out = append(out, b+('a'-'A'))
		case b == ' ' || b == '_':
			out = append(out, '-')
		default:
			out = append(out, b)
		}
	}
	return string(out)
}

// guarded compile-time assertion that NDPIClassifier implements Classifier.
var _ Classifier = (*NDPIClassifier)(nil)

// Sentinel used by tests to confirm they're running against the cgo
// build (`-tags ndpi`). The stub file defines a corresponding `false`.
const NDPIAvailable = true
