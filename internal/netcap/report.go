package netcap

import (
	"math"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/gateway"
)

// ActiveWindow is how recent a device's last frame must be to count in a
// network's activeDevices.
const ActiveWindow = 5 * time.Minute

// Reporter builds the networks part of the gateway report.
type Reporter struct {
	// Discover returns the router's interfaces (a cached read is fine).
	Discover func() Discovery
	// Selection supplies the configured WANs (Networks/Exclude unused).
	Selection Selection
	Sys       SysNet
	// Captured maps each captured device to its network.
	Captured func() map[string]string
	// Drops maps captured devices to their capture's kernel drops; nil =
	// not known.
	Drops func() map[string]uint64
	// Agg supplies the device counts and capture counters; nil = none.
	Agg *aggregator.Aggregator
	// FS reads /proc/net/dev ("" = the real one).
	FS hoststat.FS
	// Scope names the scope rule in the capture counters ("routed" or
	// "legacy").
	Scope func() string
	// Now is the clock (tests).
	Now func() time.Time

	mu    sync.Mutex
	last  map[string]sample
	rates map[string]rate
}

type sample struct {
	at     time.Time
	rx, tx uint64
}

type rate struct{ rx, tx float64 }

// Read returns the networks, or nil when netifd did not answer.
func (r *Reporter) Read() *[]gateway.Network {
	d := r.Discover()
	if !d.OK || !d.Netifd {
		return nil
	}
	p := MakePlan(d, r.Selection, r.Sys)
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	captured := map[string]string{}
	if r.Captured != nil {
		captured = r.Captured()
	}
	counters := map[string]aggregator.NetworkCounters{}
	devices := map[string]aggregator.NetworkDevices{}
	if r.Agg != nil {
		counters = r.Agg.NetworkTraffic()
		devices = r.Agg.NetworkDeviceCounts(ActiveWindow)
	}
	drops := map[string]uint64{}
	if r.Drops != nil {
		drops = r.Drops()
	}
	scope := "legacy"
	if r.Scope != nil {
		scope = r.Scope()
	}
	byDev := map[string]hoststat.NetDev{}
	if list, err := r.FS.NetDev(); err == nil {
		for _, nd := range list {
			byDev[nd.Name] = nd
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last, r.rates = map[string]sample{}, map[string]rate{}
	}
	out := make([]gateway.Network, 0, len(p.LAN))
	seenDev := map[string]bool{}
	for _, i := range p.LAN {
		n := gateway.Network{
			Name: i.Network, Device: i.Device, Proto: i.Proto, Up: i.Up,
			IPv4: append([]string{}, i.IPv4...),
			IPv6: append(append([]string{}, i.IPv6...), i.IPv6Assigned...),
		}
		if nd, ok := byDev[i.Device]; ok && i.Device != "" {
			rx, tx := nd.RxBytes(), nd.TxBytes()
			n.RxBytes, n.TxBytes = &rx, &tx
			if !seenDev[i.Device] {
				seenDev[i.Device] = true
				r.updateRate(i.Device, now, rx, tx)
			}
			if rt, ok := r.rates[i.Device]; ok {
				rxr, txr := rt.rx, rt.tx
				n.RxRate, n.TxRate = &rxr, &txr
			}
		}
		// Captured when its device is, and it is the network the frames
		// are attributed to or an alias on the same device.
		if netName, ok := captured[i.Device]; ok && i.Device != "" {
			n.Captured = true
			attr := netName
			c := devices[attr]
			if attr == i.Network {
				n.Devices, n.ActiveDevices = c.Devices, c.ActiveDevices
				if nc, ok := counters[attr]; ok {
					n.Capture = captureOf(nc, scope)
				} else {
					n.Capture = &gateway.NetworkCapture{Scope: scope}
				}
				if d, ok := drops[i.Device]; ok {
					n.Capture.KernelDrops = &d
				}
			}
		}
		out = append(out, n)
	}
	// Forget devices that are gone, so the rate map stays bounded.
	for dev := range r.last {
		if _, ok := byDev[dev]; !ok {
			delete(r.last, dev)
			delete(r.rates, dev)
		}
	}
	return &out
}

// updateRate refreshes a device's rate when its last sample is at least a
// second old. A counter that went backwards (device recreated) restarts
// the baseline and drops the rate. Caller holds r.mu.
func (r *Reporter) updateRate(dev string, now time.Time, rx, tx uint64) {
	prev, ok := r.last[dev]
	if ok && now.Sub(prev.at) < time.Second {
		return
	}
	r.last[dev] = sample{at: now, rx: rx, tx: tx}
	if !ok || rx < prev.rx || tx < prev.tx {
		delete(r.rates, dev)
		return
	}
	secs := now.Sub(prev.at).Seconds()
	r.rates[dev] = rate{rx: round1(float64(rx-prev.rx) / secs), tx: round1(float64(tx-prev.tx) / secs)}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func captureOf(c aggregator.NetworkCounters, scope string) *gateway.NetworkCapture {
	return &gateway.NetworkCapture{
		BytesInWAN: c.BytesInWAN, BytesOutWAN: c.BytesOutWAN,
		BytesInLAN: c.BytesInLAN, BytesOutLAN: c.BytesOutLAN,
		PacketsInWAN: c.PacketsInWAN, PacketsOutWAN: c.PacketsOutWAN,
		PacketsInLAN: c.PacketsInLAN, PacketsOutLAN: c.PacketsOutLAN,
		Scope: scope,
	}
}
