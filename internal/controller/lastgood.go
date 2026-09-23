package controller

// Last-good controller address (gateway plan 2 section 4.2, WP-A): when
// the controller's host name does not resolve (the router's DNS broken by
// a bad apply, AdGuard Home down, rebind protection), the collector dials
// the address that last carried an accepted session instead. Only the TCP
// destination changes: the URL, the TLS server name and the Host header
// stay the controller's name, so certificate checks are unchanged.
//
// The address is remembered in memory and, when AddressCache names a file,
// on disk, written only when it changes (so a reboot with broken DNS still
// finds the controller).

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fallbackDialer struct {
	base   *net.Dialer
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	file   string

	mu        sync.Mutex
	lastGood  netip.Addr // persisted
	dialed    netip.Addr // the address of the newest connection
	local     netip.AddrPort
	remote    netip.AddrPort
	usingLast bool
}

func newFallbackDialer(file string) *fallbackDialer {
	d := &fallbackDialer{
		base: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: markCS6},
		file: file,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	if file != "" {
		if b, err := os.ReadFile(file); err == nil {
			if a, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil {
				d.lastGood = a
			}
		}
	}
	return d
}

// install puts the dialer into client's transport. It does nothing when
// the transport is not an *http.Transport or goes through a proxy (the
// dialed address would be the proxy's).
func (d *fallbackDialer) install(client *http.Client) bool {
	tr, ok := client.Transport.(*http.Transport)
	if !ok || proxyConfigured() {
		return false
	}
	tr.DialContext = d.DialContext
	return true
}

func proxyConfigured() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// DialContext resolves the host itself, dials each answer in turn, and
// falls back to the last good address when resolution fails.
func (d *fallbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return d.dial(ctx, network, ip, port)
	}
	ips, lerr := d.lookup(ctx, host)
	if lerr != nil || len(ips) == 0 {
		d.mu.Lock()
		last := d.lastGood
		d.mu.Unlock()
		if !last.IsValid() || ctx.Err() != nil {
			if lerr == nil {
				lerr = errors.New("no addresses")
			}
			return nil, lerr
		}
		d.mu.Lock()
		if !d.usingLast {
			log.Printf("controller: %s does not resolve (%v); dialing its last good address %s", host, lerr, last)
		}
		d.usingLast = true
		d.mu.Unlock()
		return d.dial(ctx, network, last, port)
	}
	d.mu.Lock()
	if d.usingLast {
		log.Printf("controller: %s resolves again", host)
	}
	d.usingLast = false
	d.mu.Unlock()
	var firstErr error
	for _, ip := range ips {
		conn, err := d.dial(ctx, network, ip, port)
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}

func (d *fallbackDialer) dial(ctx context.Context, network string, ip netip.Addr, port string) (net.Conn, error) {
	conn, err := d.base.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dialed = ip.Unmap()
	d.local = addrPort(conn.LocalAddr())
	d.remote = addrPort(conn.RemoteAddr())
	d.mu.Unlock()
	return conn, nil
}

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// endpoints of the newest connection.
func (d *fallbackDialer) endpoints() (netip.AddrPort, netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.local, d.remote
}

// confirm records the newest connection's address as the last good one:
// called once the controller accepted the session's hello.
func (d *fallbackDialer) confirm() {
	d.mu.Lock()
	ip := d.dialed
	changed := ip.IsValid() && ip != d.lastGood
	if changed {
		d.lastGood = ip
	}
	file := d.file
	d.mu.Unlock()
	if !changed || file == "" {
		return
	}
	if err := writeAtomic(file, []byte(ip.String()+"\n")); err != nil {
		log.Printf("controller: remembering the controller address in %s: %v", file, err)
	}
}

// lastGoodAddr is the remembered address (tests, logs).
func (d *fallbackDialer) lastGoodAddr() netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastGood
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
