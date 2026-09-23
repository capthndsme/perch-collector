package qos

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// System is everything the engine touches outside its own memory: tc,
// links, files, netifd, the neighbour table and the clock. OS is the real
// router; tests use fakes or OS with a file root inside a network namespace.
type System interface {
	// Tc runs `tc [-s] -j -force -batch -` or `tc -force -batch -` with the
	// given lines on stdin.
	Tc(ctx context.Context, lines []string, json, stats bool) (stdout, stderr []byte, err error)
	// EnsureIfb creates an ifb device (if missing) and brings it up.
	EnsureIfb(name string) error
	// DeleteLink removes a link; a missing one is no error.
	DeleteLink(name string) error
	// Interfaces is `ubus call network.interface dump`.
	Interfaces() ([]byte, error)
	// Neighbors is the kernel's neighbour table.
	Neighbors() ([]Neighbor, error)
	// LocalMACs are the router's own interface MACs.
	LocalMACs() map[string]bool
	ReadFile(path string) ([]byte, error)
	// WriteFile replaces a file atomically (temporary file + rename).
	WriteFile(path string, data []byte, perm os.FileMode) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
	Now() time.Time
	// ClockSynced reports whether the clock is known to be right.
	ClockSynced() bool
	// Lock takes the reconcile lock (shared by the daemon and the CLI).
	Lock(path string) (unlock func(), err error)
}

// OS is the real system. Root prefixes every file path ("" = /).
type OS struct {
	Root string
	// TcPath is the tc binary; "" = "tc" from PATH.
	TcPath string
	// NtpMarker is the file the ntp hotplug script touches once busybox
	// ntpd has synchronised ("" = the default in the runtime directory).
	NtpMarker string
}

func (o *OS) path(p string) string {
	if o.Root == "" {
		return p
	}
	return filepath.Join(o.Root, p)
}

// Tc implements System.
func (o *OS) Tc(ctx context.Context, lines []string, asJSON, stats bool) ([]byte, []byte, error) {
	bin := o.TcPath
	if bin == "" {
		bin = "tc"
	}
	args := []string{}
	if stats {
		args = append(args, "-s")
	}
	if asJSON {
		args = append(args, "-j")
	}
	args = append(args, "-force", "-batch", "-")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// Interfaces implements System.
func (o *OS) Interfaces() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return observe.ExecRunner(ctx, "ubus", "call", "network.interface", "dump")
}

// Neighbors implements System.
func (o *OS) Neighbors() ([]Neighbor, error) {
	r := observe.NeighborReader{Env: &observe.Env{Root: o.Root}}
	list, err := r.Read()
	if err != nil {
		return nil, err
	}
	out := make([]Neighbor, 0, len(list))
	for _, n := range list {
		out = append(out, Neighbor{MAC: n.MAC, Device: n.Device, Confirmed: n.Reachable || n.State == "permanent"})
	}
	return out, nil
}

// LocalMACs implements System.
func (o *OS) LocalMACs() map[string]bool {
	out := map[string]bool{}
	list, _ := net.Interfaces()
	for _, i := range list {
		if m := NormalizeMAC(i.HardwareAddr.String()); m != "" {
			out[m] = true
		}
	}
	return out
}

// ReadFile implements System.
func (o *OS) ReadFile(p string) ([]byte, error) { return os.ReadFile(o.path(p)) }

// WriteFile implements System.
func (o *OS) WriteFile(p string, data []byte, perm os.FileMode) error {
	full := o.path(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

// Remove implements System.
func (o *OS) Remove(p string) error {
	err := os.Remove(o.path(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Stat implements System.
func (o *OS) Stat(p string) (os.FileInfo, error) { return os.Stat(o.path(p)) }

// Now implements System.
func (o *OS) Now() time.Time { return time.Now() }

// ClockSynced implements System: the kernel's clock status says an NTP
// discipline runs (busybox ntpd clears STA_UNSYNC; so does the host of a
// container), or the ntp hotplug script left its marker.
func (o *OS) ClockSynced() bool {
	marker := o.NtpMarker
	if marker == "" {
		marker = RuntimeDir + "/ntp-synced"
	}
	if _, err := os.Stat(o.path(marker)); err == nil {
		return true
	}
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false
	}
	const staUnsync = 0x0040
	const timeError = 5
	return tx.Status&staUnsync == 0 && state != timeError
}

// Lock implements System with flock(2) on path.
func (o *OS) Lock(p string) (func(), error) {
	full := o.path(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// rtnetlink constants (include/uapi/linux/rtnetlink.h, if_link.h).
const (
	rtmNewLink      = 16
	rtmDelLink      = 17
	iflaIfname      = 3
	iflaLinkinfo    = 18
	iflaInfoKind    = 1
	iffUp           = 0x1
	ifinfomsgLength = 16
)

func ifinfomsg(index int32, flags, change uint32) []byte {
	b := make([]byte, ifinfomsgLength)
	// family (1), pad (1), type (2), index (4), flags (4), change (4)
	binary.NativeEndian.PutUint32(b[4:8], uint32(index))
	binary.NativeEndian.PutUint32(b[8:12], flags)
	binary.NativeEndian.PutUint32(b[12:16], change)
	return b
}

func rtnl(msg netlink.Message) error {
	c, err := netlink.Dial(0 /* NETLINK_ROUTE */, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Execute(msg)
	return err
}

// EnsureIfb implements System over rtnetlink (RTM_NEWLINK kind ifb, then
// IFF_UP), so the package needs no ip-full.
func (o *OS) EnsureIfb(name string) error {
	if _, err := net.InterfaceByName(name); err != nil {
		ae := netlink.NewAttributeEncoder()
		ae.String(iflaIfname, name)
		ae.Nested(iflaLinkinfo, func(nae *netlink.AttributeEncoder) error {
			nae.String(iflaInfoKind, "ifb")
			return nil
		})
		attrs, err := ae.Encode()
		if err != nil {
			return err
		}
		err = rtnl(netlink.Message{
			Header: netlink.Header{Type: rtmNewLink, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl},
			Data:   append(ifinfomsg(0, 0, 0), attrs...),
		})
		if err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if ifc.Flags&net.FlagUp != 0 {
		return nil
	}
	err = rtnl(netlink.Message{
		Header: netlink.Header{Type: rtmNewLink, Flags: netlink.Request | netlink.Acknowledge},
		Data:   ifinfomsg(int32(ifc.Index), iffUp, iffUp),
	})
	if err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	return nil
}

// DeleteLink implements System.
func (o *OS) DeleteLink(name string) error {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	err = rtnl(netlink.Message{
		Header: netlink.Header{Type: rtmDelLink, Flags: netlink.Request | netlink.Acknowledge},
		Data:   ifinfomsg(int32(ifc.Index), 0, 0),
	})
	if err != nil && !errors.Is(err, syscall.ENODEV) {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}
