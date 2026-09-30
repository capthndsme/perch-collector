package gwconfig

import "syscall"

// bindToDevice makes a reach check's TCP connect leave by one device
// (SO_BINDTODEVICE), whatever the routing table says.
func bindToDevice(dev string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if cerr := c.Control(func(fd uintptr) { err = syscall.BindToDevice(int(fd), dev) }); cerr != nil {
			return cerr
		}
		return err
	}
}
