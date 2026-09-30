//go:build !linux

package gwconfig

import (
	"errors"
	"syscall"
)

// bindToDevice: only Linux can bind a socket to a device.
func bindToDevice(string) func(network, address string, c syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return errors.New("binding to a device needs Linux") }
}
