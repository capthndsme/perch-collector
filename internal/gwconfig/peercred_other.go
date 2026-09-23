//go:build !linux

package gwconfig

import "net"

// peerUID: no peer credentials here; the socket's 0600 mode decides.
func peerUID(net.Conn) (int, bool) { return 0, false }
