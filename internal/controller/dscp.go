package controller

import "syscall"

// dscpCS6 is the TOS byte of DSCP CS6 (48 << 2): the controller socket
// rides in CAKE's voice tin under diffserv3/4 on a shaped WAN, ahead of
// bulk traffic (gateway plan 3 section 8, mitigation 3).
const dscpCS6 = 0xc0

// markCS6 is the dialer's Control: it marks every controller connection.
// A failure is ignored: an unmarked socket still works.
func markCS6(network, _ string, rc syscall.RawConn) error {
	_ = rc.Control(func(fd uintptr) {
		switch network {
		case "tcp6", "udp6":
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscpCS6)
		default:
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscpCS6)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscpCS6)
		}
	})
	return nil
}
