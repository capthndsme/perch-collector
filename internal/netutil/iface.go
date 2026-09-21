package netutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// DetectDefaultInterface returns the name of the interface that carries the
// IPv4 default route, read from /proc/net/route. When several default routes
// exist the lowest metric wins; ties go to the first row. This is the capture
// interface a newcomer almost always wants: on a router it is the LAN bridge
// facing the clients only when the default route leaves through it, so
// operators with a dedicated WAN port still set `interface` explicitly.
func DetectDefaultInterface() (string, error) {
	f, err := os.Open(procRoute)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", procRoute, err)
	}
	defer f.Close()
	return parseDefaultInterface(f)
}

// parseDefaultInterface is the pure parser behind DetectDefaultInterface.
// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT.
func parseDefaultInterface(r io.Reader) (string, error) {
	const rtfUp = 0x1
	sc := bufio.NewScanner(r)
	headerSeen := false
	best := ""
	bestMetric := 0
	for sc.Scan() {
		line := sc.Text()
		if !headerSeen {
			headerSeen = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Default route: Destination == 00000000 AND Mask == 00000000.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			metric = 0
		}
		if best == "" || metric < bestMetric {
			best = fields[0]
			bestMetric = metric
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", procRoute, err)
	}
	if best == "" {
		return "", fmt.Errorf("no IPv4 default route in %s", procRoute)
	}
	return best, nil
}
