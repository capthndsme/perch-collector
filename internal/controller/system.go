package controller

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/capthndsme/perch-agentkit/hoststat"
)

// SystemInfo describes the host for the hello: "OpenWrt 24.10.2" from
// /etc/openwrt_release, else PRETTY_NAME from /etc/os-release, and the
// build's architecture.
func SystemInfo(fs hoststat.FS, arch string) *System {
	s := &System{Arch: arch}
	if kv := readShellVars(fs, "/etc/openwrt_release"); kv["DISTRIB_ID"] != "" {
		s.OS = strings.TrimSpace(kv["DISTRIB_ID"] + " " + kv["DISTRIB_RELEASE"])
	} else if kv := readShellVars(fs, "/etc/os-release"); kv["PRETTY_NAME"] != "" {
		s.OS = kv["PRETTY_NAME"]
	}
	return s
}

// readShellVars reads KEY='value' / KEY="value" lines.
func readShellVars(fs hoststat.FS, path string) map[string]string {
	out := map[string]string{}
	data, err := fs.Read(path)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		out[key] = strings.Trim(value, `"'`)
	}
	return out
}
