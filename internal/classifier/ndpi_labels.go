package classifier

import "strings"

// This file defines the nDPI protocol-id → label mapping. Kept free of
// cgo (no build tags) so it can be unit-tested and reasoned about
// without requiring libndpi at compile time. The numeric IDs match
// ndpi_protocol_ids.h from nDPI 5.0; TestNDPIProtocolIDsMatchLibrary
// (cgo build) checks every one of them against the header.

// nDPI master/app protocol IDs we explicitly recognize. Keep the
// names mirroring NDPI_PROTOCOL_* constants for grep-ability against
// the spec's protocol lookup tables in PROTOCOL_CLASSIFICATION.md §4.
const (
	ndpiProtocolUnknown        = 0
	ndpiProtocolFTPControl     = 1
	ndpiProtocolMail_POP       = 2
	ndpiProtocolMail_SMTP      = 3
	ndpiProtocolMail_IMAP      = 4
	ndpiProtocolDNS            = 5
	ndpiProtocolHTTP           = 7
	ndpiProtocolMDNS           = 8
	ndpiProtocolNTP            = 9
	ndpiProtocolNetBIOS        = 10
	ndpiProtocolNFS            = 11
	ndpiProtocolSSDP           = 12
	ndpiProtocolBGP            = 13
	ndpiProtocolSNMP           = 14
	ndpiProtocolXDMCP          = 15
	ndpiProtocolSMBv1          = 16
	ndpiProtocolSyslog         = 17
	ndpiProtocolDHCP           = 18
	ndpiProtocolMail_POPS      = 23
	ndpiProtocolNATS           = 68
	ndpiProtocolFTPData        = 175
	ndpiProtocolBitTorrent     = 37
	ndpiProtocolSignal         = 39
	ndpiProtocolTikTok         = 49
	ndpiProtocolDiscord        = 58
	ndpiProtocolMail_SMTPS     = 29
	ndpiProtocolMail_IMAPS     = 51
	ndpiProtocolSteam          = 74
	ndpiProtocolTelnet         = 77
	ndpiProtocolRDP            = 88
	ndpiProtocolVNC            = 89
	ndpiProtocolTLS            = 91
	ndpiProtocolSSH            = 92
	ndpiProtocolUSENET         = 93
	ndpiProtocolFacebook       = 119
	ndpiProtocolYouTube        = 124
	ndpiProtocolGoogle         = 126
	ndpiProtocolNetflix        = 133
	ndpiProtocolApple          = 140
	ndpiProtocolWhatsApp       = 142
	ndpiProtocolWindowsUpdate  = 147
	ndpiProtocolSpotify        = 156
	ndpiProtocolOpenVPN        = 159
	ndpiProtocolTor            = 163
	ndpiProtocolQUIC           = 188
	ndpiProtocolZoom           = 189
	ndpiProtocolTwitch         = 195
	ndpiProtocolWireGuard      = 206
	ndpiProtocolMicrosoft      = 212
	ndpiProtocolMicrosoft365   = 219
	ndpiProtocolMQTT           = 222
	ndpiProtocolGit            = 226
	ndpiProtocolAppleiCloud    = 143
	ndpiProtocolAppleiTunes    = 145
	ndpiProtocolGoogleServices = 239
	ndpiProtocolInstagram      = 211
)

// ndpiLabelTable maps an nDPI app-protocol ID to the label namespace
// we use everywhere else (matches the PORT_TABLE labels in
// port_table.go so end users don't see two flavours of "https").
//
// Anything not listed here falls through to a heuristic: if nDPI gave
// a known master protocol (e.g. TLS), we surface that; otherwise we
// fall back to the lowercase nDPI name as the spec recommends for
// "nDPI-only detections".
var ndpiLabelTable = map[uint16]string{
	// Foundational
	ndpiProtocolUnknown: "",
	ndpiProtocolDNS:     "dns",
	ndpiProtocolNTP:     "ntp",
	ndpiProtocolDHCP:    "dhcp",
	ndpiProtocolMDNS:    "mdns",
	ndpiProtocolSNMP:    "snmp",
	ndpiProtocolNetBIOS: "netbios",
	ndpiProtocolSyslog:  "syslog",
	ndpiProtocolSSDP:    "ssdp",
	ndpiProtocolBGP:     "bgp",

	// Email
	ndpiProtocolMail_SMTP:  "smtp",
	ndpiProtocolMail_SMTPS: "smtps",
	ndpiProtocolMail_POP:   "pop3",
	ndpiProtocolMail_POPS:  "pop3s",
	ndpiProtocolMail_IMAP:  "imap",
	ndpiProtocolMail_IMAPS: "imaps",

	// Web & generic transport
	ndpiProtocolHTTP: "http",
	ndpiProtocolTLS:  "https",
	ndpiProtocolQUIC: "quic",

	// File transfer / remote access
	ndpiProtocolFTPControl: "ftp",
	ndpiProtocolFTPData:    "ftp-data",
	ndpiProtocolSSH:        "ssh",
	ndpiProtocolTelnet:     "telnet",
	ndpiProtocolRDP:        "rdp",
	ndpiProtocolVNC:        "vnc",
	ndpiProtocolSMBv1:      "smb",
	ndpiProtocolNFS:        "nfs",

	// Tunnels / VPNs
	ndpiProtocolOpenVPN:   "openvpn",
	ndpiProtocolWireGuard: "wireguard",
	ndpiProtocolTor:       "tor",

	// P2P
	ndpiProtocolBitTorrent: "bittorrent",

	// Gaming
	ndpiProtocolSteam: "steam",

	// IoT / pub-sub
	ndpiProtocolMQTT: "mqtt",
	ndpiProtocolGit:  "git",

	// Streaming / social / cloud (the "DPI wins over port" category;
	// these will never come out of the port-based classifier).
	ndpiProtocolNetflix:        "netflix",
	ndpiProtocolYouTube:        "youtube",
	ndpiProtocolSpotify:        "spotify",
	ndpiProtocolTwitch:         "twitch",
	ndpiProtocolTikTok:         "tiktok",
	ndpiProtocolFacebook:       "facebook",
	ndpiProtocolInstagram:      "instagram",
	ndpiProtocolWhatsApp:       "whatsapp",
	ndpiProtocolDiscord:        "discord",
	ndpiProtocolSignal:         "signal",
	ndpiProtocolZoom:           "zoom",
	ndpiProtocolGoogle:         "google",
	ndpiProtocolGoogleServices: "google",
	ndpiProtocolApple:          "apple",
	ndpiProtocolAppleiCloud:    "apple",
	ndpiProtocolMicrosoft:      "microsoft",
	ndpiProtocolMicrosoft365:   "microsoft-365",
	ndpiProtocolWindowsUpdate:  "windows-update",
}

// ndpiLabel resolves an nDPI (app, master) protocol pair to our label
// namespace. The app protocol wins; the master protocol is used as a
// fallback (so a Netflix-over-TLS classification still surfaces as
// "netflix" rather than "https"). If neither is in the table the
// returned label is empty, signalling the caller to fall back to
// port-based reasoning or the lowercase nDPI name.
func ndpiLabel(appProto, masterProto uint16) string {
	if l, ok := ndpiLabelTable[appProto]; ok && l != "" {
		return l
	}
	if l, ok := ndpiLabelTable[masterProto]; ok && l != "" {
		return l
	}
	return ""
}

// normalizeCategory turns an nDPI category name ("SocialNetwork",
// "Download-FT", "Crypto_Currency", "IoT-Scada", "VoIP") into the
// lowercase-dash slug we expose ("social-network", "download-ft",
// "crypto-currency", "iot-scada", "voip"). A dash is inserted at a
// lower→upper boundary only when the lowercase run is at least two
// characters, so acronym-ish names such as IoT and VoIP stay intact.
// "Unspecified" (nDPI's category 0) becomes "" so callers can treat it
// as unknown.
func normalizeCategory(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s)+4)
	lowerRun := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'A' && b <= 'Z':
			if lowerRun >= 2 {
				out = append(out, '-')
			}
			out = append(out, b+('a'-'A'))
			lowerRun = 0
		case b >= 'a' && b <= 'z':
			out = append(out, b)
			lowerRun++
		case b == ' ' || b == '_' || b == '-':
			if len(out) > 0 && out[len(out)-1] != '-' {
				out = append(out, '-')
			}
			lowerRun = 0
		default:
			out = append(out, b)
			lowerRun = 0
		}
	}
	slug := strings.Trim(string(out), "-")
	if slug == "unspecified" {
		return ""
	}
	return slug
}
