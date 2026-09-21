package classifier

// portTable maps well-known port numbers to protocol labels.
// Port ranges (e.g. VNC 5900–5903) are expanded into individual entries.
//
// Source: PROTOCOL_CLASSIFICATION.md §4 — Protocol Lookup Table.
var portTable = map[uint16]string{
	// ── Web & CDN ──
	80:   "http",
	443:  "https", // TCP only; UDP 443 is handled as "quic" in Classify()
	8080: "http-alt",
	8443: "https-alt",

	// ── DNS ──
	53:   "dns",
	853:  "dot",
	784:  "doq",
	8853: "doq",
	5353: "mdns",

	// ── Infrastructure ──
	123: "ntp",
	67:  "dhcp",
	68:  "dhcp",
	161: "snmp",
	162: "snmp",
	514: "syslog",

	// ── Email ──
	25:  "smtp",
	465: "smtps",
	587: "submission",
	110: "pop3",
	995: "pop3s",
	143: "imap",
	993: "imaps",

	// ── Remote Access ──
	22:   "ssh",
	23:   "telnet",
	3389: "rdp",
	5900: "vnc",
	5901: "vnc",
	5902: "vnc",
	5903: "vnc",

	// ── File Sharing & Storage (LAN-heavy) ──
	445:  "smb",
	139:  "netbios",
	2049: "nfs",
	20:   "ftp",
	21:   "ftp",
	3260: "iscsi",

	// ── Media Servers (LAN) ──
	32400: "plex",
	8096:  "jellyfin",
	8920:  "jellyfin-tls",

	// ── VPN ──
	1194:  "openvpn",
	51820: "wireguard",
	500:   "ipsec",
	4500:  "ipsec",
	1701:  "l2tp",
	1723:  "pptp",

	// ── IoT / Smart Home ──
	1883: "mqtt",
	8883: "mqtts",
	5683: "coap",

	// ── P2P / Torrents ──
	6881: "bittorrent",
	6882: "bittorrent",
	6883: "bittorrent",
	6884: "bittorrent",
	6885: "bittorrent",
	6886: "bittorrent",
	6887: "bittorrent",
	6888: "bittorrent",
	6889: "bittorrent",
	6969: "bittorrent",

	// ── Gaming ──
	3074:  "xbox-live",
	3478:  "stun",
	3479:  "stun",
	3480:  "stun",
	25565: "minecraft",
	19132: "minecraft-bedrock",
	19133: "minecraft-bedrock",
	27015: "steam",
	27016: "steam",
	27017: "steam",
	27018: "steam",
	27019: "steam",
	27020: "steam",
	27021: "steam",
	27022: "steam",
	27023: "steam",
	27024: "steam",
	27025: "steam",
	27026: "steam",
	27027: "steam",
	27028: "steam",
	27029: "steam",
	27030: "steam",
	27031: "steam",
	27032: "steam",
	27033: "steam",
	27034: "steam",
	27035: "steam",
	27036: "steam",
	27037: "steam",
	27038: "steam",
	27039: "steam",
	27040: "steam",
	27041: "steam",
	27042: "steam",
	27043: "steam",
	27044: "steam",
	27045: "steam",
	27046: "steam",
	27047: "steam",
	27048: "steam",
	27049: "steam",
	27050: "steam",
}
