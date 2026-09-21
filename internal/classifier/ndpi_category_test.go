package classifier

import "testing"

func TestNormalizeCategory(t *testing.T) {
	cases := map[string]string{
		"Unspecified":      "",
		"":                 "",
		"Web":              "web",
		"Media":            "media",
		"Streaming":        "streaming",
		"SocialNetwork":    "social-network",
		"DataTransfer":     "data-transfer",
		"RemoteAccess":     "remote-access",
		"SoftwareUpdate":   "software-update",
		"FileSharing":      "file-sharing",
		"Download-FT":      "download-ft",
		"Crypto_Currency":  "crypto-currency",
		"IoT-Scada":        "iot-scada",
		"VoIP":             "voip",
		"VPN":              "vpn",
		"RPC":              "rpc",
		"ConnCheck":        "conn-check",
		"VirtAssistant":    "virt-assistant",
		"AdultContent":     "adult-content",
		"Advertisement":    "advertisement",
		"Site_Unavailable": "site-unavailable",
	}
	for in, want := range cases {
		if got := normalizeCategory(in); got != want {
			t.Errorf("normalizeCategory(%q) = %q, want %q", in, got, want)
		}
	}
}
