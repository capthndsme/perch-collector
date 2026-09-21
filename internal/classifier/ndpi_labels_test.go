package classifier

import "testing"

func TestNDPILabelAppWins(t *testing.T) {
	// Netflix-over-TLS: app=NETFLIX, master=TLS. Caller wants "netflix".
	if got := ndpiLabel(ndpiProtocolNetflix, ndpiProtocolTLS); got != "netflix" {
		t.Errorf("Netflix/TLS: got %q, want %q", got, "netflix")
	}
}

func TestNDPILabelMasterFallback(t *testing.T) {
	// App unknown, master TLS → "https" (gives us at least the master).
	if got := ndpiLabel(ndpiProtocolUnknown, ndpiProtocolTLS); got != "https" {
		t.Errorf("Unknown/TLS: got %q, want %q", got, "https")
	}
}

func TestNDPILabelEmptyWhenUnmapped(t *testing.T) {
	// Both unmapped — caller should fall back to port heuristic.
	if got := ndpiLabel(9999, 9998); got != "" {
		t.Errorf("9999/9998: got %q, want empty", got)
	}
}

func TestNDPILabelCoversSpecHeadliners(t *testing.T) {
	// These are the headline detections spec'd in
	// PROTOCOL_CLASSIFICATION.md §4 "nDPI-only detections".
	cases := map[uint16]string{
		ndpiProtocolBitTorrent:     "bittorrent",
		ndpiProtocolNetflix:        "netflix",
		ndpiProtocolYouTube:        "youtube",
		ndpiProtocolSpotify:        "spotify",
		ndpiProtocolDiscord:        "discord",
		ndpiProtocolZoom:           "zoom",
		ndpiProtocolWhatsApp:       "whatsapp",
		ndpiProtocolSignal:         "signal",
		ndpiProtocolMicrosoft365:   "microsoft-365",
		ndpiProtocolGoogleServices: "google",
	}
	for app, want := range cases {
		if got := ndpiLabel(app, ndpiProtocolUnknown); got != want {
			t.Errorf("app=%d: got %q, want %q", app, got, want)
		}
	}
}
