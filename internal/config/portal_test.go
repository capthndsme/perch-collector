package config

import "testing"

func TestPortalOptions(t *testing.T) {
	cfg, err := load(writeYAML(t, "listen: \"127.0.0.1:9800\"\n"), cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Portal != "auto" || cfg.PortalPort != 2080 || cfg.PortalFlushInterval != 0 {
		t.Fatalf("defaults %+v", cfg)
	}
	if !cfg.PortalEnabled(true, true) || cfg.PortalEnabled(true, false) || cfg.PortalEnabled(false, true) {
		t.Fatal("auto = OpenWrt with the WebSocket transport")
	}
	t.Setenv("PERCH_COLLECTOR_PORTAL", "0")
	t.Setenv("PERCH_COLLECTOR_PORTAL_PORT", "2081")
	t.Setenv("PERCH_COLLECTOR_PORTAL_FLUSH_INTERVAL", "2")
	t.Setenv("PERCH_COLLECTOR_PORTAL_STORAGE_MOUNT", " /mnt/usb ")
	cfg, err = load(writeYAML(t, "listen: \"127.0.0.1:9800\"\n"), cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Portal != "off" || cfg.PortalEnabled(true, true) || cfg.PortalPort != 2081 || cfg.PortalFlushInterval != 5 || cfg.PortalStorageMount != "/mnt/usb" {
		t.Fatalf("%+v", cfg)
	}
	t.Setenv("PERCH_COLLECTOR_PORTAL_PORT", "80")
	if _, err := load(writeYAML(t, "listen: \"127.0.0.1:9800\"\n"), cliOverrides{}); err == nil {
		t.Fatal("port 80 accepted")
	}
}
