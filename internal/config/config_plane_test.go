package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigPlaneDefaults(t *testing.T) {
	cfg, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	cp := cfg.ConfigPlane
	if cp.ConfigAccess != ConfigAccessNone || !reflect.DeepEqual(cp.ManagedConfigs, []string{"network", "dhcp", "firewall"}) ||
		cp.ConfigAllowInsecure || cp.ConfigConfirmMax != 600 || cp.StoragePath != "/etc/perch-collector" || cp.CaptureNetwork != "" {
		t.Fatalf("%+v", cp)
	}
}

func TestConfigPlaneYAMLAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "config_access: READ\nmanaged_config: [network, sqm, rpcd, network]\nconfig_confirm_max: 5\nstorage_path: /mnt/usb/perch\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(path, cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	cp := cfg.ConfigPlane
	// rpcd is never allowed; repeats collapse; the confirm cap is clamped.
	if cp.ConfigAccess != "read" || !reflect.DeepEqual(cp.ManagedConfigs, []string{"network", "sqm"}) || cp.ConfigConfirmMax != 30 || cp.StoragePath != "/mnt/usb/perch" {
		t.Fatalf("%+v", cp)
	}

	t.Setenv("PERCH_COLLECTOR_CONFIG_ACCESS", "write")
	t.Setenv("PERCH_COLLECTOR_MANAGED_CONFIGS", "dhcp, opennds")
	t.Setenv("PERCH_COLLECTOR_CONFIG_ALLOW_INSECURE", "1")
	t.Setenv("PERCH_COLLECTOR_CONFIG_CONFIRM_MAX", "99999")
	t.Setenv("PERCH_COLLECTOR_CAPTURE_NETWORK", "lan")
	t.Setenv("PERCH_COLLECTOR_STORAGE_PATH", "/tmp/perch")
	t.Setenv("PERCH_COLLECTOR_CONFIG_SIGN_KEY", " a-long-enough-signing-key ")
	t.Setenv("PERCH_COLLECTOR_PACKAGE_ALLOW", "tcpdump-mini, tcpdump-mini,iperf3")
	cfg, err = load(path, cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	cp = cfg.ConfigPlane
	if cp.ConfigAccess != "write" || !reflect.DeepEqual(cp.ManagedConfigs, []string{"dhcp", "opennds"}) || !cp.ConfigAllowInsecure ||
		cp.ConfigConfirmMax != 3600 || cp.CaptureNetwork != "lan" || cp.StoragePath != "/tmp/perch" ||
		cp.ConfigSignKey != "a-long-enough-signing-key" || !reflect.DeepEqual(cp.PackageAllow, []string{"tcpdump-mini", "iperf3"}) {
		t.Fatalf("%+v", cp)
	}
}

func TestConfigPlaneBadValues(t *testing.T) {
	for _, tt := range []struct{ env, val string }{
		{"PERCH_COLLECTOR_CONFIG_ACCESS", "admin"},
		{"PERCH_COLLECTOR_MANAGED_CONFIGS", "../passwd"},
		{"PERCH_COLLECTOR_STORAGE_PATH", "relative"},
		{"PERCH_COLLECTOR_CONFIG_CONFIRM_MAX", "soon"},
		{"PERCH_COLLECTOR_CONFIG_ALLOW_INSECURE", "maybe"},
		{"PERCH_COLLECTOR_CONFIG_SIGN_KEY", "short"},
	} {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv(tt.env, tt.val)
			if _, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{}); err == nil {
				t.Fatalf("%s=%s accepted", tt.env, tt.val)
			}
		})
	}
}

func TestConfigTransportOK(t *testing.T) {
	for _, tt := range []struct {
		url      string
		insecure bool
		want     bool
	}{
		{"https://perch.example.com", false, true},
		{"https://perch.example.com", true, false},
		{"http://192.168.1.10:8080", false, false},
		{"", false, false},
	} {
		c := Config{ServerURL: tt.url, AnnounceTLSInsecure: tt.insecure}
		if got := c.ConfigTransportOK(); got != tt.want {
			t.Errorf("%s insecure=%v: %v", tt.url, tt.insecure, got)
		}
	}
}
