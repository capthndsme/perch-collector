package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeYAML drops a config file in a temp dir and returns its path.
func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collector.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestDefaultsAnnounce(t *testing.T) {
	cfg := Defaults()
	if cfg.ServerURL != "" {
		t.Errorf("server_url default = %q, want empty (announcing off)", cfg.ServerURL)
	}
	if cfg.AnnounceInterval != 60 {
		t.Errorf("announce_interval default = %d, want 60", cfg.AnnounceInterval)
	}
	if !cfg.AnnounceAPIKey {
		t.Error("announce_api_key default = false, want true")
	}
	if cfg.InstanceID != "" {
		t.Errorf("instance_id default = %q, want empty", cfg.InstanceID)
	}
	if cfg.InstanceIDFile != DefaultInstanceIDFile {
		t.Errorf("instance_id_file default = %q, want %q", cfg.InstanceIDFile, DefaultInstanceIDFile)
	}
	if cfg.AnnounceTLSInsecure {
		t.Error("announce_tls_insecure default = true, want false")
	}
}

// The YAML file alone must be able to configure announcing.
func TestLoadYAMLAnnounceKeys(t *testing.T) {
	path := writeYAML(t, `
server_url: "http://192.168.1.10:8080"
announce_interval: 120
announce_api_key: false
instance_id: "yaml-instance-id"
instance_id_file: "/tmp/does-not-need-to-exist"
announce_tls_insecure: true
`)
	cfg, err := load(path, cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerURL != "http://192.168.1.10:8080" {
		t.Errorf("server_url = %q", cfg.ServerURL)
	}
	if cfg.AnnounceInterval != 120 {
		t.Errorf("announce_interval = %d, want 120", cfg.AnnounceInterval)
	}
	if cfg.AnnounceAPIKey {
		t.Error("announce_api_key = true, want the YAML's false to win over the true default")
	}
	if cfg.InstanceID != "yaml-instance-id" {
		t.Errorf("instance_id = %q", cfg.InstanceID)
	}
	if cfg.InstanceIDFile != "/tmp/does-not-need-to-exist" {
		t.Errorf("instance_id_file = %q", cfg.InstanceIDFile)
	}
	if !cfg.AnnounceTLSInsecure {
		t.Error("announce_tls_insecure = false, want true")
	}
}

// env > CLI > YAML, for the announce keys and for a pre-existing key that
// has all three sources.
func TestLoadPrecedence(t *testing.T) {
	path := writeYAML(t, `
listen: "10.0.0.1:1111"
server_url: "http://from-yaml:8080"
announce_interval: 90
announce_api_key: true
instance_id: "from-yaml"
instance_id_file: "/from/yaml"
announce_tls_insecure: false
`)

	// YAML only.
	cfg, err := load(path, cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "10.0.0.1:1111" || cfg.ServerURL != "http://from-yaml:8080" {
		t.Fatalf("YAML tier: listen=%q server_url=%q", cfg.Listen, cfg.ServerURL)
	}

	// CLI beats YAML.
	cfg, err = load(path, cliOverrides{Listen: "10.0.0.2:2222"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "10.0.0.2:2222" {
		t.Errorf("CLI tier: listen = %q, want the CLI value", cfg.Listen)
	}

	// Env beats both.
	t.Setenv("PERCH_COLLECTOR_LISTEN", "10.0.0.3:3333")
	t.Setenv("PERCH_COLLECTOR_SERVER_URL", "https://from-env:8443")
	t.Setenv("PERCH_COLLECTOR_ANNOUNCE_INTERVAL", "300")
	t.Setenv("PERCH_COLLECTOR_ANNOUNCE_API_KEY", "0")
	t.Setenv("PERCH_COLLECTOR_INSTANCE_ID", "from-env")
	t.Setenv("PERCH_COLLECTOR_INSTANCE_ID_FILE", "/from/env")
	t.Setenv("PERCH_COLLECTOR_ANNOUNCE_TLS_INSECURE", "1")

	cfg, err = load(path, cliOverrides{Listen: "10.0.0.2:2222"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "10.0.0.3:3333" {
		t.Errorf("env tier: listen = %q, want the env value", cfg.Listen)
	}
	if cfg.ServerURL != "https://from-env:8443" {
		t.Errorf("env tier: server_url = %q", cfg.ServerURL)
	}
	if cfg.AnnounceInterval != 300 {
		t.Errorf("env tier: announce_interval = %d, want 300", cfg.AnnounceInterval)
	}
	if cfg.AnnounceAPIKey {
		t.Error("env tier: announce_api_key = true, want false from PERCH_COLLECTOR_ANNOUNCE_API_KEY=0")
	}
	if cfg.InstanceID != "from-env" {
		t.Errorf("env tier: instance_id = %q", cfg.InstanceID)
	}
	if cfg.InstanceIDFile != "/from/env" {
		t.Errorf("env tier: instance_id_file = %q", cfg.InstanceIDFile)
	}
	if !cfg.AnnounceTLSInsecure {
		t.Error("env tier: announce_tls_insecure = false, want true from =1")
	}
}

// A missing config file is not an error, and the announce keys are still
// reachable through the environment alone (the OpenWrt and Docker shape).
func TestLoadEnvOnlyNoFile(t *testing.T) {
	t.Setenv("PERCH_COLLECTOR_SERVER_URL", "http://192.168.1.10:8080/")
	cfg, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerURL != "http://192.168.1.10:8080" {
		t.Errorf("server_url = %q, want the trailing slash normalised away", cfg.ServerURL)
	}
	if cfg.AnnounceInterval != 60 {
		t.Errorf("announce_interval = %d, want the 60 default", cfg.AnnounceInterval)
	}
}

func TestLoadEnvBadValues(t *testing.T) {
	tests := []struct {
		name string
		env  string
		val  string
	}{
		{"interval not a number", "PERCH_COLLECTOR_ANNOUNCE_INTERVAL", "soon"},
		{"announce_api_key not a bool", "PERCH_COLLECTOR_ANNOUNCE_API_KEY", "yes-please"},
		{"tls_insecure not a bool", "PERCH_COLLECTOR_ANNOUNCE_TLS_INSECURE", "maybe"},
		{"server_url not http", "PERCH_COLLECTOR_SERVER_URL", "ftp://192.168.1.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.val)
			if _, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{}); err == nil {
				t.Fatalf("load with %s=%q: want an error", tt.env, tt.val)
			}
		})
	}
}

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
		want    string
	}{
		{name: "empty disables announcing", in: "", want: ""},
		{name: "http", in: "http://192.168.1.10:8080", want: "http://192.168.1.10:8080"},
		{name: "https", in: "https://metrics.example.com", want: "https://metrics.example.com"},
		{name: "trailing slashes trimmed", in: "http://192.168.1.10:8080//", want: "http://192.168.1.10:8080"},
		{name: "surrounding space trimmed", in: "  http://192.168.1.10:8080 ", want: "http://192.168.1.10:8080"},
		{name: "ipv6 literal", in: "http://[fd00::1]:8080", want: "http://[fd00::1]:8080"},
		{name: "no scheme", in: "192.168.1.10:8080", wantErr: true},
		{name: "wrong scheme", in: "ftp://192.168.1.10", wantErr: true},
		{name: "no host", in: "http://", wantErr: true},
		{name: "unparseable", in: "http://[::1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ServerURL = tt.in
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q) = nil, want an error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q): %v", tt.in, err)
			}
			if cfg.ServerURL != tt.want {
				t.Errorf("server_url = %q, want %q", cfg.ServerURL, tt.want)
			}
		})
	}
}

func TestValidateAnnounceIntervalClamp(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"zero becomes the floor", 0, AnnounceIntervalMin},
		{"negative becomes the floor", -5, AnnounceIntervalMin},
		{"below the floor", 5, AnnounceIntervalMin},
		{"at the floor", 15, 15},
		{"in range", 60, 60},
		{"at the ceiling", 3600, 3600},
		{"above the ceiling", 86400, AnnounceIntervalMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ServerURL = "http://192.168.1.10:8080"
			cfg.AnnounceInterval = tt.in
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.AnnounceInterval != tt.want {
				t.Errorf("announce_interval = %d, want %d", cfg.AnnounceInterval, tt.want)
			}
		})
	}
}

// An API key the server's announce validator would reject must fail here,
// not silently 422 on every announce.
func TestValidateAnnouncedAPIKeyLength(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		announce  bool
		apiKey    string
		wantErr   bool
	}{
		{name: "short key announced", serverURL: "http://192.168.1.10:8080", announce: true, apiKey: "short", wantErr: true},
		{name: "short key not announced", serverURL: "http://192.168.1.10:8080", announce: false, apiKey: "short"},
		{name: "short key, no server", serverURL: "", announce: true, apiKey: "short"},
		{name: "exactly the minimum", serverURL: "http://192.168.1.10:8080", announce: true, apiKey: "12345678"},
		{name: "a real key", serverURL: "http://192.168.1.10:8080", announce: true, apiKey: "7f3c9d21ab64e8f07f3c9d21ab64e8f0"},
		{name: "no key at all", serverURL: "http://192.168.1.10:8080", announce: true, apiKey: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ServerURL = tt.serverURL
			cfg.AnnounceAPIKey = tt.announce
			cfg.APIKey = tt.apiKey
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate = nil, want an error naming the server's minimum")
				}
				if !strings.Contains(err.Error(), "8") {
					t.Errorf("err = %v, want it to name the minimum length", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// announce_tls_insecure on an http:// URL is a no-op, not an error: the
// daemon warns and carries on.
func TestValidateTLSInsecureOnPlainHTTP(t *testing.T) {
	cfg := Defaults()
	cfg.ServerURL = "http://192.168.1.10:8080"
	cfg.AnnounceTLSInsecure = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !cfg.AnnounceTLSInsecure {
		t.Error("announce_tls_insecure was cleared; it should survive as a no-op")
	}
}

func TestNDPIPartialExtraPacketsEnv(t *testing.T) {
	t.Setenv("PERCH_COLLECTOR_NDPI_PARTIAL_EXTRA_PACKETS", "0")
	cfg, err := load(filepath.Join(t.TempDir(), "missing.yaml"), cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.NDPIPartialExtraPackets != 0 {
		t.Fatalf("NDPIPartialExtraPackets = %d, want 0 from the env alone", cfg.NDPIPartialExtraPackets)
	}

	t.Setenv("PERCH_COLLECTOR_NDPI_PARTIAL_EXTRA_PACKETS", "banana")
	if _, err := load(filepath.Join(t.TempDir(), "missing.yaml"), cliOverrides{}); err == nil {
		t.Fatal("expected a parse error for a non-integer value")
	}

	t.Setenv("PERCH_COLLECTOR_NDPI_PARTIAL_EXTRA_PACKETS", "200")
	if _, err := load(filepath.Join(t.TempDir(), "missing.yaml"), cliOverrides{}); err == nil {
		t.Fatal("expected a range error for 200")
	}
}

func TestTransportResolution(t *testing.T) {
	cases := []struct {
		name, serverURL, apiKey, transport string
		want                               string // EffectiveTransport, or "error"
	}{
		{"no server", "", "0123456789abcdef", "auto", ""},
		{"auto with a key", "https://perch.example.com", "0123456789abcdef", "auto", TransportWebSocket},
		{"auto without a key", "https://perch.example.com", "", "", TransportPoll},
		{"poll forced", "https://perch.example.com", "0123456789abcdef", "poll", TransportPoll},
		{"websocket, any case", "https://perch.example.com", "0123456789abcdef", " WebSocket ", TransportWebSocket},
		{"websocket without a key", "https://perch.example.com", "", "websocket", "error"},
		{"websocket without a server", "", "0123456789abcdef", "websocket", "error"},
		{"unknown transport", "https://perch.example.com", "0123456789abcdef", "grpc", "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ServerURL, cfg.APIKey, cfg.Transport = tc.serverURL, tc.apiKey, tc.transport
			err := cfg.Validate()
			if tc.want == "error" {
				if err == nil {
					t.Fatalf("Validate accepted transport %q", tc.transport)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := cfg.EffectiveTransport(); got != tc.want {
				t.Fatalf("EffectiveTransport = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGatewayStatsSetting(t *testing.T) {
	for in, want := range map[string]string{"": "auto", "auto": "auto", "on": "on", "OFF": "off", "true": "on", "0": "off"} {
		cfg := Defaults()
		cfg.GatewayStats = in
		if err := cfg.Validate(); err != nil || cfg.GatewayStats != want {
			t.Errorf("%q -> %q %v, want %q", in, cfg.GatewayStats, err, want)
		}
	}
	cfg := Defaults()
	cfg.GatewayStats = "sometimes"
	if err := cfg.Validate(); err == nil {
		t.Error("gateway_stats sometimes accepted")
	}
	for _, tc := range []struct {
		setting  string
		openwrt  bool
		expected bool
	}{{"auto", true, true}, {"auto", false, false}, {"on", false, true}, {"off", true, false}} {
		cfg := Config{GatewayStats: tc.setting}
		if got := cfg.GatewayStatsEnabled(tc.openwrt); got != tc.expected {
			t.Errorf("%s on openwrt=%v: %v", tc.setting, tc.openwrt, got)
		}
	}
}

// The new keys from YAML, including an unquoted `on` and a list with a repeat.
func TestLoadYAMLTransportKeys(t *testing.T) {
	path := writeYAML(t, `
server_url: "https://perch.example.com"
api_key: "0123456789abcdef"
transport: websocket
gateway_stats: on
wan_interfaces: [wan0, " wan2", wan0, ""]
server_ca_file: /etc/ssl/private-ca.pem
`)
	cfg, err := load(path, cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Transport != TransportWebSocket || cfg.GatewayStats != GatewayStatsOn || cfg.ServerCAFile != "/etc/ssl/private-ca.pem" {
		t.Errorf("transport=%q gateway_stats=%q server_ca_file=%q", cfg.Transport, cfg.GatewayStats, cfg.ServerCAFile)
	}
	if strings.Join(cfg.WANInterfaces, ",") != "wan0,wan2" {
		t.Errorf("wan_interfaces = %q", cfg.WANInterfaces)
	}
	if len(cfg.Deprecated) != 0 {
		t.Errorf("deprecated = %v with no environment", cfg.Deprecated)
	}
}

// PERCH_COLLECTOR_* is read; GOCOLLECTOR_* still works while the new name
// is unset, is recorded once, and loses to the new name.
func TestEnvNamesNewAndLegacy(t *testing.T) {
	t.Setenv("PERCH_COLLECTOR_LISTEN", "10.0.0.9:9800")
	t.Setenv("GOCOLLECTOR_LISTEN", "10.0.0.8:9800")
	t.Setenv("GOCOLLECTOR_SERVER_URL", "https://perch.example.com")
	t.Setenv("GOCOLLECTOR_API_KEY", "0123456789abcdef")
	t.Setenv("PERCH_COLLECTOR_TRANSPORT", "poll")
	t.Setenv("PERCH_COLLECTOR_GATEWAY_STATS", "off")
	t.Setenv("PERCH_COLLECTOR_WAN_INTERFACES", "pppoe-wan, wan6")
	t.Setenv("PERCH_COLLECTOR_SERVER_CA_FILE", "/ca.pem")
	cfg, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "10.0.0.9:9800" {
		t.Errorf("listen = %q, want the PERCH_COLLECTOR_ value", cfg.Listen)
	}
	if cfg.ServerURL != "https://perch.example.com" || cfg.APIKey != "0123456789abcdef" {
		t.Errorf("legacy names not read: server_url=%q api_key=%q", cfg.ServerURL, cfg.APIKey)
	}
	if strings.Join(cfg.Deprecated, ",") != "GOCOLLECTOR_API_KEY,GOCOLLECTOR_SERVER_URL" {
		t.Errorf("deprecated = %v", cfg.Deprecated)
	}
	if cfg.EffectiveTransport() != TransportPoll || cfg.GatewayStats != GatewayStatsOff || cfg.ServerCAFile != "/ca.pem" {
		t.Errorf("transport=%q gateway_stats=%q ca=%q", cfg.EffectiveTransport(), cfg.GatewayStats, cfg.ServerCAFile)
	}
	if strings.Join(cfg.WANInterfaces, ",") != "pppoe-wan,wan6" {
		t.Errorf("wan_interfaces = %q", cfg.WANInterfaces)
	}
}

// A parse error names the variable that carried the bad value.
func TestEnvErrorNamesTheVariable(t *testing.T) {
	t.Setenv("PERCH_COLLECTOR_SNAP_LEN", "big")
	_, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err == nil || !strings.Contains(err.Error(), "PERCH_COLLECTOR_SNAP_LEN") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("PERCH_COLLECTOR_SNAP_LEN", "")
	t.Setenv("GOCOLLECTOR_PROMISCUOUS", "sometimes")
	_, err = load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err == nil || !strings.Contains(err.Error(), "GOCOLLECTOR_PROMISCUOUS") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstanceIDPath(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "perch-collector", "instance-id")
	legacy := filepath.Join(dir, "go-collector", "instance-id")
	if got := instanceIDPath(def, def, legacy); got != def {
		t.Errorf("neither file: %q", got)
	}
	os.MkdirAll(filepath.Dir(legacy), 0o755)
	os.WriteFile(legacy, []byte("0123456789abcdef"), 0o600)
	if got := instanceIDPath(def, def, legacy); got != legacy {
		t.Errorf("only the legacy file: %q", got)
	}
	os.MkdirAll(filepath.Dir(def), 0o755)
	os.WriteFile(def, []byte("fedcba9876543210"), 0o600)
	if got := instanceIDPath(def, def, legacy); got != def {
		t.Errorf("both files: %q", got)
	}
	if got := instanceIDPath("/etc/custom-id", def, legacy); got != "/etc/custom-id" {
		t.Errorf("configured path: %q", got)
	}
}

func TestDefaultsTransport(t *testing.T) {
	cfg := Defaults()
	if cfg.Transport != TransportAuto || cfg.GatewayStats != GatewayStatsAuto || cfg.WANInterfaces != nil || cfg.ServerCAFile != "" {
		t.Errorf("defaults: %+v", cfg)
	}
	if cfg.InstanceIDFile != "/var/lib/perch-collector/instance-id" {
		t.Errorf("instance_id_file default %q", cfg.InstanceIDFile)
	}
	if cfg.EffectiveTransport() != "" {
		t.Errorf("no server_url resolved to %q", cfg.EffectiveTransport())
	}
}

// The shipped template must load as is.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := load(filepath.Join("..", "..", "collector.example.yaml"), cliOverrides{})
	if err != nil {
		t.Fatalf("collector.example.yaml: %v", err)
	}
	if cfg.Transport != TransportAuto || cfg.GatewayStats != GatewayStatsAuto || cfg.InstanceIDFile != DefaultInstanceIDFile {
		t.Errorf("example: transport=%q gateway_stats=%q instance_id_file=%q", cfg.Transport, cfg.GatewayStats, cfg.InstanceIDFile)
	}
}
