package config

import (
	"fmt"
	"os"
	"strings"
)

// ConfigPlane is the router owner's opt-in to the Perch config plane (plan
// 1 section 3.2 of the managed gateway): whether the controller may read
// (and, in a later version, write) the router's UCI configuration, and
// which configs. It lives in the collector's own config, which the plane can
// never touch, so only someone with access to the router can change it.
type ConfigPlane struct {
	// ConfigAccess is none (default), read or write.
	ConfigAccess string `yaml:"config_access"`

	// ManagedConfigs is the allowlist of UCI configs the controller may read
	// and, with write access, write. The agent's own config, perch-apd, rpcd, uhttpd,
	// dropbear and luci are never allowed, whatever is listed.
	ManagedConfigs []string `yaml:"managed_config"`

	// ManagedConfigAuto (default true, gateway README 7.7): an installed
	// sibling package's config joins the allowlist by itself (sqm-scripts →
	// sqm, perch-qos → perch-qos). false keeps the allowlist to
	// managed_config.
	ManagedConfigAuto bool `yaml:"managed_config_auto"`

	// ManagedConfigExclude keeps single sibling configs off the allowlist
	// although their package is installed.
	ManagedConfigExclude []string `yaml:"managed_config_exclude"`

	// ConfigAllowInsecure accepts config writes over plain http:// or an
	// unverified certificate (with the controller's matching opt-in).
	ConfigAllowInsecure bool `yaml:"config_allow_insecure"`

	// ConfigConfirmMax caps any confirm window of a config apply, seconds.
	ConfigConfirmMax int `yaml:"config_confirm_max"`

	// ConfigSignKey is a fixed HMAC key of signed writes over an unverified
	// transport; empty = the key of a pairing with the controller
	// (perch-collector pair). The api_key (the Bearer token of every
	// connection) never signs. It never crosses the wire: the admin pastes
	// it into the controller.
	ConfigSignKey string `yaml:"config_sign_key"`

	// PackageAllow extends the packages the controller may install
	// (gateway.package.install).
	PackageAllow []string `yaml:"package_allow"`

	// StoragePath is where the agent keeps local state later (quotas,
	// vouchers). Today its storage type is only detected and reported in the
	// gateway capabilities. Apply snapshots always live on the root flash
	// (/etc/perch-collector/rollback), where the boot guard finds them.
	StoragePath string `yaml:"storage_path"`

	// CaptureNetwork is the UCI network the capture interface belongs to
	// (the OpenWrt package passes it), reported with the capabilities.
	CaptureNetwork string `yaml:"capture_network"`
}

// ConfigAccess values.
const (
	ConfigAccessNone  = "none"
	ConfigAccessRead  = "read"
	ConfigAccessWrite = "write"
)

// Config plane defaults and bounds.
const (
	ConfigConfirmMaxDefault = 600
	ConfigConfirmMaxMin     = 30
	ConfigConfirmMaxMax     = 3600
	DefaultStoragePath      = "/etc/perch-collector"
)

// DefaultManagedConfigs is the package default allowlist.
var DefaultManagedConfigs = []string{"network", "dhcp", "firewall"}

// configPlaneNeverAllowed are configs no allowlist can open (gateway README
// section 3.4); internal/gwconfig enforces the same list.
var configPlaneNeverAllowed = map[string]bool{
	"perch-collector": true, "perch-apd": true, "rpcd": true, "uhttpd": true, "dropbear": true, "luci": true,
}

func defaultConfigPlane() ConfigPlane {
	return ConfigPlane{
		ConfigAccess:      ConfigAccessNone,
		ManagedConfigs:    append([]string(nil), DefaultManagedConfigs...),
		ManagedConfigAuto: true,
		ConfigConfirmMax:  ConfigConfirmMaxDefault,
		StoragePath:       DefaultStoragePath,
	}
}

func (c *ConfigPlane) readEnv(env *envReader) {
	env.str("CONFIG_ACCESS", &c.ConfigAccess)
	if list, ok := env.list("MANAGED_CONFIGS"); ok {
		c.ManagedConfigs = list
	}
	env.boolean("MANAGED_CONFIG_AUTO", &c.ManagedConfigAuto)
	if list, ok := env.list("MANAGED_CONFIG_EXCLUDE"); ok {
		c.ManagedConfigExclude = list
	}
	env.boolean("CONFIG_ALLOW_INSECURE", &c.ConfigAllowInsecure)
	env.integer("CONFIG_CONFIRM_MAX", func(n int) { c.ConfigConfirmMax = n })
	env.str("CONFIG_SIGN_KEY", &c.ConfigSignKey)
	if list, ok := env.list("PACKAGE_ALLOW"); ok {
		c.PackageAllow = list
	}
	env.str("STORAGE_PATH", &c.StoragePath)
	env.str("CAPTURE_NETWORK", &c.CaptureNetwork)
}

func (c *ConfigPlane) validate() error {
	switch a := strings.ToLower(strings.TrimSpace(c.ConfigAccess)); a {
	case "", ConfigAccessNone:
		c.ConfigAccess = ConfigAccessNone
	case ConfigAccessRead, ConfigAccessWrite:
		c.ConfigAccess = a
	default:
		return fmt.Errorf("config_access must be none, read or write, got %q", c.ConfigAccess)
	}
	var list []string
	for _, name := range cleanList(c.ManagedConfigs) {
		if configPlaneNeverAllowed[name] {
			fmt.Fprintf(os.Stderr, "WARNING: managed_config %q is never readable or writable through the controller; ignored.\n", name)
			continue
		}
		if strings.ContainsAny(name, "/ \t") || strings.HasPrefix(name, ".") {
			return fmt.Errorf("managed_config %q is not a UCI config name", name)
		}
		list = append(list, name)
	}
	c.ManagedConfigs = list
	c.ManagedConfigExclude = cleanList(c.ManagedConfigExclude)
	for _, name := range c.ManagedConfigExclude {
		if strings.ContainsAny(name, "/ \t") || strings.HasPrefix(name, ".") {
			return fmt.Errorf("managed_config_exclude %q is not a UCI config name", name)
		}
	}
	if c.ConfigConfirmMax == 0 {
		c.ConfigConfirmMax = ConfigConfirmMaxDefault
	}
	if c.ConfigConfirmMax < ConfigConfirmMaxMin {
		c.ConfigConfirmMax = ConfigConfirmMaxMin
	}
	if c.ConfigConfirmMax > ConfigConfirmMaxMax {
		c.ConfigConfirmMax = ConfigConfirmMaxMax
	}
	c.StoragePath = strings.TrimSpace(c.StoragePath)
	if c.StoragePath == "" {
		c.StoragePath = DefaultStoragePath
	}
	if !strings.HasPrefix(c.StoragePath, "/") {
		return fmt.Errorf("storage_path must be absolute, got %q", c.StoragePath)
	}
	c.CaptureNetwork = strings.TrimSpace(c.CaptureNetwork)
	c.ConfigSignKey = strings.TrimSpace(c.ConfigSignKey)
	if c.ConfigSignKey != "" && len(c.ConfigSignKey) < 16 {
		return fmt.Errorf("config_sign_key must be at least 16 characters")
	}
	c.PackageAllow = cleanList(c.PackageAllow)
	return nil
}

// LoadEnv is the configuration from the defaults and the environment only
// (no YAML file, no flags), validated: what subcommands use.
func LoadEnv() (Config, error) {
	return load("", cliOverrides{})
}

// ConfigTransportOK reports whether the transport to the controller is
// fit for config writes on the agent's side: an https server_url with
// certificate verification on (announce_tls_insecure off; a server_ca_file
// is verification too).
func (c Config) ConfigTransportOK() bool {
	return strings.HasPrefix(c.ServerURL, "https://") && !c.AnnounceTLSInsecure
}
