package gwconfig

import (
	"fmt"
	"sort"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Generated values (gateway-sync protocol 2): a put option may be
// {"$generate":"wg_private_key"}, and the agent makes the value itself while
// it simulates the job, so the commit is verified against the exact value
// and the private key never exists anywhere but on the router. Only its
// public half leaves: in the apply's reply (`generated`) and in a retried
// apply's. Nothing secret crosses the wire, so it works on a signed plain
// HTTP session too (usesSecrets stays false). A dry run stages and shows
// GeneratedPlaceholder instead of a key; a rollback drops the key with the
// snapshot (the next attempt generates a new one). The value is never
// logged.
//
// Rules, else bad_params with data.reason generate_not_allowed: only the
// kind wg_private_key, only in a put, only on option private_key of a
// network `interface` whose resulting proto is wireguard.
//
// The key comes from wgtypes.GeneratePrivateKey (golang.zx2c4.com/wireguard/
// wgctrl, only its wgtypes package: crypto/rand plus x/crypto/curve25519,
// clamped the way `wg genkey` does it).

func init() { builtFeatures = append(builtFeatures, FeatureGenerateWGKey) }

// GeneratedPlaceholder is what a dry run stages and reports in place of a
// generated value.
const GeneratedPlaceholder = "<generated>"

// ReasonGenerateNotAllowed is data.reason of a refused {"$generate"}.
const ReasonGenerateNotAllowed = "generate_not_allowed"

// keyGen makes a value of a generated kind: the value that goes into the
// config and its public half.
type keyGen func(kind string) (value, public string, err error)

// generateValue is the real generator.
func generateValue(kind string) (string, string, error) {
	switch kind {
	case GenerateWGPrivateKey:
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", "", err
		}
		return k.String(), k.PublicKey().String(), nil
	}
	return "", "", fmt.Errorf("unknown kind %q", kind)
}

// placeholderValue is a dry run's generator: nothing random, nothing real.
func placeholderValue(string) (string, string, error) { return GeneratedPlaceholder, "", nil }

// WGPublicKey derives the WireGuard public key of a base64 private key, what
// `wg pubkey` prints.
func WGPublicKey(private string) (string, error) {
	k, err := wgtypes.ParseKey(private)
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

func generateNotAllowed(where, format string, args ...any) *PlaneError {
	return &PlaneError{Code: CodeBadParams, Message: where + ": " + ReasonGenerateNotAllowed + ": " + fmt.Sprintf(format, args...),
		Data: map[string]any{"reason": ReasonGenerateNotAllowed}}
}

// generatedOptions returns the options of op that ask for a generated value,
// sorted, after checking the rules. sec is the section as it is before the
// op (nil = new), for a proto kept with {"$keep":true}.
func generatedOptions(where string, op Op, sec *uci.Section) ([]string, error) {
	var names []string
	for name, v := range op.Options {
		if v.Generate != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sort.Strings(names)
	if op.Op != "put" {
		return nil, generateNotAllowed(where, "generated values go in a put")
	}
	for _, name := range names {
		kind := op.Options[name].Generate
		switch {
		case kind != GenerateWGPrivateKey:
			return nil, generateNotAllowed(where, "option %s: unknown kind %q (known: %s)", name, kind, GenerateWGPrivateKey)
		case op.Config != "network" || op.Type != "interface" || name != "private_key":
			return nil, generateNotAllowed(where, "option %s: %s only makes network interface option private_key", name, kind)
		}
	}
	proto := ""
	if v, ok := op.Options["proto"]; ok {
		switch {
		case v.Keep:
			if sec != nil {
				v, _ := sec.Get("proto")
				proto = v.Str()
			}
		case v.Secret == "" && v.Generate == "" && !v.Value.IsList:
			proto = v.Value.Str()
		}
	}
	if proto != "wireguard" {
		return nil, generateNotAllowed(where, "a WireGuard key needs proto wireguard (the interface's proto is %q)", proto)
	}
	return names, nil
}
