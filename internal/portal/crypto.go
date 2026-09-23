// Package portal is the router side of the Perch guest portal (captive
// portal): Perch-owned nftables enforcement, the guest pages (FAS) on
// portal_port, the grant store, the enforcement tick and the portal.* RPCs
// on the collector socket. The controller side and the wire contract are in
// the controller repository, docs/gateway/portal.md; this package follows it
// exactly and is tested against its pinned vectors.
package portal

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HMAC scheme v1 (docs/gateway/portal.md §6). The router never sees APP_KEY:
// it receives gatewayKey in portal.configure and derives the two sub-keys.
//
//	voucherKey = HMAC-SHA256(gatewayKey, "perch-portal-voucher-v1")
//	signKey    = HMAC-SHA256(gatewayKey, "perch-portal-sign-v1")
//	verifier   = hex(HMAC-SHA256(voucherKey, "v1\n<gatewayId>\n<code>"))
//	signature  = base64url_nopad(HMAC-SHA256(signKey, canonical))
const (
	voucherSubkeyLabel = "perch-portal-voucher-v1"
	signSubkeyLabel    = "perch-portal-sign-v1"
	keyBytes           = 32

	GroupRecordTag   = "perch-portal-group-v1"
	GrantRecordTag   = "perch-portal-grant-v1"
	VoucherRecordTag = "perch-portal-voucher-v1"
)

// Keys are one gateway's portal keys at one epoch.
type Keys struct {
	GatewayID  int64
	Epoch      int64
	GatewayKey []byte
	VoucherKey []byte
	SignKey    []byte
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// KeysFrom derives the sub-keys from the gatewayKey the controller sent.
func KeysFrom(gatewayKey []byte, gatewayID, epoch int64) (*Keys, error) {
	if len(gatewayKey) != keyBytes {
		return nil, errors.New("gateway key must be 32 bytes")
	}
	if gatewayID < 1 {
		return nil, fmt.Errorf("invalid gateway id %d", gatewayID)
	}
	if epoch < 1 {
		return nil, fmt.Errorf("invalid key epoch %d", epoch)
	}
	k := &Keys{GatewayID: gatewayID, Epoch: epoch, GatewayKey: append([]byte(nil), gatewayKey...)}
	k.VoucherKey = hmacSHA256(k.GatewayKey, voucherSubkeyLabel)
	k.SignKey = hmacSHA256(k.GatewayKey, signSubkeyLabel)
	return k, nil
}

// DecodeGatewayKey decodes the base64url (no padding) key of portal.configure.
func DecodeGatewayKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("gatewayKey: %w", err)
	}
	if len(b) != keyBytes {
		return nil, errors.New("gatewayKey: must be 32 bytes")
	}
	return b, nil
}

// Verifier is the offline-redemption verifier of a normalized code on this
// gateway (64 lower-case hex characters).
func (k *Keys) Verifier(normalizedCode string) string {
	return hex.EncodeToString(hmacSHA256(k.VoucherKey, "v1\n"+strconv.FormatInt(k.GatewayID, 10)+"\n"+normalizedCode))
}

func (k *Keys) sign(canonical string) string {
	return base64.RawURLEncoding.EncodeToString(hmacSHA256(k.SignKey, canonical))
}

// SignatureMatches compares a presented signature in constant time.
func SignatureMatches(expected, presented string) bool {
	if len(expected) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// ---------------------------------------------------------------------------
// Canonical records: lines joined by "\n", no trailing newline: tag, gateway
// id, epoch, then the fields. Integers decimal, null empty, booleans 1/0,
// strings verbatim from a newline-free charset, integer lists sorted and
// comma-joined, times epoch milliseconds.
// ---------------------------------------------------------------------------

var (
	tokenRe     = regexp.MustCompile(`^[A-Za-z0-9._:-]{0,64}$`)
	macFieldRe  = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	hex64Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	groupKeyRe  = regexp.MustCompile(`^[vug]:[1-9][0-9]{0,15}$`)
	sigRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	nonceRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	localRefRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	maxSafeInt  = int64(1<<53 - 1)
	errNotCanon = errors.New("not canonical")
)

type canon struct {
	lines []string
	err   error
}

func newCanon(tag string, k *Keys) *canon {
	return &canon{lines: []string{tag, strconv.FormatInt(k.GatewayID, 10), strconv.FormatInt(k.Epoch, 10)}}
}

func (c *canon) fail(name, why string) {
	if c.err == nil {
		c.err = fmt.Errorf("%s: %s", name, why)
	}
}

func (c *canon) int(name string, v int64) {
	if v < 0 || v > maxSafeInt {
		c.fail(name, "not a non-negative integer")
	}
	c.lines = append(c.lines, strconv.FormatInt(v, 10))
}

func (c *canon) intp(name string, v *int64) {
	if v == nil {
		c.lines = append(c.lines, "")
		return
	}
	c.int(name, *v)
}

func (c *canon) bool(v bool) {
	if v {
		c.lines = append(c.lines, "1")
	} else {
		c.lines = append(c.lines, "0")
	}
}

func (c *canon) str(name, v string) {
	if !tokenRe.MatchString(v) {
		c.fail(name, "not a canonical token")
	}
	c.lines = append(c.lines, v)
}

func (c *canon) strp(name string, v *string) {
	if v == nil {
		c.lines = append(c.lines, "")
		return
	}
	c.str(name, *v)
}

func (c *canon) ints(name string, v []int64) {
	list := append([]int64(nil), v...)
	sort.Slice(list, func(a, b int) bool { return list[a] < list[b] })
	parts := make([]string, len(list))
	for i, n := range list {
		if n < 0 || n > maxSafeInt {
			c.fail(name, "not a non-negative integer")
		}
		parts[i] = strconv.FormatInt(n, 10)
	}
	c.lines = append(c.lines, strings.Join(parts, ","))
}

func (c *canon) text() (string, error) {
	return strings.Join(c.lines, "\n"), c.err
}

// CanonicalGroup is the signed text of a wire group.
func (k *Keys) CanonicalGroup(g WireGroup) (string, error) {
	if !groupKeyRe.MatchString(g.GroupKey) {
		return "", fmt.Errorf("groupKey: invalid %q", g.GroupKey)
	}
	c := newCanon(GroupRecordTag, k)
	c.str("groupKey", g.GroupKey)
	c.str("durationMode", g.DurationMode)
	c.intp("expiresAt", g.ExpiresAt)
	c.intp("durationSeconds", g.DurationSeconds)
	c.intp("quotaBytes", g.QuotaBytes)
	c.int("baseTimeUsedSeconds", g.BaseTimeUsedSeconds)
	c.int("baseBytesUsed", g.BaseBytesUsed)
	c.intp("downKbps", g.DownKbps)
	c.intp("upKbps", g.UpKbps)
	c.int("maxDevices", g.MaxDevices)
	c.int("revision", g.Revision)
	return c.text()
}

// SignGroup signs a wire group.
func (k *Keys) SignGroup(g WireGroup) (string, error) {
	t, err := k.CanonicalGroup(g)
	if err != nil {
		return "", err
	}
	return k.sign(t), nil
}

// CanonicalGrant is the signed text of a wire grant.
func (k *Keys) CanonicalGrant(g WireGrant) (string, error) {
	if g.GrantID == nil && (g.LocalRef == nil || *g.LocalRef == "") {
		return "", errors.New("grant needs a grantId or a localRef")
	}
	if !macFieldRe.MatchString(g.MAC) {
		return "", fmt.Errorf("mac: invalid %q", g.MAC)
	}
	if !groupKeyRe.MatchString(g.GroupKey) {
		return "", fmt.Errorf("groupKey: invalid %q", g.GroupKey)
	}
	c := newCanon(GrantRecordTag, k)
	c.intp("grantId", g.GrantID)
	c.strp("localRef", g.LocalRef)
	c.int("portalId", g.PortalID)
	c.str("groupKey", g.GroupKey)
	c.lines = append(c.lines, g.MAC)
	c.intp("expiresAt", g.ExpiresAt)
	c.int("revision", g.Revision)
	return c.text()
}

// SignGrant signs a wire grant.
func (k *Keys) SignGrant(g WireGrant) (string, error) {
	t, err := k.CanonicalGrant(g)
	if err != nil {
		return "", err
	}
	return k.sign(t), nil
}

// CanonicalOfflineVoucher is the signed text of an offline voucher.
func (k *Keys) CanonicalOfflineVoucher(v WireOfflineVoucher) (string, error) {
	if !hex64Re.MatchString(v.Verifier) {
		return "", errors.New("verifier: not 64 hex chars")
	}
	if !groupKeyRe.MatchString(v.GroupKey) {
		return "", fmt.Errorf("groupKey: invalid %q", v.GroupKey)
	}
	if len(v.PortalIDs) == 0 {
		return "", errors.New("portalIds: empty")
	}
	c := newCanon(VoucherRecordTag, k)
	c.int("voucherId", v.VoucherID)
	c.lines = append(c.lines, v.Verifier)
	c.ints("portalIds", v.PortalIDs)
	c.str("groupKey", v.GroupKey)
	c.str("durationMode", v.DurationMode)
	c.str("startMode", v.StartMode)
	c.intp("durationSeconds", v.DurationSeconds)
	c.intp("quotaBytes", v.QuotaBytes)
	c.intp("downKbps", v.DownKbps)
	c.intp("upKbps", v.UpKbps)
	c.int("maxDevices", v.MaxDevices)
	c.intp("redeemBy", v.RedeemBy)
	c.intp("expiresAt", v.ExpiresAt)
	c.int("timeUsedSeconds", v.TimeUsedSeconds)
	c.int("bytesUsed", v.BytesUsed)
	c.int("revision", v.Revision)
	c.intp("firstUsedAt", v.FirstUsedAt)
	return c.text()
}

// SignOfflineVoucher signs an offline voucher.
func (k *Keys) SignOfflineVoucher(v WireOfflineVoucher) (string, error) {
	t, err := k.CanonicalOfflineVoucher(v)
	if err != nil {
		return "", err
	}
	return k.sign(t), nil
}

// Envelope binds a whole message (docs/gateway/portal.md §6.3).
type Envelope struct {
	Kind           string // authorize | deauthorize | vouchers
	Full           bool
	ServerNow      int64
	Nonce          string
	ItemSignatures []string
	AckedEventSeq  int64
	GrantIDs       []int64
	Reason         *string
	Externals      []ExternalRef
}

// CanonicalEnvelope is the signed text of an envelope.
func (k *Keys) CanonicalEnvelope(e Envelope) (string, error) {
	switch e.Kind {
	case "authorize", "deauthorize", "vouchers":
	default:
		return "", fmt.Errorf("unknown envelope kind %q", e.Kind)
	}
	for _, s := range e.ItemSignatures {
		if !sigRe.MatchString(s) {
			return "", errors.New("itemSignatures: not a signature")
		}
	}
	if !nonceRe.MatchString(e.Nonce) {
		return "", errors.New("nonce: expected 16 bytes base64url")
	}
	c := newCanon("perch-portal-"+e.Kind+"-v1", k)
	c.bool(e.Full)
	c.int("serverNow", e.ServerNow)
	c.lines = append(c.lines, e.Nonce)
	c.int("ackedEventSeq", e.AckedEventSeq)
	c.ints("grantIds", e.GrantIDs)
	c.strp("reason", e.Reason)
	c.int("itemCount", int64(len(e.ItemSignatures)))
	c.int("externalCount", int64(len(e.Externals)))
	head, err := c.text()
	if err != nil {
		return "", err
	}
	lines := []string{head}
	lines = append(lines, e.ItemSignatures...)
	for _, x := range e.Externals {
		if !macFieldRe.MatchString(x.MAC) {
			return "", fmt.Errorf("externals: invalid mac %s", x.MAC)
		}
		pid := ""
		if x.PortalID != nil {
			if *x.PortalID < 0 {
				return "", errNotCanon
			}
			pid = strconv.FormatInt(*x.PortalID, 10)
		}
		lines = append(lines, "ext:"+pid+":"+x.MAC)
	}
	return strings.Join(lines, "\n"), nil
}

// SignEnvelope signs an envelope.
func (k *Keys) SignEnvelope(e Envelope) (string, error) {
	t, err := k.CanonicalEnvelope(e)
	if err != nil {
		return "", err
	}
	return k.sign(t), nil
}

// verify recomputes a signature and compares it with the presented one.
func verify(expected string, err error, presented string) bool {
	if err != nil {
		return false
	}
	return SignatureMatches(expected, presented)
}
