package portal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// Checkout records and terminal request signatures (docs/gateway/portal.md
// §14.4 and §14.6; vectors pinned in the controller's hotspot.spec.ts).
//
//	checkoutKey   = HMAC-SHA256(gatewayKey, "perch-portal-checkout-v1")
//	sig           = base64url_nopad(HMAC-SHA256(signKey, canonical))
//	referenceCode = ALPHABET[HMAC-SHA256(checkoutKey, canonical)[i] & 31], i = 0…9
//
// The reference code is derived on both sides and never sent.

// CheckoutRecordTag is the canonical record tag (and the sub-key label).
const CheckoutRecordTag = "perch-portal-checkout-v1"

// TerminalRequestTag heads a terminal request's signing string.
const TerminalRequestTag = "perch-terminal-v1"

// ReferenceCodeLength is the symbols of a reference code (50 bits).
const ReferenceCodeLength = 10

// Checkout reasons.
const (
	ReasonDone     = "done"
	ReasonTimeout  = "timeout"
	ReasonTerminal = "terminal"
)

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// CheckoutRecord is the signed facts of one finalised checkout.
type CheckoutRecord struct {
	CheckoutRef     string
	PortalID        int64
	TerminalID      int64
	MAC             string
	Amount          int64
	Currency        string
	PriceTableID    int64
	PriceRevision   int64
	DurationMode    string
	DurationSeconds int64
	QuotaBytes      *int64
	DownKbps        *int64
	UpKbps          *int64
	OpenedAt        int64
	FinalizedAt     int64
	Reason          string
	LocalRef        string
	UnusedAmount    int64
	CoinCount       int64
}

// CanonicalCheckout is a record's canonical text.
func (k *Keys) CanonicalCheckout(r CheckoutRecord) (string, error) {
	c := newCanon(CheckoutRecordTag, k)
	if !localRefRe.MatchString(r.CheckoutRef) {
		c.fail("checkoutRef", "invalid")
	}
	if !localRefRe.MatchString(r.LocalRef) {
		c.fail("localRef", "invalid")
	}
	if !macFieldRe.MatchString(r.MAC) {
		c.fail("mac", "invalid")
	}
	if !currencyRe.MatchString(r.Currency) {
		c.fail("currency", "invalid")
	}
	if r.Reason != ReasonDone && r.Reason != ReasonTimeout && r.Reason != ReasonTerminal {
		c.fail("reason", "invalid")
	}
	if r.DurationMode != ModeWallClock && r.DurationMode != ModeActiveTime {
		c.fail("durationMode", "invalid")
	}
	c.str("checkoutRef", r.CheckoutRef)
	c.int("portalId", r.PortalID)
	c.int("terminalId", r.TerminalID)
	c.str("mac", r.MAC)
	c.int("amount", r.Amount)
	c.str("currency", r.Currency)
	c.int("priceTableId", r.PriceTableID)
	c.int("priceRevision", r.PriceRevision)
	c.str("durationMode", r.DurationMode)
	c.int("durationSeconds", r.DurationSeconds)
	c.intp("quotaBytes", r.QuotaBytes)
	c.intp("downKbps", r.DownKbps)
	c.intp("upKbps", r.UpKbps)
	c.int("openedAt", r.OpenedAt)
	c.int("finalizedAt", r.FinalizedAt)
	c.str("reason", r.Reason)
	c.str("localRef", r.LocalRef)
	c.int("unusedAmount", r.UnusedAmount)
	c.int("coinCount", r.CoinCount)
	return c.text()
}

// CheckoutKey is HMAC(gatewayKey, "perch-portal-checkout-v1").
func (k *Keys) CheckoutKey() []byte { return hmacSHA256(k.GatewayKey, CheckoutRecordTag) }

// SignCheckout signs a record with the signKey.
func (k *Keys) SignCheckout(r CheckoutRecord) (string, error) {
	text, err := k.CanonicalCheckout(r)
	if err != nil {
		return "", err
	}
	return k.sign(text), nil
}

// CheckoutReferenceCode is the guest's reference code of a record.
func (k *Keys) CheckoutReferenceCode(r CheckoutRecord) (string, error) {
	text, err := k.CanonicalCheckout(r)
	if err != nil {
		return "", err
	}
	b := hmacSHA256(k.CheckoutKey(), text)
	out := make([]byte, ReferenceCodeLength)
	for i := range out {
		out[i] = VoucherAlphabet[b[i]&31]
	}
	return string(out), nil
}

// TerminalSigningString is what a terminal signs for one request.
func TerminalSigningString(method, path string, terminalID int64, session string, seq int64, bodySHA256Hex string) string {
	return strings.Join([]string{TerminalRequestTag, strings.ToUpper(method), path,
		strconv.FormatInt(terminalID, 10), session, strconv.FormatInt(seq, 10), bodySHA256Hex}, "\n")
}

// SignTerminalRequest is the X-Perch-Signature of a request: HMAC-SHA256
// keyed with the terminal's token, base64url without padding.
func SignTerminalRequest(token, method, path string, terminalID int64, session string, seq int64, body []byte) string {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte(TerminalSigningString(method, path, terminalID, session, seq, hex.EncodeToString(sum[:]))))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
