package gwconfig

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Pairing crypto (owner decision 29; the controller's
// docs/gateway/config-plane.md section 4.4, pairing_crypto.ts): an X25519
// key agreement over the collector socket with Bluetooth-style numeric
// comparison. Byte for byte the controller's functions; the pinned vector
// in pair_test.go is the controller's.
//
//	commitment = HMAC-SHA256(key = routerNonce, "perch-pair-commit-v1" ‖ routerPub ‖ controllerPub)
//	key        = HKDF-SHA256(ikm = X25519 shared, salt = controllerNonce ‖ routerNonce,
//	                         info = "perch-config-sign-v1:" + gatewayId, L = 32)
//	SAS        = uint32_be(SHA-256("perch-pair-sas-v1" ‖ controllerPub ‖ routerPub ‖
//	                         controllerNonce ‖ routerNonce ‖ gatewayId)[0:4]) mod 10^6, 6 digits
//	keyId      = hex(SHA-256("perch-pair-keyid-v1" ‖ key))[0:16]
//
// The router commits to its nonce before it learns the controller's: a man
// in the middle cannot grind its own nonce until both codes agree, it gets
// one guess in 10^6.

const (
	pairCommitLabel = "perch-pair-commit-v1"
	pairSASLabel    = "perch-pair-sas-v1"
	pairInfoPrefix  = "perch-config-sign-v1:"
	pairKeyIDLabel  = "perch-pair-keyid-v1"
	// PairKeyBytes is the size of keys, public keys and nonces.
	PairKeyBytes = 32
)

// PairTranscript is what both ends feed the key derivation and the code.
type PairTranscript struct {
	GatewayID       int64
	ControllerPub   []byte
	RouterPub       []byte
	ControllerNonce []byte
	RouterNonce     []byte
}

// PairCommitment is the router's commitment to its nonce.
func PairCommitment(routerNonce, routerPub, controllerPub []byte) []byte {
	m := hmac.New(sha256.New, routerNonce)
	m.Write([]byte(pairCommitLabel))
	m.Write(routerPub)
	m.Write(controllerPub)
	return m.Sum(nil)
}

// PairKey derives the 32-byte signing key (HKDF-SHA256, RFC 5869; one
// block, so expand is a single HMAC).
func PairKey(shared []byte, t PairTranscript) []byte {
	salt := append(append([]byte{}, t.ControllerNonce...), t.RouterNonce...)
	ext := hmac.New(sha256.New, salt)
	ext.Write(shared)
	prk := ext.Sum(nil)
	exp := hmac.New(sha256.New, prk)
	exp.Write([]byte(pairInfoPrefix + strconv.FormatInt(t.GatewayID, 10)))
	exp.Write([]byte{1})
	return exp.Sum(nil)[:PairKeyBytes]
}

// PairSAS is the 6-digit code both ends show.
func PairSAS(t PairTranscript) string {
	h := sha256.New()
	h.Write([]byte(pairSASLabel))
	h.Write(t.ControllerPub)
	h.Write(t.RouterPub)
	h.Write(t.ControllerNonce)
	h.Write(t.RouterNonce)
	h.Write([]byte(strconv.FormatInt(t.GatewayID, 10)))
	sum := h.Sum(nil)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[:4])%1_000_000)
}

// PairKeyID is the key's short public name (16 hex).
func PairKeyID(key []byte) string {
	h := sha256.New()
	h.Write([]byte(pairKeyIDLabel))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// errLowOrder: the peer's key gives an all-zero shared secret.
var errLowOrder = errors.New("the peer's X25519 key is unusable (low order)")

// X25519Shared is X25519(priv, peerPub); an all-zero result is refused.
func X25519Shared(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		// crypto/ecdh refuses the all-zero output itself.
		return nil, errLowOrder
	}
	zero := true
	for _, b := range shared {
		zero = zero && b == 0
	}
	if zero {
		return nil, errLowOrder
	}
	return shared, nil
}

// newPairNonce is 32 random bytes.
func newPairNonce() []byte {
	b := make([]byte, PairKeyBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// hex32 decodes 64 lowercase hex digits.
func hex32(s string) ([]byte, bool) {
	if len(s) != 2*PairKeyBytes {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}
