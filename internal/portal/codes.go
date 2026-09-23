package portal

import (
	"strings"
	"unicode"
	"unicode/utf16"
)

// Voucher codes (docs/gateway/portal.md §3): Crockford base32 upper case,
// 8–16 symbols. The router normalizes what a guest types exactly like the
// controller's normalizeVoucherCode (JavaScript semantics: \s whitespace,
// full upper-casing), because the result is what the offline verifier hashes.
const (
	VoucherAlphabet  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeMinLength    = 8
	codeMaxLength    = 16
	codeMaxRawLength = 64 // UTF-16 code units, like String.length
)

// jsSpace is JavaScript's \s: Unicode White_Space plus U+FEFF.
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// specialUpper are String.prototype.toUpperCase's one-to-many mappings that
// end in ASCII letters (SpecialCasing.txt); everything else is rune-wise.
var specialUpper = map[rune]string{
	'ß': "SS", 'ﬀ': "FF", 'ﬁ': "FI", 'ﬂ': "FL", 'ﬃ': "FFI", 'ﬄ': "FFL", 'ﬅ': "ST", 'ﬆ': "ST",
}

// NormalizeCode turns typed input into the canonical code, or "" when it
// cannot be one.
func NormalizeCode(input string) string {
	if len(utf16.Encode([]rune(input))) > codeMaxRawLength {
		return ""
	}
	var b strings.Builder
	for _, r := range input {
		if jsSpace(r) || r == '-' || r == '.' || r == '_' {
			continue
		}
		if s, ok := specialUpper[r]; ok {
			b.WriteString(s)
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	stripped := b.String()
	if n := len(utf16.Encode([]rune(stripped))); n < codeMinLength || n > codeMaxLength {
		return ""
	}
	out := make([]byte, 0, len(stripped))
	for _, r := range stripped {
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if r > 0x7f || !strings.ContainsRune(VoucherAlphabet, r) {
			return ""
		}
		out = append(out, byte(r))
	}
	return string(out)
}

// NormalizeMAC is the controller's normalizeMac: any common spelling to
// "02:00:00:aa:bb:cc"; "" for anything else and for the all-zero, broadcast
// and multicast addresses.
func NormalizeMAC(input string) string {
	var hex []byte
	for _, r := range strings.ToLower(strings.TrimSpace(input)) {
		switch {
		case r == ':' || r == '-' || r == '.':
			continue
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'):
			hex = append(hex, byte(r))
		default:
			return ""
		}
	}
	if len(hex) != 12 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.Write(hex[i : i+2])
	}
	mac := b.String()
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	first := strings.IndexByte("0123456789abcdef", hex[1])
	if first&1 == 1 {
		return "" // multicast
	}
	return mac
}

// GroupKeyOf builds a group key ("v:17").
func GroupKeyOf(kind byte, id int64) string {
	return string(kind) + ":" + itoa(id)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
