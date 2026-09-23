package portal

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Guest page templates (plan 4 §9; controller portal/templates.ts and
// portal/builtin_template.ts). The builtin template is compiled in and is
// byte-identical to the controller's; its digest is that of the empty set.
// Custom templates arrive in portal.template, are checked again here (the
// router trusts nothing it serves), and are stored by their digest.
//
// Template HTML is not sanitised (the admin is trusted, and a Paid Hotspot
// API page for a coin-operated vending box needs scripts): it is isolated. It runs on the router's portal
// origin under a strict CSP, where the only power is the guest's own
// session; values substituted into it are always escaped.

//go:embed builtin/*
var builtinFS embed.FS

// Template limits (TEMPLATE_LIMITS).
const (
	TemplateMaxFiles     = 24
	TemplateMaxFileBytes = 512 * 1024
	TemplateMaxHTMLBytes = 256 * 1024
	TemplateMaxTotal     = 2 * 1024 * 1024
	LoginPage            = "login.html"
	StatusPage           = "status.html"
)

// EmptySetSHA256 is the builtin template's digest (the empty file set).
var EmptySetSHA256 = sha256Hex(nil)

var templateNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type fileType struct {
	contentType string
	text        bool
}

var templateTypes = map[string]fileType{
	"html":  {"text/html; charset=utf-8", true},
	"css":   {"text/css; charset=utf-8", true},
	"js":    {"text/javascript; charset=utf-8", true},
	"txt":   {"text/plain; charset=utf-8", true},
	"svg":   {"image/svg+xml", true},
	"png":   {"image/png", false},
	"jpg":   {"image/jpeg", false},
	"jpeg":  {"image/jpeg", false},
	"webp":  {"image/webp", false},
	"gif":   {"image/gif", false},
	"ico":   {"image/x-icon", false},
	"woff2": {"font/woff2", false},
}

// TemplateVariables are the {{name}} variables a page may use.
var TemplateVariables = []string{
	"portal_name", "gateway_name", "client_mac", "client_ip", "origin_url", "message", "message_code",
	"assets", "remaining_time", "remaining_data", "expires_at", "privacy_notice", "methods", "status_json",
	"voucher_form", "login_form", "logout_form",
}

var (
	variableSet  = map[string]bool{}
	rawVariables = map[string]bool{"voucher_form": true, "login_form": true, "logout_form": true}
	variableRe   = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)
	svgRe        = regexp.MustCompile(`(?i)<svg[\s>]`)
)

func init() {
	for _, v := range TemplateVariables {
		variableSet[v] = true
	}
}

// PortalMessages are the message codes the pages show (PORTAL_MESSAGES).
var PortalMessages = map[string]string{
	"invalid_code":           "That code is not valid. Check it and try again.",
	"invalid_credentials":    "Wrong username or password.",
	"expired":                "This voucher has expired.",
	"exhausted":              "The data of this voucher is used up.",
	"revoked":                "This voucher is no longer valid.",
	"disabled":               "This account is disabled.",
	"device_limit":           "Too many devices are using this login. Disconnect one first.",
	"already_authorized":     "This device is already online.",
	"wrong_portal":           "This voucher is for another network.",
	"rate_limited":           "Too many attempts. Wait a minute and try again.",
	"controller_unreachable": "Sign-in is not available right now. Try again in a moment.",
	"origin_mismatch":        "The request came from another page. Reload and try again.",
	"bad_request":            "Something was missing. Try again.",
	"logged_out":             "You are disconnected.",
	"connected":              "You are online.",
	"time_up":                "Your time is up.",
	"data_used_up":           "Your data is used up.",
}

// Snippets are the three Perch-rendered forms (portalSnippets).
func Snippets(voucher, password bool) map[string]string {
	out := map[string]string{"voucher_form": "", "login_form": ""}
	if voucher {
		out["voucher_form"] = `<form class="perch-form perch-voucher" method="post" action="/portal/voucher">` +
			`<label for="perch-code">Voucher code</label>` +
			`<input id="perch-code" name="code" required maxlength="64" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false">` +
			`<button type="submit">Connect</button></form>`
	}
	if password {
		out["login_form"] = `<form class="perch-form perch-login" method="post" action="/portal/login">` +
			`<label for="perch-user">Username</label>` +
			`<input id="perch-user" name="username" required maxlength="32" autocomplete="username" autocapitalize="none" spellcheck="false">` +
			`<label for="perch-pass">Password</label>` +
			`<input id="perch-pass" name="password" type="password" required maxlength="64" autocomplete="current-password">` +
			`<button type="submit">Sign in</button></form>`
	}
	out["logout_form"] = `<form class="perch-form perch-logout" method="post" action="/portal/logout">` +
		`<button type="submit">Disconnect</button></form>`
	return out
}

// TemplateFileData is one stored file.
type TemplateFileData struct {
	Name        string
	ContentType string
	Data        []byte
}

// Template is a file set by name.
type Template struct {
	SHA256  string
	Builtin bool
	Files   map[string]TemplateFileData
}

// BuiltinTemplate is the compiled-in set.
func BuiltinTemplate() *Template {
	t := &Template{SHA256: EmptySetSHA256, Builtin: true, Files: map[string]TemplateFileData{}}
	for _, name := range []string{LoginPage, StatusPage, "style.css"} {
		data, err := builtinFS.ReadFile("builtin/" + name)
		if err != nil {
			panic(err)
		}
		t.Files[name] = TemplateFileData{Name: name, ContentType: templateTypes[extOf(name)].contentType, Data: data}
	}
	return t
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func extOf(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// TemplateSetSHA256 is the digest of a file set (templateSetSha256):
// SHA-256 over "<name>\n<sha256 hex>\n" per file, sorted by name.
func TemplateSetSHA256(files []TemplateFileData) string {
	list := append([]TemplateFileData(nil), files...)
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	var b bytes.Buffer
	for _, f := range list {
		b.WriteString(f.Name + "\n" + sha256Hex(f.Data) + "\n")
	}
	return sha256Hex(b.Bytes())
}

func magicOK(ext string, d []byte) bool {
	has := func(off int, sig string) bool { return len(d) >= off+len(sig) && string(d[off:off+len(sig)]) == sig }
	switch ext {
	case "png":
		return has(0, "\x89PNG\r\n\x1a\n")
	case "jpg", "jpeg":
		return has(0, "\xff\xd8\xff")
	case "gif":
		return has(0, "GIF87a") || has(0, "GIF89a")
	case "webp":
		return has(0, "RIFF") && has(8, "WEBP")
	case "ico":
		return has(0, "\x00\x00\x01\x00")
	case "woff2":
		return has(0, "wOF2")
	}
	return false
}

// CheckTemplateFile checks one file the way the controller's upload does:
// name, type by extension and content, size, and for HTML the variables.
func CheckTemplateFile(name string, data []byte) (TemplateFileData, error) {
	if !templateNameRe.MatchString(name) {
		return TemplateFileData{}, fmt.Errorf("%q is not an allowed file name", name)
	}
	ext := extOf(name)
	t, ok := templateTypes[ext]
	if !ok {
		return TemplateFileData{}, fmt.Errorf("%q: unsupported type", name)
	}
	limit := TemplateMaxFileBytes
	if ext == "html" {
		limit = TemplateMaxHTMLBytes
	}
	if len(data) > limit {
		return TemplateFileData{}, fmt.Errorf("%q is %d bytes; the limit is %d", name, len(data), limit)
	}
	if t.text {
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return TemplateFileData{}, fmt.Errorf("%q is not UTF-8 text", name)
		}
		if ext == "svg" && !svgRe.Match(data) {
			return TemplateFileData{}, fmt.Errorf("%q is not an SVG", name)
		}
	} else if !magicOK(ext, data) {
		return TemplateFileData{}, fmt.Errorf("%q does not contain what its extension says", name)
	}
	if ext == "html" {
		for _, m := range variableRe.FindAllSubmatch(data, -1) {
			if !variableSet[string(m[1])] {
				return TemplateFileData{}, fmt.Errorf("%q: {{%s}} is not a portal variable", name, m[1])
			}
		}
	}
	return TemplateFileData{Name: name, ContentType: t.contentType, Data: data}, nil
}

// CheckTemplateSet checks a whole set: count, total, login page.
func CheckTemplateSet(files []TemplateFileData) error {
	if len(files) > TemplateMaxFiles {
		return fmt.Errorf("a template holds at most %d files", TemplateMaxFiles)
	}
	seen := map[string]bool{}
	total := 0
	for _, f := range files {
		if seen[f.Name] {
			return fmt.Errorf("%q appears twice", f.Name)
		}
		seen[f.Name] = true
		total += len(f.Data)
	}
	if total > TemplateMaxTotal {
		return fmt.Errorf("the template is %d bytes; the limit is %d", total, TemplateMaxTotal)
	}
	if !seen[LoginPage] {
		return fmt.Errorf("a template needs a %s", LoginPage)
	}
	return nil
}

// EscapeHTML is the controller's escapeHtml.
func EscapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// ScriptSafeJSON is JSON safe inside <script type="application/json">.
func ScriptSafeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	// encoding/json already escapes <, > and & as < etc.
	return string(b)
}

// SafeOriginURL keeps http(s) URLs only.
func SafeOriginURL(u string) string {
	l := strings.ToLower(u)
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
		return u
	}
	return ""
}

// RenderPage substitutes a page's variables. Unknown names render empty;
// plain values are HTML-escaped, status_json is script-safe JSON, the forms
// are inserted as they are.
func RenderPage(html []byte, values map[string]string, status any, voucher, password bool) []byte {
	snippets := Snippets(voucher, password)
	return variableRe.ReplaceAllFunc(html, func(m []byte) []byte {
		name := string(variableRe.FindSubmatch(m)[1])
		switch {
		case rawVariables[name]:
			return []byte(snippets[name])
		case name == "status_json":
			return []byte(ScriptSafeJSON(status))
		case !variableSet[name]:
			return nil
		}
		return []byte(EscapeHTML(values[name]))
	})
}

// CSP builds the Content-Security-Policy of a page: the builtin allows no
// inline script; a custom template may use inline script and connect to
// the origins the admin listed (already validated).
func CSP(builtin bool, connectSrc []string) string {
	script := "script-src 'self' 'unsafe-inline'"
	if builtin {
		script = "script-src 'self'"
	}
	connect := "connect-src 'self'"
	if len(connectSrc) > 0 {
		connect += " " + strings.Join(connectSrc, " ")
	}
	return "default-src 'self'; " + script + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		connect + "; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

var cspSourceRe = regexp.MustCompile(`^(https?|wss?)://(\*\.)?[A-Za-z0-9.-]+(:[0-9]{1,5})?$|^(https?|wss?)://\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

// CleanCSPSources keeps well-formed origins only (no spaces, quotes,
// semicolons or paths that could bend the header).
func CleanCSPSources(in []string) (ok []string, dropped []string) {
	for _, s := range in {
		s = strings.TrimSpace(s)
		if cspSourceRe.MatchString(s) {
			ok = append(ok, s)
		} else if s != "" {
			dropped = append(dropped, s)
		}
	}
	return sortedCopy(ok), dropped
}
