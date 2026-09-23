package portal

import "encoding/json"

// Wire shapes of the portal.* RPCs (docs/gateway/portal.md §6.4 and §7 in
// the controller repository). Times are epoch milliseconds; nullable
// numbers are pointers.

// Duration and start modes.
const (
	ModeWallClock  = "wall_clock"
	ModeActiveTime = "active_time"
	StartFirstUse  = "first_use"
	StartCreation  = "creation"
)

// WireGroup is a group's limits and the usage outside this router's live grants.
type WireGroup struct {
	GroupKey            string `json:"groupKey"`
	DurationMode        string `json:"durationMode"`
	ExpiresAt           *int64 `json:"expiresAt"`
	DurationSeconds     *int64 `json:"durationSeconds"`
	QuotaBytes          *int64 `json:"quotaBytes"`
	BaseTimeUsedSeconds int64  `json:"baseTimeUsedSeconds"`
	BaseBytesUsed       int64  `json:"baseBytesUsed"`
	DownKbps            *int64 `json:"downKbps"`
	UpKbps              *int64 `json:"upKbps"`
	MaxDevices          int64  `json:"maxDevices"`
	Revision            int64  `json:"revision"`
}

// SignedGroup is a WireGroup with its signature.
type SignedGroup struct {
	WireGroup
	Sig string `json:"sig"`
}

// WireGrant is one MAC's authorisation on one portal.
type WireGrant struct {
	GrantID   *int64  `json:"grantId"`
	LocalRef  *string `json:"localRef"`
	PortalID  int64   `json:"portalId"`
	GroupKey  string  `json:"groupKey"`
	MAC       string  `json:"mac"`
	ExpiresAt *int64  `json:"expiresAt"`
	Revision  int64   `json:"revision"`
}

// SignedGrant is a WireGrant with its signature.
type SignedGrant struct {
	WireGrant
	Sig string `json:"sig"`
}

// WireOfflineVoucher is a voucher this gateway may redeem while the
// controller is unreachable (decision 20).
type WireOfflineVoucher struct {
	VoucherID       int64   `json:"voucherId"`
	Verifier        string  `json:"verifier"`
	PortalIDs       []int64 `json:"portalIds"`
	GroupKey        string  `json:"groupKey"`
	DurationMode    string  `json:"durationMode"`
	StartMode       string  `json:"startMode"`
	DurationSeconds *int64  `json:"durationSeconds"`
	QuotaBytes      *int64  `json:"quotaBytes"`
	DownKbps        *int64  `json:"downKbps"`
	UpKbps          *int64  `json:"upKbps"`
	MaxDevices      int64   `json:"maxDevices"`
	RedeemBy        *int64  `json:"redeemBy"`
	ExpiresAt       *int64  `json:"expiresAt"`
	TimeUsedSeconds int64   `json:"timeUsedSeconds"`
	BytesUsed       int64   `json:"bytesUsed"`
	Revision        int64   `json:"revision"`
}

// SignedOfflineVoucher is a WireOfflineVoucher with its signature.
type SignedOfflineVoucher struct {
	WireOfflineVoucher
	Sig string `json:"sig"`
}

// ExternalRef names an authorisation made outside Perch.
type ExternalRef struct {
	PortalID *int64 `json:"portalId"`
	MAC      string `json:"mac"`
}

// AuthorizeParams are portal.authorize's params.
type AuthorizeParams struct {
	Full            bool          `json:"full"`
	ServerNow       int64         `json:"serverNow"`
	AckedEventSeq   int64         `json:"ackedEventSeq"`
	Nonce           string        `json:"nonce"`
	KeyEpoch        int64         `json:"keyEpoch"`
	Groups          []SignedGroup `json:"groups"`
	Grants          []SignedGrant `json:"grants"`
	RevertExternals []ExternalRef `json:"revertExternals"`
	Sig             string        `json:"sig"`
}

// AuthorizeItemResult is one grant's outcome.
type AuthorizeItemResult struct {
	GrantID  *int64  `json:"grantId"`
	LocalRef *string `json:"localRef,omitempty"`
	Revision int64   `json:"revision"`
	// State: active | pending_device | rejected.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// AuthorizeResult is portal.authorize's result.
type AuthorizeResult struct {
	Results []AuthorizeItemResult `json:"results"`
	// Ended lists grants a full set removed (reason removed).
	Ended []GrantRef `json:"ended"`
}

// GrantRef names a grant by id or by the router's localRef.
type GrantRef struct {
	GrantID  *int64  `json:"grantId"`
	LocalRef *string `json:"localRef,omitempty"`
}

// DeauthorizeParams are portal.deauthorize's params.
type DeauthorizeParams struct {
	GrantIDs  []int64 `json:"grantIds"`
	Reason    string  `json:"reason"`
	ServerNow int64   `json:"serverNow"`
	Nonce     string  `json:"nonce"`
	KeyEpoch  int64   `json:"keyEpoch"`
	Sig       string  `json:"sig"`
}

// DeauthorizeResult is portal.deauthorize's result.
type DeauthorizeResult struct {
	Ended []int64 `json:"ended"`
}

// VouchersParams are portal.vouchers' params.
type VouchersParams struct {
	Enabled   bool                   `json:"enabled"`
	ServerNow int64                  `json:"serverNow"`
	Nonce     string                 `json:"nonce"`
	KeyEpoch  int64                  `json:"keyEpoch"`
	Vouchers  []SignedOfflineVoucher `json:"vouchers"`
	Sig       string                 `json:"sig"`
}

// VouchersResult is portal.vouchers' result.
type VouchersResult struct {
	Stored   int `json:"stored"`
	Rejected int `json:"rejected"`
}

// SyncParams are portal.sync's params.
type SyncParams struct {
	AckedEventSeq int64 `json:"ackedEventSeq"`
}

// Event is one journal entry (RouterEvent). Type-specific fields are
// omitted when empty.
type Event struct {
	Seq      int64   `json:"seq"`
	At       int64   `json:"at"`
	Type     string  `json:"type"`
	PortalID *int64  `json:"portalId"`
	MAC      string  `json:"mac"`
	GrantID  *int64  `json:"grantId,omitempty"`
	LocalRef *string `json:"localRef,omitempty"`
	IP       *string `json:"ip,omitempty"`
	// grant_ended
	Reason        string `json:"reason,omitempty"`
	BytesUp       *int64 `json:"bytesUp,omitempty"`
	BytesDown     *int64 `json:"bytesDown,omitempty"`
	ActiveSeconds *int64 `json:"activeSeconds,omitempty"`
	// offline_redeemed
	VoucherID       *int64  `json:"voucherId,omitempty"`
	Placement       string  `json:"placement,omitempty"`
	DemotedGrantID  *int64  `json:"demotedGrantId,omitempty"`
	DemotedLocalRef *string `json:"demotedLocalRef,omitempty"`
	StartsAt        *int64  `json:"startsAt,omitempty"`
	ExpiresAt       *int64  `json:"expiresAt,omitempty"`
	Hostname        *string `json:"hostname,omitempty"`
}

// Event types.
const (
	EvGrantActive     = "grant_active"
	EvSessionPaused   = "session_paused"
	EvSessionResumed  = "session_resumed"
	EvGrantEnded      = "grant_ended"
	EvExternalAuth    = "external_auth"
	EvExternalDeauth  = "external_deauth"
	EvOfflineRedeemed = "offline_redeemed"
)

// End reasons the router reports (RouterEndReason).
const (
	EndExpired      = "expired"
	EndQuota        = "quota"
	EndRouterDeauth = "router_deauth"
	EndLogout       = "logout"
	EndMoved        = "moved"
	EndRemoved      = "removed"
)

// GrantUsage is one held grant in portal.sync and portal.sessions.
type GrantUsage struct {
	GrantID       *int64  `json:"grantId"`
	LocalRef      *string `json:"localRef"`
	PortalID      int64   `json:"portalId"`
	MAC           string  `json:"mac"`
	IP            *string `json:"ip"`
	BytesUp       int64   `json:"bytesUp"`
	BytesDown     int64   `json:"bytesDown"`
	ActiveSeconds int64   `json:"activeSeconds"`
	// State: active | paused | pending_device.
	State      string `json:"state"`
	LastSeenAt *int64 `json:"lastSeenAt"`
	Revision   *int64 `json:"revision"`
}

// External is an authorisation made outside Perch that is still present.
type External struct {
	PortalID  *int64  `json:"portalId"`
	MAC       string  `json:"mac"`
	IP        *string `json:"ip"`
	Since     *int64  `json:"since"`
	BytesUp   int64   `json:"bytesUp"`
	BytesDown int64   `json:"bytesDown"`
}

// SyncResult is portal.sync's result (RouterPortalReport).
type SyncResult struct {
	LastEventSeq int64        `json:"lastEventSeq"`
	Truncated    bool         `json:"truncated"`
	Events       []Event      `json:"events"`
	Grants       []GrantUsage `json:"grants"`
	Externals    []External   `json:"externals"`
}

// SessionClient is one client of portal.sessions.
type SessionClient struct {
	GrantUsage
	Hostname         *string `json:"hostname"`
	SessionStartedAt *int64  `json:"sessionStartedAt"`
}

// PortalCount is the per-portal client count of portal.sessions.
type PortalCount struct {
	PortalID      int64 `json:"portalId"`
	Authenticated int   `json:"authenticated"`
	Preauth       int   `json:"preauth"`
}

// SessionsParams are portal.sessions' params (notification).
type SessionsParams struct {
	CollectedAt  int64           `json:"collectedAt"`
	Clients      []SessionClient `json:"clients"`
	PreauthCount int             `json:"preauthCount"`
	Portals      []PortalCount   `json:"portals"`
}

// RedeemParams are portal.redeem's params (collector → controller).
type RedeemParams struct {
	PortalID int64   `json:"portalId"`
	MAC      string  `json:"mac"`
	IP       string  `json:"ip"`
	Hostname *string `json:"hostname,omitempty"`
	Code     string  `json:"code"`
	Replace  bool    `json:"replace,omitempty"`
}

// LoginParams are portal.login's params (collector → controller).
type LoginParams struct {
	PortalID int64   `json:"portalId"`
	MAC      string  `json:"mac"`
	IP       string  `json:"ip"`
	Hostname *string `json:"hostname,omitempty"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	Replace  bool    `json:"replace,omitempty"`
}

// RedeemResult is portal.redeem's and portal.login's result: the grant and
// its group, each signed like the items of portal.authorize, applied at
// once. Queued = the entitlement waits behind the device's current one
// (decision 23); grant and group are then null.
type RedeemResult struct {
	Grant  *SignedGrant `json:"grant"`
	Group  *SignedGroup `json:"group"`
	Queued bool         `json:"queued,omitempty"`
}

// RelayParams are portal.relay's params (collector → controller): an
// integration's request on the guest network, passed through untouched.
type RelayParams struct {
	PortalID int64           `json:"portalId"`
	Op       string          `json:"op"`
	MAC      string          `json:"mac,omitempty"`
	Token    string          `json:"token"`
	Body     json.RawMessage `json:"body,omitempty"`
	ClientIP string          `json:"clientIp"`
}

// RelayResult is portal.relay's result.
type RelayResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// TemplateParams are portal.template's params.
type TemplateParams struct {
	SHA256 string         `json:"sha256"`
	Files  []TemplateFile `json:"files"`
}

// TemplateFile is one file of a template.
type TemplateFile struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	DataBase64  string `json:"dataBase64"`
}
