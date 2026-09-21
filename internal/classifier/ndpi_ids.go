//go:build ndpi
// +build ndpi

package classifier

/*
#include <ndpi_protocol_ids.h>
*/
import "C"

// Compile-time pins: each line only compiles when the id hard-coded in
// ndpi_labels.go (kept cgo-free so it stays unit-testable) equals the
// library's NDPI_PROTOCOL_* value from ndpi_protocol_ids.h. Both
// operands are untyped constants, so the difference is a constant too;
// if it is non-zero one of the two conversions overflows uint and the
// build fails naming the offending line. Generated from the const block
// in ndpi_labels.go; keep the two lists in step.
const (
	_ = uint(C.NDPI_PROTOCOL_UNKNOWN-ndpiProtocolUnknown) + uint(ndpiProtocolUnknown-C.NDPI_PROTOCOL_UNKNOWN)
	_ = uint(C.NDPI_PROTOCOL_FTP_CONTROL-ndpiProtocolFTPControl) + uint(ndpiProtocolFTPControl-C.NDPI_PROTOCOL_FTP_CONTROL)
	_ = uint(C.NDPI_PROTOCOL_MAIL_POP-ndpiProtocolMail_POP) + uint(ndpiProtocolMail_POP-C.NDPI_PROTOCOL_MAIL_POP)
	_ = uint(C.NDPI_PROTOCOL_MAIL_SMTP-ndpiProtocolMail_SMTP) + uint(ndpiProtocolMail_SMTP-C.NDPI_PROTOCOL_MAIL_SMTP)
	_ = uint(C.NDPI_PROTOCOL_MAIL_IMAP-ndpiProtocolMail_IMAP) + uint(ndpiProtocolMail_IMAP-C.NDPI_PROTOCOL_MAIL_IMAP)
	_ = uint(C.NDPI_PROTOCOL_DNS-ndpiProtocolDNS) + uint(ndpiProtocolDNS-C.NDPI_PROTOCOL_DNS)
	_ = uint(C.NDPI_PROTOCOL_HTTP-ndpiProtocolHTTP) + uint(ndpiProtocolHTTP-C.NDPI_PROTOCOL_HTTP)
	_ = uint(C.NDPI_PROTOCOL_MDNS-ndpiProtocolMDNS) + uint(ndpiProtocolMDNS-C.NDPI_PROTOCOL_MDNS)
	_ = uint(C.NDPI_PROTOCOL_NTP-ndpiProtocolNTP) + uint(ndpiProtocolNTP-C.NDPI_PROTOCOL_NTP)
	_ = uint(C.NDPI_PROTOCOL_NETBIOS-ndpiProtocolNetBIOS) + uint(ndpiProtocolNetBIOS-C.NDPI_PROTOCOL_NETBIOS)
	_ = uint(C.NDPI_PROTOCOL_NFS-ndpiProtocolNFS) + uint(ndpiProtocolNFS-C.NDPI_PROTOCOL_NFS)
	_ = uint(C.NDPI_PROTOCOL_SSDP-ndpiProtocolSSDP) + uint(ndpiProtocolSSDP-C.NDPI_PROTOCOL_SSDP)
	_ = uint(C.NDPI_PROTOCOL_BGP-ndpiProtocolBGP) + uint(ndpiProtocolBGP-C.NDPI_PROTOCOL_BGP)
	_ = uint(C.NDPI_PROTOCOL_SNMP-ndpiProtocolSNMP) + uint(ndpiProtocolSNMP-C.NDPI_PROTOCOL_SNMP)
	_ = uint(C.NDPI_PROTOCOL_XDMCP-ndpiProtocolXDMCP) + uint(ndpiProtocolXDMCP-C.NDPI_PROTOCOL_XDMCP)
	_ = uint(C.NDPI_PROTOCOL_SMBV1-ndpiProtocolSMBv1) + uint(ndpiProtocolSMBv1-C.NDPI_PROTOCOL_SMBV1)
	_ = uint(C.NDPI_PROTOCOL_SYSLOG-ndpiProtocolSyslog) + uint(ndpiProtocolSyslog-C.NDPI_PROTOCOL_SYSLOG)
	_ = uint(C.NDPI_PROTOCOL_DHCP-ndpiProtocolDHCP) + uint(ndpiProtocolDHCP-C.NDPI_PROTOCOL_DHCP)
	_ = uint(C.NDPI_PROTOCOL_MAIL_POPS-ndpiProtocolMail_POPS) + uint(ndpiProtocolMail_POPS-C.NDPI_PROTOCOL_MAIL_POPS)
	_ = uint(C.NDPI_PROTOCOL_NATS-ndpiProtocolNATS) + uint(ndpiProtocolNATS-C.NDPI_PROTOCOL_NATS)
	_ = uint(C.NDPI_PROTOCOL_FTP_DATA-ndpiProtocolFTPData) + uint(ndpiProtocolFTPData-C.NDPI_PROTOCOL_FTP_DATA)
	_ = uint(C.NDPI_PROTOCOL_BITTORRENT-ndpiProtocolBitTorrent) + uint(ndpiProtocolBitTorrent-C.NDPI_PROTOCOL_BITTORRENT)
	_ = uint(C.NDPI_PROTOCOL_SIGNAL-ndpiProtocolSignal) + uint(ndpiProtocolSignal-C.NDPI_PROTOCOL_SIGNAL)
	_ = uint(C.NDPI_PROTOCOL_TIKTOK-ndpiProtocolTikTok) + uint(ndpiProtocolTikTok-C.NDPI_PROTOCOL_TIKTOK)
	_ = uint(C.NDPI_PROTOCOL_DISCORD-ndpiProtocolDiscord) + uint(ndpiProtocolDiscord-C.NDPI_PROTOCOL_DISCORD)
	_ = uint(C.NDPI_PROTOCOL_MAIL_SMTPS-ndpiProtocolMail_SMTPS) + uint(ndpiProtocolMail_SMTPS-C.NDPI_PROTOCOL_MAIL_SMTPS)
	_ = uint(C.NDPI_PROTOCOL_MAIL_IMAPS-ndpiProtocolMail_IMAPS) + uint(ndpiProtocolMail_IMAPS-C.NDPI_PROTOCOL_MAIL_IMAPS)
	_ = uint(C.NDPI_PROTOCOL_STEAM-ndpiProtocolSteam) + uint(ndpiProtocolSteam-C.NDPI_PROTOCOL_STEAM)
	_ = uint(C.NDPI_PROTOCOL_TELNET-ndpiProtocolTelnet) + uint(ndpiProtocolTelnet-C.NDPI_PROTOCOL_TELNET)
	_ = uint(C.NDPI_PROTOCOL_RDP-ndpiProtocolRDP) + uint(ndpiProtocolRDP-C.NDPI_PROTOCOL_RDP)
	_ = uint(C.NDPI_PROTOCOL_VNC-ndpiProtocolVNC) + uint(ndpiProtocolVNC-C.NDPI_PROTOCOL_VNC)
	_ = uint(C.NDPI_PROTOCOL_TLS-ndpiProtocolTLS) + uint(ndpiProtocolTLS-C.NDPI_PROTOCOL_TLS)
	_ = uint(C.NDPI_PROTOCOL_SSH-ndpiProtocolSSH) + uint(ndpiProtocolSSH-C.NDPI_PROTOCOL_SSH)
	_ = uint(C.NDPI_PROTOCOL_USENET-ndpiProtocolUSENET) + uint(ndpiProtocolUSENET-C.NDPI_PROTOCOL_USENET)
	_ = uint(C.NDPI_PROTOCOL_FACEBOOK-ndpiProtocolFacebook) + uint(ndpiProtocolFacebook-C.NDPI_PROTOCOL_FACEBOOK)
	_ = uint(C.NDPI_PROTOCOL_YOUTUBE-ndpiProtocolYouTube) + uint(ndpiProtocolYouTube-C.NDPI_PROTOCOL_YOUTUBE)
	_ = uint(C.NDPI_PROTOCOL_GOOGLE-ndpiProtocolGoogle) + uint(ndpiProtocolGoogle-C.NDPI_PROTOCOL_GOOGLE)
	_ = uint(C.NDPI_PROTOCOL_NETFLIX-ndpiProtocolNetflix) + uint(ndpiProtocolNetflix-C.NDPI_PROTOCOL_NETFLIX)
	_ = uint(C.NDPI_PROTOCOL_APPLE-ndpiProtocolApple) + uint(ndpiProtocolApple-C.NDPI_PROTOCOL_APPLE)
	_ = uint(C.NDPI_PROTOCOL_WHATSAPP-ndpiProtocolWhatsApp) + uint(ndpiProtocolWhatsApp-C.NDPI_PROTOCOL_WHATSAPP)
	_ = uint(C.NDPI_PROTOCOL_WINDOWS_UPDATE-ndpiProtocolWindowsUpdate) + uint(ndpiProtocolWindowsUpdate-C.NDPI_PROTOCOL_WINDOWS_UPDATE)
	_ = uint(C.NDPI_PROTOCOL_SPOTIFY-ndpiProtocolSpotify) + uint(ndpiProtocolSpotify-C.NDPI_PROTOCOL_SPOTIFY)
	_ = uint(C.NDPI_PROTOCOL_OPENVPN-ndpiProtocolOpenVPN) + uint(ndpiProtocolOpenVPN-C.NDPI_PROTOCOL_OPENVPN)
	_ = uint(C.NDPI_PROTOCOL_TOR-ndpiProtocolTor) + uint(ndpiProtocolTor-C.NDPI_PROTOCOL_TOR)
	_ = uint(C.NDPI_PROTOCOL_QUIC-ndpiProtocolQUIC) + uint(ndpiProtocolQUIC-C.NDPI_PROTOCOL_QUIC)
	_ = uint(C.NDPI_PROTOCOL_ZOOM-ndpiProtocolZoom) + uint(ndpiProtocolZoom-C.NDPI_PROTOCOL_ZOOM)
	_ = uint(C.NDPI_PROTOCOL_TWITCH-ndpiProtocolTwitch) + uint(ndpiProtocolTwitch-C.NDPI_PROTOCOL_TWITCH)
	_ = uint(C.NDPI_PROTOCOL_WIREGUARD-ndpiProtocolWireGuard) + uint(ndpiProtocolWireGuard-C.NDPI_PROTOCOL_WIREGUARD)
	_ = uint(C.NDPI_PROTOCOL_MICROSOFT-ndpiProtocolMicrosoft) + uint(ndpiProtocolMicrosoft-C.NDPI_PROTOCOL_MICROSOFT)
	_ = uint(C.NDPI_PROTOCOL_MICROSOFT_365-ndpiProtocolMicrosoft365) + uint(ndpiProtocolMicrosoft365-C.NDPI_PROTOCOL_MICROSOFT_365)
	_ = uint(C.NDPI_PROTOCOL_MQTT-ndpiProtocolMQTT) + uint(ndpiProtocolMQTT-C.NDPI_PROTOCOL_MQTT)
	_ = uint(C.NDPI_PROTOCOL_GIT-ndpiProtocolGit) + uint(ndpiProtocolGit-C.NDPI_PROTOCOL_GIT)
	_ = uint(C.NDPI_PROTOCOL_APPLE_ICLOUD-ndpiProtocolAppleiCloud) + uint(ndpiProtocolAppleiCloud-C.NDPI_PROTOCOL_APPLE_ICLOUD)
	_ = uint(C.NDPI_PROTOCOL_APPLE_ITUNES-ndpiProtocolAppleiTunes) + uint(ndpiProtocolAppleiTunes-C.NDPI_PROTOCOL_APPLE_ITUNES)
	_ = uint(C.NDPI_PROTOCOL_GOOGLE_SERVICES-ndpiProtocolGoogleServices) + uint(ndpiProtocolGoogleServices-C.NDPI_PROTOCOL_GOOGLE_SERVICES)
	_ = uint(C.NDPI_PROTOCOL_INSTAGRAM-ndpiProtocolInstagram) + uint(ndpiProtocolInstagram-C.NDPI_PROTOCOL_INSTAGRAM)
)

// ndpiHeaderProtocolIDs is the same numbering as a runtime map, so the
// cgo test can also report every id at once instead of stopping at the
// first build error.
var ndpiHeaderProtocolIDs = map[string]uint16{
	"NDPI_PROTOCOL_UNKNOWN":         uint16(C.NDPI_PROTOCOL_UNKNOWN),
	"NDPI_PROTOCOL_FTP_CONTROL":     uint16(C.NDPI_PROTOCOL_FTP_CONTROL),
	"NDPI_PROTOCOL_MAIL_POP":        uint16(C.NDPI_PROTOCOL_MAIL_POP),
	"NDPI_PROTOCOL_MAIL_SMTP":       uint16(C.NDPI_PROTOCOL_MAIL_SMTP),
	"NDPI_PROTOCOL_MAIL_IMAP":       uint16(C.NDPI_PROTOCOL_MAIL_IMAP),
	"NDPI_PROTOCOL_DNS":             uint16(C.NDPI_PROTOCOL_DNS),
	"NDPI_PROTOCOL_HTTP":            uint16(C.NDPI_PROTOCOL_HTTP),
	"NDPI_PROTOCOL_MDNS":            uint16(C.NDPI_PROTOCOL_MDNS),
	"NDPI_PROTOCOL_NTP":             uint16(C.NDPI_PROTOCOL_NTP),
	"NDPI_PROTOCOL_NETBIOS":         uint16(C.NDPI_PROTOCOL_NETBIOS),
	"NDPI_PROTOCOL_NFS":             uint16(C.NDPI_PROTOCOL_NFS),
	"NDPI_PROTOCOL_SSDP":            uint16(C.NDPI_PROTOCOL_SSDP),
	"NDPI_PROTOCOL_BGP":             uint16(C.NDPI_PROTOCOL_BGP),
	"NDPI_PROTOCOL_SNMP":            uint16(C.NDPI_PROTOCOL_SNMP),
	"NDPI_PROTOCOL_XDMCP":           uint16(C.NDPI_PROTOCOL_XDMCP),
	"NDPI_PROTOCOL_SMBV1":           uint16(C.NDPI_PROTOCOL_SMBV1),
	"NDPI_PROTOCOL_SYSLOG":          uint16(C.NDPI_PROTOCOL_SYSLOG),
	"NDPI_PROTOCOL_DHCP":            uint16(C.NDPI_PROTOCOL_DHCP),
	"NDPI_PROTOCOL_MAIL_POPS":       uint16(C.NDPI_PROTOCOL_MAIL_POPS),
	"NDPI_PROTOCOL_NATS":            uint16(C.NDPI_PROTOCOL_NATS),
	"NDPI_PROTOCOL_FTP_DATA":        uint16(C.NDPI_PROTOCOL_FTP_DATA),
	"NDPI_PROTOCOL_BITTORRENT":      uint16(C.NDPI_PROTOCOL_BITTORRENT),
	"NDPI_PROTOCOL_SIGNAL":          uint16(C.NDPI_PROTOCOL_SIGNAL),
	"NDPI_PROTOCOL_TIKTOK":          uint16(C.NDPI_PROTOCOL_TIKTOK),
	"NDPI_PROTOCOL_DISCORD":         uint16(C.NDPI_PROTOCOL_DISCORD),
	"NDPI_PROTOCOL_MAIL_SMTPS":      uint16(C.NDPI_PROTOCOL_MAIL_SMTPS),
	"NDPI_PROTOCOL_MAIL_IMAPS":      uint16(C.NDPI_PROTOCOL_MAIL_IMAPS),
	"NDPI_PROTOCOL_STEAM":           uint16(C.NDPI_PROTOCOL_STEAM),
	"NDPI_PROTOCOL_TELNET":          uint16(C.NDPI_PROTOCOL_TELNET),
	"NDPI_PROTOCOL_RDP":             uint16(C.NDPI_PROTOCOL_RDP),
	"NDPI_PROTOCOL_VNC":             uint16(C.NDPI_PROTOCOL_VNC),
	"NDPI_PROTOCOL_TLS":             uint16(C.NDPI_PROTOCOL_TLS),
	"NDPI_PROTOCOL_SSH":             uint16(C.NDPI_PROTOCOL_SSH),
	"NDPI_PROTOCOL_USENET":          uint16(C.NDPI_PROTOCOL_USENET),
	"NDPI_PROTOCOL_FACEBOOK":        uint16(C.NDPI_PROTOCOL_FACEBOOK),
	"NDPI_PROTOCOL_YOUTUBE":         uint16(C.NDPI_PROTOCOL_YOUTUBE),
	"NDPI_PROTOCOL_GOOGLE":          uint16(C.NDPI_PROTOCOL_GOOGLE),
	"NDPI_PROTOCOL_NETFLIX":         uint16(C.NDPI_PROTOCOL_NETFLIX),
	"NDPI_PROTOCOL_APPLE":           uint16(C.NDPI_PROTOCOL_APPLE),
	"NDPI_PROTOCOL_WHATSAPP":        uint16(C.NDPI_PROTOCOL_WHATSAPP),
	"NDPI_PROTOCOL_WINDOWS_UPDATE":  uint16(C.NDPI_PROTOCOL_WINDOWS_UPDATE),
	"NDPI_PROTOCOL_SPOTIFY":         uint16(C.NDPI_PROTOCOL_SPOTIFY),
	"NDPI_PROTOCOL_OPENVPN":         uint16(C.NDPI_PROTOCOL_OPENVPN),
	"NDPI_PROTOCOL_TOR":             uint16(C.NDPI_PROTOCOL_TOR),
	"NDPI_PROTOCOL_QUIC":            uint16(C.NDPI_PROTOCOL_QUIC),
	"NDPI_PROTOCOL_ZOOM":            uint16(C.NDPI_PROTOCOL_ZOOM),
	"NDPI_PROTOCOL_TWITCH":          uint16(C.NDPI_PROTOCOL_TWITCH),
	"NDPI_PROTOCOL_WIREGUARD":       uint16(C.NDPI_PROTOCOL_WIREGUARD),
	"NDPI_PROTOCOL_MICROSOFT":       uint16(C.NDPI_PROTOCOL_MICROSOFT),
	"NDPI_PROTOCOL_MICROSOFT_365":   uint16(C.NDPI_PROTOCOL_MICROSOFT_365),
	"NDPI_PROTOCOL_MQTT":            uint16(C.NDPI_PROTOCOL_MQTT),
	"NDPI_PROTOCOL_GIT":             uint16(C.NDPI_PROTOCOL_GIT),
	"NDPI_PROTOCOL_APPLE_ICLOUD":    uint16(C.NDPI_PROTOCOL_APPLE_ICLOUD),
	"NDPI_PROTOCOL_APPLE_ITUNES":    uint16(C.NDPI_PROTOCOL_APPLE_ITUNES),
	"NDPI_PROTOCOL_GOOGLE_SERVICES": uint16(C.NDPI_PROTOCOL_GOOGLE_SERVICES),
	"NDPI_PROTOCOL_INSTAGRAM":       uint16(C.NDPI_PROTOCOL_INSTAGRAM),
}
