package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Phone struct {
	ID              uuid.UUID   `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID          uuid.UUID   `gorm:"type:uuid;not null" json:"user_id"`
	HubServerID     *uuid.UUID  `gorm:"type:uuid;column:hub_server_id" json:"hub_server_id"`
	Name            string      `gorm:"not null" json:"name"`
	PairingCode     string      `gorm:"uniqueIndex" json:"-"`
	PairingPIN      string      `json:"-"` // 4-digit PIN for QR pairing
	APIToken        string      `gorm:"uniqueIndex" json:"-"` // Secure token for phone API auth
	PublicKey         string      `json:"-"` // Phone's ECDSA public key (PEM format) for request signing
	DeviceFingerprint string      `json:"-"` // Hardware fingerprint for device binding
	PairedAt          *time.Time  `json:"paired_at"`
	WireGuardIP     string      `json:"wireguard_ip"`    // Phone's WireGuard IP (e.g., 10.66.66.2)
	WireGuardConfig    string      `json:"-"` // Sensitive, only returned during pairing
	WireGuardPrivateKey string     `json:"-"` // Phone's WireGuard private key
	WireGuardPublicKey  string     `json:"-"` // Phone's WireGuard public key
	CreatedAt       time.Time   `json:"created_at"`

	// DNS routing fields (for dynamic proxy routing via CNAME)
	ProxySubdomain string `json:"proxy_subdomain"` // Unique subdomain ID (e.g., "abc123def" for abc123def.cn.yalx.in)
	ProxyDomain    string `json:"proxy_domain"`    // Full proxy domain (e.g., "abc123def.cn.yalx.in")
	DNSRecordID    int64  `json:"-"`               // Rage4 DNS record ID for updates/deletion

	// IP Rotation settings
	RotationMode            string `gorm:"default:'off'" json:"rotation_mode"`     // 'off', 'timed', 'api'
	RotationIntervalMinutes int    `gorm:"default:0" json:"rotation_interval_minutes"` // 2-120 minutes (when mode is 'timed')

	// Log retention settings (derived from plan)
	LogRetentionWeeks int `gorm:"default:12" json:"log_retention_weeks"` // Access log retention (1-12 weeks)

	// Plan/License fields
	PlanTier          string     `gorm:"type:varchar(20)" json:"plan_tier"`          // lite, turbo, nitro (empty = no plan)
	LicenseExpiresAt  *time.Time `json:"license_expires_at"`                         // When license expires
	LicenseAutoExtend bool       `gorm:"default:false" json:"license_auto_extend"`   // Auto-renew from balance
	SpeedLimitMbps    int        `gorm:"default:0" json:"speed_limit_mbps"`          // Speed limit in Mbps (from plan)
	MaxConnections    int        `gorm:"default:0" json:"max_connections"`           // Max concurrent connections (from plan)

	// Domain blocking (phone level)
	BlockedDomains pq.StringArray `gorm:"type:text[]" json:"blocked_domains"` // Domain patterns to block

	// SIM card info (updated via status updates)
	SimCountry string `json:"sim_country"` // ISO country code (e.g., "US", "GB")
	SimCarrier string `json:"sim_carrier"` // Carrier name

	// Device metrics (from APK heartbeat/status)
	BatteryLevel     int        `json:"battery_level"`      // 0-100%
	BatteryHealth    string     `json:"battery_health"`     // good, overheat, cold, dead, unknown
	BatteryCharging  bool       `json:"battery_charging"`   // Currently charging
	BatteryTemp      int        `json:"battery_temp"`       // Temperature in celsius
	RAMUsedMB        int64      `json:"ram_used_mb"`        // Used RAM in MB
	RAMTotalMB       int64      `json:"ram_total_mb"`       // Total RAM in MB
	DeviceModel      string     `json:"device_model"`       // Device model (e.g., "Google Pixel 6a")
	OSVersion        string     `json:"os_version"`         // OS version (e.g., "Android 14")
	AppVersion       int        `json:"app_version"`        // APK version number (e.g., 10)
	MetricsUpdatedAt *time.Time `json:"metrics_updated_at"` // Last metrics update

	// Real-time connection stats (from hub-api usage reports)
	ActiveConnections int `gorm:"default:0" json:"active_connections"` // Current unique IPs connected to proxy

	// Relationships
	User      User       `gorm:"foreignKey:UserID" json:"-"`
	HubServer *HubServer `gorm:"foreignKey:HubServerID" json:"hub_server,omitempty"`
}

func (p *Phone) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.PairingCode == "" {
		p.PairingCode = generatePairingCode()
	}
	if p.PairingPIN == "" {
		p.PairingPIN = generatePairingPIN()
	}
	// Generate placeholder API token to satisfy unique constraint
	// Will be replaced with a new token during pairing
	if p.APIToken == "" {
		p.APIToken = GenerateAPIToken()
	}
	return nil
}

func generatePairingCode() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generatePairingPIN() string {
	// Generate 4-digit PIN
	bytes := make([]byte, 2)
	rand.Read(bytes)
	pin := (int(bytes[0])<<8 | int(bytes[1])) % 10000
	return fmt.Sprintf("%04d", pin)
}

// GenerateAPIToken creates a secure 64-character token for phone API authentication
func GenerateAPIToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// PhoneResponse is the public representation
// Note: status, current_ip, last_seen come from Centrifugo real-time data, not database
type PhoneResponse struct {
	ID                      uuid.UUID         `json:"id"`
	Name                    string            `json:"name"`
	PairedAt                *time.Time        `json:"paired_at,omitempty"`
	HubServerIP             string            `json:"hub_server_ip,omitempty"`  // Hub server IP for proxy connection
	ProxyDomain             string            `json:"proxy_domain,omitempty"`   // Full proxy domain (e.g., "abc123def.cn.yalx.in")
	HubServer               HubServerResponse `json:"hub_server,omitempty"`
	RotationMode            string            `json:"rotation_mode"`            // 'off', 'timed', 'api'
	RotationIntervalMinutes int               `json:"rotation_interval_minutes"` // 2-120 minutes
	LogRetentionWeeks       int               `json:"log_retention_weeks"`       // 1-12 weeks
	SimCountry              string            `json:"sim_country"`
	SimCarrier              string            `json:"sim_carrier"`

	// Plan/License fields
	PlanTier          string     `json:"plan_tier"`           // lite, turbo, nitro (empty = no plan)
	LicenseExpiresAt  *time.Time `json:"license_expires_at"`  // When license expires
	LicenseAutoExtend bool       `json:"license_auto_extend"` // Auto-renew from balance
	SpeedLimitMbps    int        `json:"speed_limit_mbps"`    // Bandwidth limit
	MaxConnections    int        `json:"max_connections"`     // Max concurrent connections
	ActiveConnections int        `json:"active_connections"`  // Current unique IPs connected (from hub)
	HasActiveLicense  bool       `json:"has_active_license"`  // Computed: has valid non-expired license

	// Domain blocking
	BlockedDomains []string `json:"blocked_domains"`

	// Device metrics
	BatteryLevel     int        `json:"battery_level"`
	BatteryHealth    string     `json:"battery_health"`
	BatteryCharging  bool       `json:"battery_charging"`
	BatteryTemp      int        `json:"battery_temp"`
	RAMUsedMB        int64      `json:"ram_used_mb"`
	RAMTotalMB       int64      `json:"ram_total_mb"`
	DeviceModel      string     `json:"device_model"`
	OSVersion        string     `json:"os_version"`
	AppVersion       int        `json:"app_version"`
	MetricsUpdatedAt *time.Time `json:"metrics_updated_at"`

	CreatedAt time.Time `json:"created_at"`
}

// RotationSettingsRequest for updating rotation settings
type RotationSettingsRequest struct {
	RotationMode            string `json:"rotation_mode" binding:"required,oneof=off timed api"`
	RotationIntervalMinutes int    `json:"rotation_interval_minutes"` // Required when mode is 'timed'
}

// RotationSettingsResponse for getting rotation settings
type RotationSettingsResponse struct {
	RotationMode            string `json:"rotation_mode"`
	RotationIntervalMinutes int    `json:"rotation_interval_minutes"`
}

// PhoneWithPairingCode includes the pairing code (only for new phones)
type PhoneWithPairingCode struct {
	Phone       PhoneResponse `json:"phone"`
	PairingCode string        `json:"pairing_code"`
	PairingPIN  string        `json:"pairing_pin"` // 6-digit PIN
	QRCodeData  string        `json:"qr_code_data"` // Data to encode in QR
}

func (p *Phone) ToResponse() PhoneResponse {
	// Default to 12 weeks if not set
	retention := p.LogRetentionWeeks
	if retention <= 0 {
		retention = 12
	}

	// Compute active license status
	hasActiveLicense := p.PlanTier != "" && p.LicenseExpiresAt != nil && time.Now().Before(*p.LicenseExpiresAt)

	resp := PhoneResponse{
		ID:                      p.ID,
		Name:                    p.Name,
		PairedAt:                p.PairedAt,
		ProxyDomain:             p.ProxyDomain,
		RotationMode:            p.RotationMode,
		RotationIntervalMinutes: p.RotationIntervalMinutes,
		LogRetentionWeeks:       retention,
		SimCountry:              p.SimCountry,
		SimCarrier:              p.SimCarrier,

		// Plan/License
		PlanTier:          p.PlanTier,
		LicenseExpiresAt:  p.LicenseExpiresAt,
		LicenseAutoExtend: p.LicenseAutoExtend,
		SpeedLimitMbps:    p.SpeedLimitMbps,
		MaxConnections:    p.MaxConnections,
		ActiveConnections: p.ActiveConnections,
		HasActiveLicense:  hasActiveLicense,

		// Domain blocking
		BlockedDomains: p.BlockedDomains,

		// Device metrics
		BatteryLevel:     p.BatteryLevel,
		BatteryHealth:    p.BatteryHealth,
		BatteryCharging:  p.BatteryCharging,
		BatteryTemp:      p.BatteryTemp,
		RAMUsedMB:        p.RAMUsedMB,
		RAMTotalMB:       p.RAMTotalMB,
		DeviceModel:      p.DeviceModel,
		OSVersion:        p.OSVersion,
		AppVersion:       p.AppVersion,
		MetricsUpdatedAt: p.MetricsUpdatedAt,

		CreatedAt: p.CreatedAt,
	}
	if p.HubServer != nil {
		resp.HubServer = p.HubServer.ToResponse()
		resp.HubServerIP = p.HubServer.IP // Include hub server IP for proxy connection
	}
	return resp
}

// PairingRequest is sent from the Android app (QR code + PIN method)
type PairingRequest struct {
	PairingCode        string `json:"pairing_code" binding:"required"`
	PairingPIN         string `json:"pairing_pin" binding:"required"`
	EncryptedPublicKey string `json:"encrypted_public_key" binding:"required"` // AES-GCM encrypted with PIN-derived key
	DeviceFingerprint  string `json:"device_fingerprint" binding:"required"`   // Hardware fingerprint for device binding
	DeviceInfo         string `json:"device_info"`
}

// PhoneLoginRequest is sent from Android app (email/password method)
// Note: PIN is required for both auth methods to ensure MITM protection
type PhoneLoginRequest struct {
	Email              string `json:"email" binding:"required,email"`
	Password           string `json:"password" binding:"required"`
	PhoneID            string `json:"phone_id" binding:"required"`            // Select which phone to connect
	PairingPIN         string `json:"pairing_pin" binding:"required"`         // PIN displayed on dashboard (required for key encryption)
	EncryptedPublicKey string `json:"encrypted_public_key" binding:"required"` // AES-GCM encrypted with PIN-derived key
	DeviceFingerprint  string `json:"device_fingerprint" binding:"required"`
	DeviceInfo         string `json:"device_info"`
}

// PhoneListForLoginResponse is returned when listing phones for login
type PhoneListForLoginResponse struct {
	Phones []PhoneLoginInfo `json:"phones"`
}

// PhoneLoginInfo is minimal phone info for login selection
type PhoneLoginInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ServerName  string `json:"server_name"`
	PairingCode string `json:"pairing_code"` // Needed for key derivation on client
}

// PairingResponse is sent back to the Android app
type PairingResponse struct {
	PhoneID         string `json:"phone_id"`
	APIToken        string `json:"api_token"` // Secure token for phone API authentication
	WireGuardConfig string `json:"wireguard_config"`
	CentrifugoURL   string `json:"centrifugo_url"`
	CentrifugoToken string `json:"centrifugo_token"`
	APIBaseURL      string `json:"api_base_url"`
	ServerIP        string `json:"server_ip"`   // VPS IP for proxy connection
}

// ProxyConfigResponse contains proxy configuration for the phone
type ProxyConfigResponse struct {
	PhoneID         string `json:"phone_id"`
	ServerIP        string `json:"server_ip"`
	WireGuardConfig string `json:"wireguard_config"`
	CentrifugoURL   string `json:"centrifugo_url"`
	CentrifugoToken string `json:"centrifugo_token"`
	// License info
	HasLicense       bool    `json:"has_license"`
	LicensePlanTier  string  `json:"license_plan_tier,omitempty"`  // lite, turbo, nitro
	LicenseExpiresAt *string `json:"license_expires_at,omitempty"` // ISO 8601
	SpeedLimitMbps   int     `json:"speed_limit_mbps"`
	MaxConnections   int     `json:"max_connections"`
}

// HeartbeatRequest is sent periodically from the Android app
type HeartbeatRequest struct {
	PhoneID           string `json:"phone_id" binding:"required"`
	Status            string `json:"status"`
	CurrentIP         string `json:"current_ip"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}
