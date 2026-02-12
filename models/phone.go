package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
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

	// SIM card info (updated via status updates)
	SimCountry string `json:"sim_country"` // ISO country code (e.g., "US", "GB")
	SimCarrier string `json:"sim_carrier"` // Carrier name

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
	HubServerIP             string            `json:"hub_server_ip,omitempty"` // Hub server IP for proxy connection
	ProxyDomain             string            `json:"proxy_domain,omitempty"` // Full proxy domain (e.g., "abc123def.cn.yalx.in")
	HubServer               HubServerResponse `json:"hub_server,omitempty"`
	RotationMode            string            `json:"rotation_mode"`              // 'off', 'timed', 'api'
	RotationIntervalMinutes int               `json:"rotation_interval_minutes"`  // 2-120 minutes
	SimCountry              string            `json:"sim_country"`
	SimCarrier              string            `json:"sim_carrier"`
	CreatedAt               time.Time         `json:"created_at"`
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
	resp := PhoneResponse{
		ID:                      p.ID,
		Name:                    p.Name,
		PairedAt:                p.PairedAt,
		ProxyDomain:             p.ProxyDomain,
		RotationMode:            p.RotationMode,
		RotationIntervalMinutes: p.RotationIntervalMinutes,
		SimCountry:              p.SimCountry,
		SimCarrier:              p.SimCarrier,
		CreatedAt:               p.CreatedAt,
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
}

// HeartbeatRequest is sent periodically from the Android app
type HeartbeatRequest struct {
	PhoneID           string `json:"phone_id" binding:"required"`
	Status            string `json:"status"`
	CurrentIP         string `json:"current_ip"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}
