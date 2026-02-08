package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PhoneStatus string

const (
	StatusPending PhoneStatus = "pending"
	StatusOnline  PhoneStatus = "online"
	StatusOffline PhoneStatus = "offline"
)

type Phone struct {
	ID              uuid.UUID   `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID          uuid.UUID   `gorm:"type:uuid;not null" json:"user_id"`
	ServerID        *uuid.UUID  `gorm:"type:uuid" json:"server_id"`
	Name            string      `gorm:"not null" json:"name"`
	PairingCode     string      `gorm:"uniqueIndex" json:"-"`
	PairingPIN      string      `json:"-"` // 6-digit PIN for QR pairing
	PairedAt        *time.Time  `json:"paired_at"`
	ProxyPort       int         `json:"proxy_port"`
	WireGuardConfig string      `json:"-"` // Sensitive, only returned during pairing
	Status          PhoneStatus `gorm:"default:pending" json:"status"`
	LastSeen        *time.Time  `json:"last_seen"`
	CurrentIP       string      `json:"current_ip"`
	CreatedAt       time.Time   `json:"created_at"`

	// Relationships
	User   User    `gorm:"foreignKey:UserID" json:"-"`
	Server *Server `gorm:"foreignKey:ServerID" json:"server,omitempty"`
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
	// Generate 6-digit PIN
	bytes := make([]byte, 3)
	rand.Read(bytes)
	pin := (int(bytes[0])<<16 | int(bytes[1])<<8 | int(bytes[2])) % 1000000
	return fmt.Sprintf("%06d", pin)
}

// PhoneResponse is the public representation
type PhoneResponse struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Status     PhoneStatus    `json:"status"`
	CurrentIP  string         `json:"current_ip,omitempty"`
	LastSeen   *time.Time     `json:"last_seen,omitempty"`
	PairedAt   *time.Time     `json:"paired_at,omitempty"`
	ProxyPort  int            `json:"proxy_port,omitempty"`
	Server     ServerResponse `json:"server,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
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
		ID:        p.ID,
		Name:      p.Name,
		Status:    p.Status,
		CurrentIP: p.CurrentIP,
		LastSeen:  p.LastSeen,
		PairedAt:  p.PairedAt,
		ProxyPort: p.ProxyPort,
		CreatedAt: p.CreatedAt,
	}
	if p.Server != nil {
		resp.Server = p.Server.ToResponse()
	}
	return resp
}

// PairingRequest is sent from the Android app (QR code + PIN method)
type PairingRequest struct {
	PairingCode string `json:"pairing_code" binding:"required"`
	PairingPIN  string `json:"pairing_pin" binding:"required"`
	DeviceInfo  string `json:"device_info"`
}

// PhoneLoginRequest is sent from Android app (email/password method)
type PhoneLoginRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
	PhoneID    string `json:"phone_id" binding:"required"` // Select which phone to connect
	DeviceInfo string `json:"device_info"`
}

// PhoneListForLoginResponse is returned when listing phones for login
type PhoneListForLoginResponse struct {
	Phones []PhoneLoginInfo `json:"phones"`
}

// PhoneLoginInfo is minimal phone info for login selection
type PhoneLoginInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	ServerName string `json:"server_name"`
}

// PairingResponse is sent back to the Android app
type PairingResponse struct {
	PhoneID         string `json:"phone_id"`
	WireGuardConfig string `json:"wireguard_config"`
	CentrifugoURL   string `json:"centrifugo_url"`
	CentrifugoToken string `json:"centrifugo_token"`
	APIBaseURL      string `json:"api_base_url"`
}

// HeartbeatRequest is sent periodically from the Android app
type HeartbeatRequest struct {
	PhoneID           string `json:"phone_id" binding:"required"`
	Status            string `json:"status"`
	CurrentIP         string `json:"current_ip"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}
