package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProxyType string

const (
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeBoth   ProxyType = "both"
)

type AuthType string

const (
	AuthTypeIP       AuthType = "ip"
	AuthTypeUserPass AuthType = "userpass"
)

// ConnectionCredential represents proxy access credentials for a phone
type ConnectionCredential struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID   uuid.UUID `gorm:"type:uuid;not null;index" json:"phone_id"`
	Name      string    `gorm:"not null" json:"name"` // Friendly name like "Home IP", "Work"
	AuthType  AuthType  `gorm:"not null" json:"auth_type"`
	ProxyType ProxyType `gorm:"default:both" json:"proxy_type"`

	// IP-based auth
	AllowedIP string `json:"allowed_ip,omitempty"`

	// Username/password auth
	Username string `json:"username,omitempty"`
	Password string `json:"-"` // Hidden in JSON responses

	// Limits
	BandwidthLimit  int64      `json:"bandwidth_limit,omitempty"` // Bytes per month, 0 = unlimited
	BandwidthUsed   int64      `json:"bandwidth_used"`
	ConnectionCount int64      `json:"connection_count"` // Total number of connections
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`

	// Status
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

func (c *ConnectionCredential) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

// ConnectionCredentialResponse is the public representation
type ConnectionCredentialResponse struct {
	ID              uuid.UUID  `json:"id"`
	PhoneID         uuid.UUID  `json:"phone_id"`
	Name            string     `json:"name"`
	AuthType        AuthType   `json:"auth_type"`
	ProxyType       ProxyType  `json:"proxy_type"`
	AllowedIP       string     `json:"allowed_ip,omitempty"`
	Username        string     `json:"username,omitempty"`
	Password        string     `json:"password,omitempty"` // Plain password for proxy auth
	BandwidthLimit  int64      `json:"bandwidth_limit,omitempty"`
	BandwidthUsed   int64      `json:"bandwidth_used"`
	ConnectionCount int64      `json:"connection_count"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	IsActive        bool       `json:"is_active"`
	LastUsed        *time.Time `json:"last_used,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func (c *ConnectionCredential) ToResponse() ConnectionCredentialResponse {
	return ConnectionCredentialResponse{
		ID:              c.ID,
		PhoneID:         c.PhoneID,
		Name:            c.Name,
		AuthType:        c.AuthType,
		ProxyType:       c.ProxyType,
		AllowedIP:       c.AllowedIP,
		Username:        c.Username,
		Password:        c.Password,
		BandwidthLimit:  c.BandwidthLimit,
		BandwidthUsed:   c.BandwidthUsed,
		ConnectionCount: c.ConnectionCount,
		ExpiresAt:       c.ExpiresAt,
		IsActive:        c.IsActive,
		LastUsed:        c.LastUsed,
		CreatedAt:       c.CreatedAt,
	}
}

// ConnectionCredentialWithPassword includes plain password (only for creation response)
type ConnectionCredentialWithPassword struct {
	ConnectionCredentialResponse
	Password string `json:"password,omitempty"` // Plain password, shown only on creation
}

// RotationToken allows external API access to rotate IP for a phone
type RotationToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID   uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"phone_id"`
	Token     string    `gorm:"uniqueIndex;not null" json:"-"`
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

func (r *RotationToken) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	if r.Token == "" {
		r.Token = GenerateRotationToken()
	}
	return nil
}

// GenerateRotationToken creates a secure token for rotation API
func GenerateRotationToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "rot_" + hex.EncodeToString(bytes)
}

// RotationTokenResponse is the public representation
type RotationTokenResponse struct {
	ID        uuid.UUID  `json:"id"`
	PhoneID   uuid.UUID  `json:"phone_id"`
	Token     string     `json:"token,omitempty"` // Only shown on creation
	Endpoint  string     `json:"endpoint"`
	IsActive  bool       `json:"is_active"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (r *RotationToken) ToResponse(baseURL string, showToken bool) RotationTokenResponse {
	resp := RotationTokenResponse{
		ID:        r.ID,
		PhoneID:   r.PhoneID,
		Endpoint:  baseURL + "/api/rotate/" + r.Token,
		IsActive:  r.IsActive,
		LastUsed:  r.LastUsed,
		CreatedAt: r.CreatedAt,
	}
	if showToken {
		resp.Token = r.Token
	}
	return resp
}

// Request/Response types for API
type CreateCredentialRequest struct {
	Name           string    `json:"name" binding:"required"`
	AuthType       AuthType  `json:"auth_type" binding:"required"`
	ProxyType      ProxyType `json:"proxy_type"`
	AllowedIP      string    `json:"allowed_ip"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	BandwidthLimit int64     `json:"bandwidth_limit"`
	ExpiresAt      string    `json:"expires_at"`
}

type UpdateCredentialRequest struct {
	Name           *string    `json:"name"`
	ProxyType      *ProxyType `json:"proxy_type"`
	AllowedIP      *string    `json:"allowed_ip"`
	Username       *string    `json:"username"`
	Password       *string    `json:"password"`
	BandwidthLimit *int64     `json:"bandwidth_limit"`
	ExpiresAt      *string    `json:"expires_at"`
	IsActive       *bool      `json:"is_active"`
}
