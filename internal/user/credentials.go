package user

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// AuthType represents the type of proxy authentication
type AuthType string

const (
	AuthTypeUserPass   AuthType = "userpass"
	AuthTypeIPWhitelist AuthType = "ip_whitelist"
)

// ProxyType represents the type of proxy connection allowed
type ProxyType string

const (
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeBoth   ProxyType = "both"
)

// Credential represents a proxy connection credential
type Credential struct {
	ID        string     `json:"id"`
	PhoneID   string     `json:"phone_id"`
	AuthType  AuthType   `json:"auth_type"`
	ProxyType ProxyType  `json:"proxy_type"`
	AllowedIP string     `json:"allowed_ip,omitempty"`
	Username  string     `json:"username,omitempty"`
	Password  string     `json:"password,omitempty"` // Stored as hash for security
	IsActive  bool       `json:"is_active"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// CredentialSummary is a brief view of a credential for listings
type CredentialSummary struct {
	ID        string    `json:"id"`
	AuthType  AuthType  `json:"auth_type"`
	ProxyType ProxyType `json:"proxy_type"`
	Username  string    `json:"username,omitempty"`
	AllowedIP string    `json:"allowed_ip,omitempty"`
	IsActive  bool      `json:"is_active"`
}

// RotationToken is a special token for external IP rotation requests
type RotationToken struct {
	Token     string    `json:"token"`
	PhoneID   string    `json:"phone_id"`
	CreatedAt time.Time `json:"created_at"`
}

// GenerateRotationToken generates a secure rotation token
func GenerateRotationToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateUsername generates a random username for proxy auth
func GenerateUsername(prefix string, length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return prefix + hex.EncodeToString(bytes)[:length]
}

// GeneratePassword generates a random password for proxy auth
func GeneratePassword(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// IsExpired checks if a credential has expired
func (c *Credential) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return c.ExpiresAt.Before(time.Now())
}

// IsValid checks if a credential is valid (active and not expired)
func (c *Credential) IsValid() bool {
	return c.IsActive && !c.IsExpired()
}

// SupportsSOCKS5 checks if the credential allows SOCKS5 connections
func (c *Credential) SupportsSOCKS5() bool {
	return c.ProxyType == ProxyTypeSOCKS5 || c.ProxyType == ProxyTypeBoth
}

// SupportsHTTP checks if the credential allows HTTP connections
func (c *Credential) SupportsHTTP() bool {
	return c.ProxyType == ProxyTypeHTTP || c.ProxyType == ProxyTypeBoth
}

// ToSummary converts a Credential to a CredentialSummary
func (c *Credential) ToSummary() CredentialSummary {
	return CredentialSummary{
		ID:        c.ID,
		AuthType:  c.AuthType,
		ProxyType: c.ProxyType,
		Username:  c.Username,
		AllowedIP: c.AllowedIP,
		IsActive:  c.IsActive,
	}
}
