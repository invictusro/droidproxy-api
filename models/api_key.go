package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// APIKey represents a reseller API key for programmatic access
type APIKey struct {
	ID         uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	UserID     uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Name       string         `gorm:"type:varchar(100);not null" json:"name"`
	KeyHash    string         `gorm:"type:varchar(64);not null;uniqueIndex" json:"-"` // SHA256 hash
	KeyPrefix  string         `gorm:"type:varchar(12);not null" json:"key_prefix"`    // First 8 chars for identification
	Scope      string         `gorm:"type:varchar(20);not null;default:'all'" json:"scope"` // 'all' or 'groups'
	GroupIDs   pq.StringArray `gorm:"type:text[]" json:"group_ids"`                   // Group IDs if scope is 'groups'
	IsActive   bool           `gorm:"default:true" json:"is_active"`
	LastUsedAt *time.Time     `json:"last_used_at"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`

	// Associations
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (k *APIKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	return nil
}

// GenerateAPIKey creates a new API key and returns the raw key (only shown once)
func GenerateAPIKey() (rawKey string, keyHash string, keyPrefix string) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	rand.Read(bytes)

	// Create the raw key with prefix
	rawKey = "dp_" + hex.EncodeToString(bytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(rawKey))
	keyHash = hex.EncodeToString(hash[:])

	// Prefix for identification (dp_XXXXXXXX)
	keyPrefix = rawKey[:12]

	return rawKey, keyHash, keyPrefix
}

// HashAPIKey hashes a raw API key for comparison
func HashAPIKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

// APIKeyResponse is the response format for API keys (without the actual key)
type APIKeyResponse struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scope      string     `json:"scope"`
	GroupIDs   []string   `json:"group_ids"`
	IsActive   bool       `json:"is_active"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (k *APIKey) ToResponse() APIKeyResponse {
	groupIDs := []string{}
	if k.GroupIDs != nil {
		groupIDs = k.GroupIDs
	}
	return APIKeyResponse{
		ID:         k.ID,
		Name:       k.Name,
		KeyPrefix:  k.KeyPrefix,
		Scope:      k.Scope,
		GroupIDs:   groupIDs,
		IsActive:   k.IsActive,
		LastUsedAt: k.LastUsedAt,
		CreatedAt:  k.CreatedAt,
	}
}

// APIKeyCreateResponse includes the raw key (only returned on creation)
type APIKeyCreateResponse struct {
	APIKeyResponse
	Key string `json:"key"` // The actual API key - only shown once!
}
