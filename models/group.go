package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PhoneGroup represents a user-defined group of phones
type PhoneGroup struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	Name        string     `gorm:"not null" json:"name"`
	Color       string     `gorm:"default:'#6366f1'" json:"color"` // Hex color for UI
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`

	// Relationships
	User   User                   `gorm:"foreignKey:UserID" json:"-"`
	Phones []PhoneGroupMembership `gorm:"foreignKey:GroupID" json:"-"`
}

func (g *PhoneGroup) BeforeCreate(tx *gorm.DB) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	return nil
}

// PhoneGroupMembership is the many-to-many relationship between phones and groups
type PhoneGroupMembership struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null;index:idx_group_phone,unique" json:"group_id"`
	PhoneID   uuid.UUID `gorm:"type:uuid;not null;index:idx_group_phone,unique" json:"phone_id"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	Group PhoneGroup `gorm:"foreignKey:GroupID" json:"-"`
	Phone Phone      `gorm:"foreignKey:PhoneID" json:"-"`
}

func (m *PhoneGroupMembership) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

// GroupResponse is the public representation of a group
type GroupResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Color       string    `json:"color"`
	Description string    `json:"description,omitempty"`
	PhoneCount  int       `json:"phone_count"`
	PhoneIDs    []string  `json:"phone_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

// ToResponse converts a PhoneGroup to GroupResponse
func (g *PhoneGroup) ToResponse(phoneIDs []string) GroupResponse {
	return GroupResponse{
		ID:          g.ID,
		Name:        g.Name,
		Color:       g.Color,
		Description: g.Description,
		PhoneCount:  len(phoneIDs),
		PhoneIDs:    phoneIDs,
		CreatedAt:   g.CreatedAt,
	}
}

// CreateGroupRequest for creating a new group
type CreateGroupRequest struct {
	Name        string   `json:"name" binding:"required,min=1,max=100"`
	Color       string   `json:"color"`
	Description string   `json:"description"`
	PhoneIDs    []string `json:"phone_ids"` // Optional: add phones on creation
}

// UpdateGroupRequest for updating a group
type UpdateGroupRequest struct {
	Name        *string `json:"name"`
	Color       *string `json:"color"`
	Description *string `json:"description"`
}

// AddPhonesToGroupRequest for adding phones to a group
type AddPhonesToGroupRequest struct {
	PhoneIDs []string `json:"phone_ids" binding:"required,min=1"`
}

// RemovePhoneFromGroupRequest for removing a phone from a group
type RemovePhoneFromGroupRequest struct {
	PhoneID string `json:"phone_id" binding:"required"`
}

// MassActionRequest for performing mass actions on multiple phones
type MassActionRequest struct {
	PhoneIDs []string `json:"phone_ids" binding:"required,min=1"`
}

// MassRotationSettingsRequest for mass updating rotation settings
type MassRotationSettingsRequest struct {
	PhoneIDs                []string `json:"phone_ids" binding:"required,min=1"`
	RotationMode            string   `json:"rotation_mode" binding:"required,oneof=off timed api"`
	RotationIntervalMinutes int      `json:"rotation_interval_minutes"` // Required when mode is 'timed'
}

// MassCredentialRequest for mass creating/updating credentials
type MassCredentialRequest struct {
	PhoneIDs  []string `json:"phone_ids" binding:"required,min=1"`
	AuthType  string   `json:"auth_type" binding:"required,oneof=ip_whitelist username_password"`
	ProxyType string   `json:"proxy_type" binding:"required,oneof=socks5 http both"`

	// For IP whitelist
	AllowedIP string `json:"allowed_ip"`

	// For username/password
	Username string `json:"username"`
	Password string `json:"password"`

	// Optional limits
	BandwidthLimit int64  `json:"bandwidth_limit"` // bytes
	ExpiresAt      string `json:"expires_at"`      // ISO8601 timestamp
}

// ExportRequest for exporting proxy configurations
type ExportRequest struct {
	PhoneIDs         []string `json:"phone_ids" binding:"required,min=1"`
	Format           string   `json:"format" binding:"required,oneof=plain auth json csv curl"`
	ProxyType        string   `json:"proxy_type" binding:"required,oneof=socks5 http"`
	IncludeRotation  bool     `json:"include_rotation"`  // Include rotation API endpoint
	CredentialID     *string  `json:"credential_id"`     // Specific credential to use (optional)
}

// ExportResponse contains the exported proxy configurations
type ExportResponse struct {
	Format  string   `json:"format"`
	Content string   `json:"content"`
	Lines   []string `json:"lines,omitempty"` // Individual lines for UI display
}

// MassActionResult for tracking results of mass operations
type MassActionResult struct {
	Total     int      `json:"total"`
	Succeeded int      `json:"succeeded"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}
