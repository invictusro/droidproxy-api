package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DomainBlocklist represents a blocked domain pattern
type DomainBlocklist struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Pattern   string    `gorm:"not null;uniqueIndex" json:"pattern"` // e.g., "*.stripe.com", "paypal.com"
	Category  string    `json:"category"`                            // "payment", "kyc", "adult", etc.
	Reason    string    `json:"reason"`                              // Human-readable explanation
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName overrides the table name
func (DomainBlocklist) TableName() string {
	return "domain_blocklist"
}

func (b *DomainBlocklist) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}

// BlocklistPatternResponse is the response sent to phones
type BlocklistPatternResponse struct {
	Patterns  []string  `json:"patterns"`
	UpdatedAt time.Time `json:"updated_at"`
}
