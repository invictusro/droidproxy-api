package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PlanTier represents the subscription tier
type PlanTier string

const (
	PlanLite  PlanTier = "lite"
	PlanTurbo PlanTier = "turbo"
	PlanNitro PlanTier = "nitro"
)

// Plan pricing in cents
const (
	PriceLite  int64 = 500  // $5.00
	PriceTurbo int64 = 700  // $7.00
	PriceNitro int64 = 900  // $9.00
)

// Plan limits
type PlanLimits struct {
	SpeedLimitMbps int // Bandwidth limit in Mbit/sec
	MaxConnections int // Max concurrent proxy connections
	LogWeeks       int // Log retention in weeks
}

// GetPlanLimits returns the limits for a given plan tier
func GetPlanLimits(tier PlanTier) PlanLimits {
	switch tier {
	case PlanLite:
		return PlanLimits{SpeedLimitMbps: 5, MaxConnections: 4, LogWeeks: 2}
	case PlanTurbo:
		return PlanLimits{SpeedLimitMbps: 25, MaxConnections: 7, LogWeeks: 4}
	case PlanNitro:
		return PlanLimits{SpeedLimitMbps: 100, MaxConnections: 20, LogWeeks: 12}
	default:
		return PlanLimits{SpeedLimitMbps: 0, MaxConnections: 0, LogWeeks: 0}
	}
}

// GetPlanPrice returns the monthly price in cents for a given plan tier
func GetPlanPrice(tier PlanTier) int64 {
	switch tier {
	case PlanLite:
		return PriceLite
	case PlanTurbo:
		return PriceTurbo
	case PlanNitro:
		return PriceNitro
	default:
		return 0
	}
}

// LicenseStatus represents the status of a phone license
type LicenseStatus string

const (
	LicenseActive    LicenseStatus = "active"
	LicenseExpired   LicenseStatus = "expired"
	LicenseCancelled LicenseStatus = "cancelled"
)

// PhoneLicense represents a monthly license for a phone
type PhoneLicense struct {
	ID         uuid.UUID     `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID    uuid.UUID     `gorm:"type:uuid;not null;index" json:"phone_id"`
	UserID     uuid.UUID     `gorm:"type:uuid;not null;index" json:"user_id"`
	PlanTier   PlanTier      `gorm:"type:varchar(20);not null" json:"plan_tier"`
	PricePaid  int64         `json:"price_paid"` // cents
	StartedAt  time.Time     `json:"started_at"`
	ExpiresAt  time.Time     `gorm:"index" json:"expires_at"`
	AutoExtend bool          `gorm:"default:false" json:"auto_extend"`
	Status     LicenseStatus `gorm:"type:varchar(20);default:'active'" json:"status"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
	User  User  `gorm:"foreignKey:UserID" json:"-"`
}

func (l *PhoneLicense) BeforeCreate(tx *gorm.DB) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	return nil
}

// IsActive returns true if the license is currently active
func (l *PhoneLicense) IsActive() bool {
	return l.Status == LicenseActive && time.Now().Before(l.ExpiresAt)
}

// DaysRemaining returns the number of days until license expires
func (l *PhoneLicense) DaysRemaining() int {
	if time.Now().After(l.ExpiresAt) {
		return 0
	}
	return int(time.Until(l.ExpiresAt).Hours() / 24)
}

// LicenseResponse is the public representation
type LicenseResponse struct {
	ID            uuid.UUID     `json:"id"`
	PhoneID       uuid.UUID     `json:"phone_id"`
	PlanTier      PlanTier      `json:"plan_tier"`
	PricePaid     int64         `json:"price_paid"`
	StartedAt     time.Time     `json:"started_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	AutoExtend    bool          `json:"auto_extend"`
	Status        LicenseStatus `json:"status"`
	DaysRemaining int           `json:"days_remaining"`
	Limits        PlanLimits    `json:"limits"`
}

func (l *PhoneLicense) ToResponse() LicenseResponse {
	return LicenseResponse{
		ID:            l.ID,
		PhoneID:       l.PhoneID,
		PlanTier:      l.PlanTier,
		PricePaid:     l.PricePaid,
		StartedAt:     l.StartedAt,
		ExpiresAt:     l.ExpiresAt,
		AutoExtend:    l.AutoExtend,
		Status:        l.Status,
		DaysRemaining: l.DaysRemaining(),
		Limits:        GetPlanLimits(l.PlanTier),
	}
}

// PurchaseLicenseRequest is used when purchasing a license
type PurchaseLicenseRequest struct {
	PlanTier   string `json:"plan_tier" binding:"required,oneof=lite turbo nitro"`
	AutoExtend bool   `json:"auto_extend"`
}

// UpdateLicenseRequest is used when updating license settings
type UpdateLicenseRequest struct {
	AutoExtend *bool `json:"auto_extend"`
}
