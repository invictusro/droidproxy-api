package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

type AuthProvider string

const (
	AuthLocal  AuthProvider = "local"
	AuthGoogle AuthProvider = "google"
)

type User struct {
	ID               uuid.UUID    `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email            string       `gorm:"uniqueIndex;not null" json:"email"`
	Name             string       `gorm:"not null" json:"name"`
	Password         string       `gorm:"" json:"-"`
	Picture          string       `json:"picture"`
	TelegramUsername string       `gorm:"type:varchar(255)" json:"telegram_username"` // Optional Telegram username (without @)
	Role             UserRole     `gorm:"default:user" json:"role"`
	AuthProvider     AuthProvider `gorm:"default:local" json:"auth_provider"`
	GoogleID         *string      `gorm:"uniqueIndex" json:"-"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`

	// Balance (in cents)
	Balance          int64      `gorm:"default:0" json:"balance"`
	BalanceUpdatedAt *time.Time `json:"balance_updated_at"`

	// Stripe integration
	StripeCustomerID string `gorm:"type:varchar(255)" json:"-"` // Stripe customer ID for payments

	// Billing Settings
	BillingDay           *int       `gorm:"default:null" json:"billing_day"`                         // Anchor day (1-28) for anniversary billing
	AutoRefillEnabled    bool       `gorm:"default:true" json:"auto_refill_enabled"`                 // Auto-charge on billing day
	LastAutoRefillAt     *time.Time `json:"last_auto_refill_at"`                                     // Safety: prevent double charges
	AutoRefillRetryCount int        `gorm:"default:0" json:"auto_refill_retry_count"`                // Failed attempt count (0-3)
	AutoRefillRetryUntil *time.Time `json:"auto_refill_retry_until"`                                 // Stop retrying after this date

	// Romanian B2B Billing Profile
	BillingName    string `gorm:"type:varchar(255)" json:"billing_name"`               // Company or full name
	BillingCUI     string `gorm:"type:varchar(50)" json:"billing_cui"`                 // Tax ID (e.g., RO123456)
	BillingRegCom  string `gorm:"type:varchar(50)" json:"billing_reg_com"`             // Reg. Com (e.g., J40/...)
	BillingAddress string `gorm:"type:text" json:"billing_address"`                    // Street address
	BillingCity    string `gorm:"type:varchar(100)" json:"billing_city"`               // City
	BillingCounty  string `gorm:"type:varchar(100)" json:"billing_county"`             // County/State
	BillingCountry string `gorm:"type:varchar(2);default:'RO'" json:"billing_country"` // ISO 2-letter country code

	// Relationships
	Phones []Phone `gorm:"foreignKey:UserID" json:"phones,omitempty"`
}

// HashPassword hashes the user's password
func (u *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(bytes)
	return nil
}

// CheckPassword compares password with hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// UserResponse is the public representation of a user
type UserResponse struct {
	ID               uuid.UUID `json:"id"`
	Email            string    `json:"email"`
	Name             string    `json:"name"`
	Picture          string    `json:"picture"`
	TelegramUsername string    `json:"telegram_username,omitempty"`
	Role             UserRole  `json:"role"`
	Balance          int64     `json:"balance"` // Balance in cents
	CreatedAt        time.Time `json:"created_at"`

	// Billing
	BillingDay        *int   `json:"billing_day,omitempty"`
	AutoRefillEnabled bool   `json:"auto_refill_enabled"`
	BillingName       string `json:"billing_name,omitempty"`
	BillingCUI        string `json:"billing_cui,omitempty"`
	BillingCountry    string `json:"billing_country,omitempty"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:                u.ID,
		Email:             u.Email,
		Name:              u.Name,
		Picture:           u.Picture,
		TelegramUsername:  u.TelegramUsername,
		Role:              u.Role,
		Balance:           u.Balance,
		CreatedAt:         u.CreatedAt,
		BillingDay:        u.BillingDay,
		AutoRefillEnabled: u.AutoRefillEnabled,
		BillingName:       u.BillingName,
		BillingCUI:        u.BillingCUI,
		BillingCountry:    u.BillingCountry,
	}
}
