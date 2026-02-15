package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PaymentMethod stores saved payment methods (cards) for auto-billing
type PaymentMethod struct {
	ID                    uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID                uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	StripeCustomerID      string     `gorm:"type:varchar(255);not null" json:"stripe_customer_id"`
	StripePaymentMethodID string     `gorm:"type:varchar(255);not null;uniqueIndex" json:"stripe_payment_method_id"`
	CardBrand             string     `gorm:"type:varchar(50)" json:"card_brand"`   // visa, mastercard, amex
	CardLast4             string     `gorm:"type:varchar(4)" json:"card_last4"`    // Last 4 digits
	CardExpMonth          int        `json:"card_exp_month"`
	CardExpYear           int        `json:"card_exp_year"`
	IsDefault             bool       `gorm:"default:false" json:"is_default"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (p *PaymentMethod) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// PaymentMethodResponse is the public representation
type PaymentMethodResponse struct {
	ID           uuid.UUID `json:"id"`
	CardBrand    string    `json:"card_brand"`
	CardLast4    string    `json:"card_last4"`
	CardExpMonth int       `json:"card_exp_month"`
	CardExpYear  int       `json:"card_exp_year"`
	IsDefault    bool      `json:"is_default"`
	CreatedAt    time.Time `json:"created_at"`
}

func (p *PaymentMethod) ToResponse() PaymentMethodResponse {
	return PaymentMethodResponse{
		ID:           p.ID,
		CardBrand:    p.CardBrand,
		CardLast4:    p.CardLast4,
		CardExpMonth: p.CardExpMonth,
		CardExpYear:  p.CardExpYear,
		IsDefault:    p.IsDefault,
		CreatedAt:    p.CreatedAt,
	}
}

// TopUpRequest for balance top-up
type TopUpRequest struct {
	Amount        int64  `json:"amount" binding:"required,min=500"`  // Amount in cents (min $5.00)
	PaymentMethod string `json:"payment_method" binding:"required,oneof=stripe crypto"` // stripe or crypto
}

// TopUpResponse after creating a payment
type TopUpResponse struct {
	PaymentURL string `json:"payment_url"`           // Stripe hosted invoice URL
	InvoiceID  string `json:"invoice_id,omitempty"`  // Stripe invoice ID
	Amount     int64  `json:"amount"`                // Amount in cents
	Status     string `json:"status"`                // pending, paid
}
