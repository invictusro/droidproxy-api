package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TransactionType represents the type of balance transaction
type TransactionType string

const (
	TransactionCredit TransactionType = "credit"
	TransactionDebit  TransactionType = "debit"
)

// TransactionReason describes why the transaction occurred
type TransactionReason string

const (
	ReasonLicensePurchase TransactionReason = "license_purchase"
	ReasonLicenseRenewal  TransactionReason = "license_renewal"
	ReasonLicenseUpgrade  TransactionReason = "license_upgrade"
	ReasonAdminCredit     TransactionReason = "admin_credit"
	ReasonAdminDebit      TransactionReason = "admin_debit"
	ReasonRefund          TransactionReason = "refund"
	ReasonStripeTopup     TransactionReason = "stripe_topup"
	ReasonAutoCharge      TransactionReason = "auto_charge" // Auto-charged for license renewal
)

// BalanceTransaction records all balance changes
type BalanceTransaction struct {
	ID          uuid.UUID         `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      uuid.UUID         `gorm:"type:uuid;not null;index" json:"user_id"`
	Type        TransactionType   `gorm:"type:varchar(20);not null" json:"type"`
	Amount      int64             `json:"amount"` // Always positive, Type indicates direction
	Reason      TransactionReason `gorm:"type:varchar(30)" json:"reason"`
	ReferenceID *uuid.UUID        `gorm:"type:uuid" json:"reference_id,omitempty"` // PhoneID or LicenseID
	Description string            `json:"description"`
	CreatedAt   time.Time         `gorm:"index" json:"created_at"`

	// Stripe tracking
	StripeInvoiceID       string `gorm:"type:varchar(255)" json:"stripe_invoice_id,omitempty"`
	StripePaymentIntentID string `gorm:"type:varchar(255)" json:"stripe_payment_intent_id,omitempty"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (t *BalanceTransaction) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

// TransactionResponse is the public representation
type TransactionResponse struct {
	ID          uuid.UUID         `json:"id"`
	Type        TransactionType   `json:"type"`
	Amount      int64             `json:"amount"`
	AmountDelta int64             `json:"amount_delta"` // Positive or negative based on type
	Reason      TransactionReason `json:"reason"`
	ReferenceID *uuid.UUID        `json:"reference_id,omitempty"`
	Description string            `json:"description"`
	CreatedAt   time.Time         `json:"created_at"`
}

func (t *BalanceTransaction) ToResponse() TransactionResponse {
	delta := t.Amount
	if t.Type == TransactionDebit {
		delta = -t.Amount
	}
	return TransactionResponse{
		ID:          t.ID,
		Type:        t.Type,
		Amount:      t.Amount,
		AmountDelta: delta,
		Reason:      t.Reason,
		ReferenceID: t.ReferenceID,
		Description: t.Description,
		CreatedAt:   t.CreatedAt,
	}
}

// BalanceResponse is returned when querying user balance
type BalanceResponse struct {
	Balance          int64      `json:"balance"`           // Current balance in cents
	BalanceFormatted string     `json:"balance_formatted"` // e.g., "$12.50"
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

// AdminBalanceRequest is used by admins to adjust user balance
type AdminBalanceRequest struct {
	Amount      int64  `json:"amount" binding:"required"`      // Amount in cents (positive)
	Type        string `json:"type" binding:"required,oneof=credit debit"`
	Description string `json:"description"`
}
