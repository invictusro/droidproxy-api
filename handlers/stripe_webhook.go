package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/paymentmethod"
	"github.com/stripe/stripe-go/v82/webhook"
)

// HandleStripeWebhook processes Stripe webhook events
func HandleStripeWebhook(c *gin.Context) {
	const MaxBodyBytes = int64(65536)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodyBytes)

	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Stripe webhook: Error reading body: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Error reading body"})
		return
	}

	// Verify webhook signature
	sigHeader := c.GetHeader("Stripe-Signature")
	event, err := webhook.ConstructEvent(payload, sigHeader, config.AppConfig.StripeWebhookSecret)
	if err != nil {
		log.Printf("Stripe webhook: Invalid signature: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	log.Printf("Stripe webhook received: %s", event.Type)

	switch event.Type {
	case "checkout.session.completed":
		var session stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
			log.Printf("Stripe webhook: Error parsing checkout.session.completed: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Error parsing event"})
			return
		}
		handleCheckoutCompleted(&session)

	case "payment_intent.succeeded":
		var paymentIntent stripe.PaymentIntent
		if err := json.Unmarshal(event.Data.Raw, &paymentIntent); err != nil {
			log.Printf("Stripe webhook: Error parsing payment_intent.succeeded: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Error parsing event"})
			return
		}
		handlePaymentIntentSucceeded(&paymentIntent)

	default:
		log.Printf("Stripe webhook: Unhandled event type: %s", event.Type)
	}

	c.JSON(http.StatusOK, gin.H{"received": true})
}

// handleCheckoutCompleted processes successful checkout sessions
func handleCheckoutCompleted(session *stripe.CheckoutSession) {
	log.Printf("Checkout completed: %s, payment_status: %s", session.ID, session.PaymentStatus)

	// Only process if payment is complete
	if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		log.Printf("Checkout session not paid yet: %s", session.PaymentStatus)
		return
	}

	// Get metadata
	userIDStr, ok := session.Metadata["user_id"]
	if !ok {
		log.Printf("Checkout completed but no user_id in metadata")
		return
	}

	topupType, ok := session.Metadata["type"]
	// Accept both balance_topup (legacy) and balance_deposit (new billing system)
	if !ok || (topupType != "balance_topup" && topupType != "balance_deposit") {
		log.Printf("Checkout completed but not a balance topup/deposit: %s", topupType)
		return
	}

	amountStr, ok := session.Metadata["amount"]
	if !ok {
		log.Printf("Checkout completed but no amount in metadata")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("Invalid user_id in metadata: %s", userIDStr)
		return
	}

	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil {
		log.Printf("Invalid amount in metadata: %s", amountStr)
		return
	}

	// Credit the user's balance
	creditBalance(userID, amount, session.PaymentIntent.ID, "")

	// Sync billing profile from Stripe customer details (for balance_deposit type)
	if topupType == "balance_deposit" {
		syncBillingProfile(userID, session)
	}
}

// handlePaymentIntentSucceeded processes successful payment intents
func handlePaymentIntentSucceeded(pi *stripe.PaymentIntent) {
	log.Printf("Payment intent succeeded: %s, amount: %d", pi.ID, pi.Amount)

	// Check if this is a balance topup
	topupType, ok := pi.Metadata["type"]
	if !ok || topupType != "balance_topup" {
		log.Printf("Payment intent not a balance topup")
		return
	}

	userIDStr, ok := pi.Metadata["user_id"]
	if !ok {
		log.Printf("Payment intent succeeded but no user_id in metadata")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("Invalid user_id in metadata: %s", userIDStr)
		return
	}

	amountStr, ok := pi.Metadata["amount"]
	if !ok {
		log.Printf("Payment intent succeeded but no amount in metadata")
		return
	}

	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil {
		log.Printf("Invalid amount in metadata: %s", amountStr)
		return
	}

	// Credit the balance
	creditBalance(userID, amount, pi.ID, "")

	// Save the payment method if setup_future_usage was set
	if pi.PaymentMethod != nil && pi.Customer != nil {
		savePaymentMethod(userID, pi.Customer.ID, pi.PaymentMethod.ID)
	}
}

// creditBalance adds funds to a user's balance
func creditBalance(userID uuid.UUID, amount int64, paymentIntentID, invoiceID string) {
	// Check if this transaction already exists (idempotency)
	var existingTx models.BalanceTransaction
	query := database.DB.Where("user_id = ? AND amount = ? AND reason = ?", userID, amount, models.ReasonStripeTopup)
	if paymentIntentID != "" {
		query = query.Where("stripe_payment_intent_id = ?", paymentIntentID)
	}
	if err := query.First(&existingTx).Error; err == nil {
		log.Printf("Transaction already exists for payment_intent: %s", paymentIntentID)
		return
	}

	// Find user
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		log.Printf("User not found: %s", userID)
		return
	}

	// Start transaction
	tx := database.DB.Begin()

	// Update balance
	now := time.Now()
	newBalance := user.Balance + amount
	if err := tx.Model(&user).Updates(map[string]interface{}{
		"balance":            newBalance,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("Failed to update balance: %v", err)
		return
	}

	// Create transaction record
	transaction := models.BalanceTransaction{
		UserID:                userID,
		Type:                  models.TransactionCredit,
		Amount:                amount,
		Reason:                models.ReasonStripeTopup,
		Description:           fmt.Sprintf("Balance top-up: $%.2f", float64(amount)/100),
		StripePaymentIntentID: paymentIntentID,
		StripeInvoiceID:       invoiceID,
		CreatedAt:             now,
	}

	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		log.Printf("Failed to create transaction record: %v", err)
		return
	}

	tx.Commit()
	log.Printf("Successfully credited $%.2f to user %s. New balance: $%.2f",
		float64(amount)/100, userID, float64(newBalance)/100)
}

// syncBillingProfile syncs billing profile from Stripe checkout session
func syncBillingProfile(userID uuid.UUID, session *stripe.CheckoutSession) {
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		log.Printf("syncBillingProfile: User not found: %s", userID)
		return
	}

	updates := make(map[string]interface{})

	// Extract customer details from session
	if session.CustomerDetails != nil {
		if session.CustomerDetails.Name != "" {
			updates["billing_name"] = session.CustomerDetails.Name
		}

		// Extract address
		if session.CustomerDetails.Address != nil {
			addr := session.CustomerDetails.Address
			if addr.Line1 != "" {
				updates["billing_address"] = addr.Line1
				if addr.Line2 != "" {
					updates["billing_address"] = addr.Line1 + ", " + addr.Line2
				}
			}
			if addr.City != "" {
				updates["billing_city"] = addr.City
			}
			if addr.State != "" {
				updates["billing_county"] = addr.State
			}
			if addr.Country != "" {
				updates["billing_country"] = addr.Country
			}
		}

		// Extract Tax ID (CUI/VAT)
		if len(session.CustomerDetails.TaxIDs) > 0 {
			for _, taxID := range session.CustomerDetails.TaxIDs {
				// Accept eu_vat, ro_tin, or any other tax ID type
				if taxID.Value != "" {
					updates["billing_cui"] = taxID.Value
					break
				}
			}
		}
	}

	// Set billing_day on first deposit (if not already set)
	if user.BillingDay == nil {
		today := time.Now().Day()
		if today > 28 {
			today = 28 // Cap at 28 to avoid February issues
		}
		updates["billing_day"] = today
		log.Printf("syncBillingProfile: Set billing_day=%d for user %s", today, userID)
	}

	// Apply updates
	if len(updates) > 0 {
		if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
			log.Printf("syncBillingProfile: Failed to update user: %v", err)
			return
		}
		log.Printf("syncBillingProfile: Updated billing profile for user %s", userID)
	}
}

// savePaymentMethod saves a payment method for future use
func savePaymentMethod(userID uuid.UUID, stripeCustomerID, paymentMethodID string) {
	stripe.Key = config.AppConfig.StripeSecretKey

	// Check if already saved
	var existing models.PaymentMethod
	if err := database.DB.Where("stripe_payment_method_id = ?", paymentMethodID).First(&existing).Error; err == nil {
		log.Printf("Payment method already saved: %s", paymentMethodID)
		return
	}

	// Get payment method details from Stripe
	pm, err := paymentmethod.Get(paymentMethodID, nil)
	if err != nil {
		log.Printf("Failed to get payment method details: %v", err)
		return
	}

	// Only save cards
	if pm.Type != stripe.PaymentMethodTypeCard {
		log.Printf("Payment method is not a card: %s", pm.Type)
		return
	}

	// Check if user has any payment methods (first one will be default)
	var count int64
	database.DB.Model(&models.PaymentMethod{}).Where("user_id = ?", userID).Count(&count)
	isDefault := count == 0

	// Save to database
	method := models.PaymentMethod{
		UserID:                userID,
		StripeCustomerID:      stripeCustomerID,
		StripePaymentMethodID: paymentMethodID,
		CardBrand:             string(pm.Card.Brand),
		CardLast4:             pm.Card.Last4,
		CardExpMonth:          int(pm.Card.ExpMonth),
		CardExpYear:           int(pm.Card.ExpYear),
		IsDefault:             isDefault,
	}

	if err := database.DB.Create(&method).Error; err != nil {
		log.Printf("Failed to save payment method: %v", err)
		return
	}

	log.Printf("Saved payment method %s for user %s", paymentMethodID, userID)
}
