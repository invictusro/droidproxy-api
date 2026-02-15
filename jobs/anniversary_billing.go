package jobs

import (
	"fmt"
	"log"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/paymentintent"
)

const (
	// MaxAutoRefillAmount is the safety cap for auto-refill charges ($5500)
	MaxAutoRefillAmount = 550000 // in cents

	// MaxRetryAttempts is the number of times to retry a failed auto-refill
	MaxRetryAttempts = 3
)

// StartAnniversaryBillingJob runs the anniversary billing check daily
func StartAnniversaryBillingJob() {
	// Calculate time until next 00:05 UTC
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 5, 0, 0, time.UTC)
	if next.Before(now) {
		next = next.AddDate(0, 0, 1)
	}
	duration := next.Sub(now)

	log.Printf("[Jobs] Anniversary billing job will run at %s (in %v)", next.Format("2006-01-02 15:04:05 UTC"), duration)

	// Wait until 00:05 UTC, then run daily
	time.AfterFunc(duration, func() {
		processAnniversaryBilling()
		ticker := time.NewTicker(24 * time.Hour)
		go func() {
			for range ticker.C {
				processAnniversaryBilling()
			}
		}()
	})

	log.Println("[Jobs] Anniversary billing job started (runs daily at 00:05 UTC)")
}

// processAnniversaryBilling finds users whose billing day is today and processes auto-refill
func processAnniversaryBilling() {
	log.Println("[Jobs] Running anniversary billing check...")

	today := time.Now().Day()
	if today > 28 {
		today = 28 // Cap at 28 for February safety
	}

	// Find users with billing_day = today AND auto_refill_enabled = true
	var users []models.User
	if err := database.DB.Where("billing_day = ? AND auto_refill_enabled = ?", today, true).
		Find(&users).Error; err != nil {
		log.Printf("[Jobs] Error finding users for anniversary billing: %v", err)
		return
	}

	// Also find users who are in retry mode (failed payment, need to retry)
	var retryUsers []models.User
	if err := database.DB.Where("auto_refill_retry_count > 0 AND auto_refill_retry_count < ? AND auto_refill_enabled = ?",
		MaxRetryAttempts, true).Find(&retryUsers).Error; err != nil {
		log.Printf("[Jobs] Error finding retry users: %v", err)
	}

	// Merge and deduplicate
	userMap := make(map[string]models.User)
	for _, u := range users {
		userMap[u.ID.String()] = u
	}
	for _, u := range retryUsers {
		userMap[u.ID.String()] = u
	}

	if len(userMap) == 0 {
		log.Println("[Jobs] No users due for anniversary billing today")
		return
	}

	log.Printf("[Jobs] Found %d users for anniversary billing", len(userMap))

	for _, user := range userMap {
		processUserAnniversaryBilling(user)
	}

	log.Println("[Jobs] Anniversary billing check complete")
}

// processUserAnniversaryBilling handles billing for a single user
func processUserAnniversaryBilling(user models.User) {
	log.Printf("[Jobs] Processing anniversary billing for user %s (%s)", user.ID, user.Email)

	// SAFETY: Check if already charged in the last 24 hours
	if user.LastAutoRefillAt != nil {
		if time.Since(*user.LastAutoRefillAt) < 24*time.Hour {
			log.Printf("[Jobs] User %s already charged within 24 hours, skipping", user.ID)
			return
		}
	}

	// Calculate monthly burn (sum of phone prices with auto_extend=true)
	monthlyBurn := calculateMonthlyBurn(user.ID)
	if monthlyBurn == 0 {
		log.Printf("[Jobs] User %s has no phones with auto_extend, skipping", user.ID)
		return
	}

	// Calculate deficit
	deficit := monthlyBurn - user.Balance
	if deficit <= 0 {
		log.Printf("[Jobs] User %s has sufficient balance ($%.2f >= $%.2f), skipping",
			user.ID, float64(user.Balance)/100, float64(monthlyBurn)/100)
		// Reset retry count if user has enough balance
		if user.AutoRefillRetryCount > 0 {
			database.DB.Model(&user).Update("auto_refill_retry_count", 0)
		}
		return
	}

	// SAFETY: Check max charge limit
	if deficit > MaxAutoRefillAmount {
		log.Printf("[Jobs] ALERT: User %s deficit ($%.2f) exceeds max limit ($%.2f), skipping",
			user.ID, float64(deficit)/100, float64(MaxAutoRefillAmount)/100)
		// TODO: Send admin alert email
		return
	}

	log.Printf("[Jobs] User %s needs $%.2f (burn: $%.2f, balance: $%.2f)",
		user.ID, float64(deficit)/100, float64(monthlyBurn)/100, float64(user.Balance)/100)

	// Get default payment method
	var defaultPaymentMethod models.PaymentMethod
	if err := database.DB.Where("user_id = ? AND is_default = ?", user.ID, true).
		First(&defaultPaymentMethod).Error; err != nil {
		log.Printf("[Jobs] User %s has no default payment method, cannot auto-refill", user.ID)
		handleAutoRefillFailure(&user, "No payment method on file")
		return
	}

	// Charge the card
	success := chargeForAutoRefill(&user, &defaultPaymentMethod, deficit)
	if success {
		// Update last_auto_refill_at and reset retry count
		now := time.Now()
		database.DB.Model(&user).Updates(map[string]interface{}{
			"last_auto_refill_at":     &now,
			"auto_refill_retry_count": 0,
		})
		log.Printf("[Jobs] Successfully auto-refilled $%.2f for user %s", float64(deficit)/100, user.ID)
	} else {
		handleAutoRefillFailure(&user, "Payment failed")
	}
}

// calculateMonthlyBurn calculates the total monthly cost for a user's phones with auto_extend
func calculateMonthlyBurn(userID interface{}) int64 {
	var phones []models.Phone
	database.DB.Where("user_id = ? AND license_expires_at > ? AND auto_extend = ?",
		userID, time.Now(), true).Find(&phones)

	var totalBurn int64
	for _, phone := range phones {
		totalBurn += models.GetPlanPrice(models.PlanTier(phone.PlanTier))
	}

	return totalBurn
}

// chargeForAutoRefill charges a saved card for auto-refill and credits the balance
func chargeForAutoRefill(user *models.User, paymentMethod *models.PaymentMethod, amount int64) bool {
	stripe.Key = config.AppConfig.StripeSecretKey

	// Create PaymentIntent with idempotency key
	idempotencyKey := fmt.Sprintf("refill_%s_%s", user.ID, time.Now().Format("2006-01-02"))

	params := &stripe.PaymentIntentParams{
		Amount:        stripe.Int64(amount),
		Currency:      stripe.String("usd"),
		Customer:      stripe.String(paymentMethod.StripeCustomerID),
		PaymentMethod: stripe.String(paymentMethod.StripePaymentMethodID),
		OffSession:    stripe.Bool(true),
		Confirm:       stripe.Bool(true),
		Description:   stripe.String("DroidProxy Balance Auto-Refill"),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
			"type":    "auto_refill",
			"amount":  fmt.Sprintf("%d", amount),
		},
	}
	params.SetIdempotencyKey(idempotencyKey)

	pi, err := paymentintent.New(params)
	if err != nil {
		log.Printf("[Jobs] Error charging card for auto-refill (user %s): %v", user.ID, err)
		return false
	}

	if pi.Status != stripe.PaymentIntentStatusSucceeded {
		log.Printf("[Jobs] Payment intent not succeeded for user %s: %s", user.ID, pi.Status)
		return false
	}

	// Credit the balance
	now := time.Now()
	tx := database.DB.Begin()

	newBalance := user.Balance + amount
	if err := tx.Model(user).Updates(map[string]interface{}{
		"balance":            newBalance,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error crediting balance after auto-refill: %v", err)
		return false
	}

	// Create transaction record
	transaction := models.BalanceTransaction{
		UserID:                user.ID,
		Type:                  models.TransactionCredit,
		Amount:                amount,
		Reason:                models.ReasonAutoRefill,
		Description:           fmt.Sprintf("Anniversary auto-refill: $%.2f", float64(amount)/100),
		StripePaymentIntentID: pi.ID,
		CreatedAt:             now,
	}
	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error creating auto-refill transaction: %v", err)
		return false
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully charged $%.2f for auto-refill (user %s, new balance: $%.2f)",
		float64(amount)/100, user.ID, float64(newBalance)/100)

	return true
}

// handleAutoRefillFailure handles a failed auto-refill attempt
func handleAutoRefillFailure(user *models.User, reason string) {
	// Increment retry count
	newRetryCount := user.AutoRefillRetryCount + 1

	if newRetryCount >= MaxRetryAttempts {
		log.Printf("[Jobs] User %s has exceeded max retry attempts (%d), disabling auto-refill notifications",
			user.ID, MaxRetryAttempts)
		// After max retries, we stop trying but don't disable auto_refill
		// Licenses will expire naturally when balance runs out
	}

	// Update retry count
	database.DB.Model(user).Update("auto_refill_retry_count", newRetryCount)

	// TODO: Send email notification to user
	log.Printf("[Jobs] Auto-refill failed for user %s (attempt %d/%d): %s",
		user.ID, newRetryCount, MaxRetryAttempts, reason)
}
