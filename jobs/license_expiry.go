package jobs

import (
	"fmt"
	"log"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/infra"
	"github.com/droidproxy/api/models"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/paymentintent"
)

// StartLicenseExpiryJob runs the license expiry check periodically
func StartLicenseExpiryJob() {
	// Run immediately on startup
	go checkExpiredLicenses()

	// Then run every hour
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			checkExpiredLicenses()
		}
	}()

	log.Println("[Jobs] License expiry job started (runs every hour)")
}

// checkExpiredLicenses finds expired licenses and handles auto-renewal
func checkExpiredLicenses() {
	log.Println("[Jobs] Checking for license expiry and auto-renewals...")

	now := time.Now()

	// STEP 1: Check licenses expiring within 24 hours with auto_extend enabled
	// Try to renew these before they expire
	checkAutoRenewals(now)

	// STEP 2: Find all active licenses that have already expired
	var expiredLicenses []models.PhoneLicense
	if err := database.DB.Where("status = ? AND expires_at < ?", models.LicenseActive, now).
		Find(&expiredLicenses).Error; err != nil {
		log.Printf("[Jobs] Error finding expired licenses: %v", err)
		return
	}

	if len(expiredLicenses) == 0 {
		log.Println("[Jobs] No expired licenses found")
	} else {
		log.Printf("[Jobs] Found %d expired licenses to process", len(expiredLicenses))
		for _, license := range expiredLicenses {
			processExpiredLicense(license)
		}
	}

	// STEP 3: Clean up phones that expired more than 14 days ago
	cleanupOldExpiredPhones()
}

// checkAutoRenewals finds licenses expiring soon with auto_extend and attempts renewal
func checkAutoRenewals(now time.Time) {
	// Find licenses expiring within 24 hours that have auto_extend enabled
	expiryWindow := now.Add(24 * time.Hour)

	var renewableLicenses []models.PhoneLicense
	if err := database.DB.Where("status = ? AND auto_extend = ? AND expires_at > ? AND expires_at < ?",
		models.LicenseActive, true, now, expiryWindow).
		Preload("Phone").
		Find(&renewableLicenses).Error; err != nil {
		log.Printf("[Jobs] Error finding renewable licenses: %v", err)
		return
	}

	if len(renewableLicenses) == 0 {
		log.Println("[Jobs] No licenses due for auto-renewal")
		return
	}

	log.Printf("[Jobs] Found %d licenses due for auto-renewal", len(renewableLicenses))

	for _, license := range renewableLicenses {
		attemptAutoRenewal(license)
	}
}

// attemptAutoRenewal tries to renew a license using balance or saved card
func attemptAutoRenewal(license models.PhoneLicense) {
	log.Printf("[Jobs] Attempting auto-renewal for license %s (phone %s)", license.ID, license.PhoneID)

	// Get plan price
	priceToCharge := models.GetPlanPrice(license.PlanTier)
	if priceToCharge == 0 {
		log.Printf("[Jobs] Unknown plan tier: %s", license.PlanTier)
		return
	}

	// Get user
	var user models.User
	if err := database.DB.First(&user, "id = ?", license.UserID).Error; err != nil {
		log.Printf("[Jobs] Error loading user for auto-renewal: %v", err)
		return
	}

	// Check if user has sufficient balance
	if user.Balance >= priceToCharge {
		// Direct balance deduction
		if renewWithBalance(&user, &license, priceToCharge) {
			return
		}
	}

	// Insufficient balance - try charging saved card
	var defaultPaymentMethod models.PaymentMethod
	if err := database.DB.Where("user_id = ? AND is_default = ?", user.ID, true).
		First(&defaultPaymentMethod).Error; err != nil {
		log.Printf("[Jobs] No default payment method for user %s, cannot auto-renew", user.ID)
		return
	}

	// Calculate shortfall
	shortfall := priceToCharge - user.Balance
	if shortfall < 500 { // Min charge $5
		shortfall = 500
	}

	// Charge the card
	if chargeCardForRenewal(&user, &defaultPaymentMethod, shortfall) {
		// Now try to renew again with the new balance
		// Reload user to get updated balance
		database.DB.First(&user, "id = ?", user.ID)
		if user.Balance >= priceToCharge {
			renewWithBalance(&user, &license, priceToCharge)
		}
	}
}

// renewWithBalance deducts from balance and extends the license
func renewWithBalance(user *models.User, license *models.PhoneLicense, amount int64) bool {
	tx := database.DB.Begin()

	now := time.Now()
	newExpiresAt := license.ExpiresAt.AddDate(0, 1, 0) // Add 1 month

	// Deduct balance
	if err := tx.Model(user).Updates(map[string]interface{}{
		"balance":            user.Balance - amount,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error deducting balance: %v", err)
		return false
	}

	// Extend license
	if err := tx.Model(license).Updates(map[string]interface{}{
		"expires_at": newExpiresAt,
		"price_paid": amount,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error extending license: %v", err)
		return false
	}

	// Update phone license expiry
	if err := tx.Model(&models.Phone{}).Where("id = ?", license.PhoneID).
		Update("license_expires_at", newExpiresAt).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error updating phone: %v", err)
		return false
	}

	// Create transaction record
	transaction := models.BalanceTransaction{
		UserID:      user.ID,
		Type:        models.TransactionDebit,
		Amount:      amount,
		Reason:      models.ReasonLicenseRenewal,
		ReferenceID: &license.PhoneID,
		Description: fmt.Sprintf("Auto-renewal: %s plan for 1 month", license.PlanTier),
		CreatedAt:   now,
	}
	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error creating transaction: %v", err)
		return false
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully auto-renewed license for phone %s until %s",
		license.PhoneID, newExpiresAt.Format("2006-01-02"))
	return true
}

// chargeCardForRenewal charges a saved card and credits the balance
func chargeCardForRenewal(user *models.User, paymentMethod *models.PaymentMethod, amount int64) bool {
	stripe.Key = config.AppConfig.StripeSecretKey

	// Create PaymentIntent with saved payment method
	params := &stripe.PaymentIntentParams{
		Amount:        stripe.Int64(amount),
		Currency:      stripe.String("usd"),
		Customer:      stripe.String(paymentMethod.StripeCustomerID),
		PaymentMethod: stripe.String(paymentMethod.StripePaymentMethodID),
		OffSession:    stripe.Bool(true),
		Confirm:       stripe.Bool(true),
		Description:   stripe.String("DroidProxy Auto-Renewal"),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
			"type":    "auto_charge",
		},
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		log.Printf("[Jobs] Error charging card for auto-renewal: %v", err)
		return false
	}

	if pi.Status != stripe.PaymentIntentStatusSucceeded {
		log.Printf("[Jobs] Payment intent not succeeded: %s", pi.Status)
		return false
	}

	// Credit the balance
	now := time.Now()
	tx := database.DB.Begin()

	if err := tx.Model(user).Updates(map[string]interface{}{
		"balance":            user.Balance + amount,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error crediting balance after charge: %v", err)
		return false
	}

	transaction := models.BalanceTransaction{
		UserID:                user.ID,
		Type:                  models.TransactionCredit,
		Amount:                amount,
		Reason:                models.ReasonAutoCharge,
		Description:           fmt.Sprintf("Auto-charge for license renewal: $%.2f", float64(amount)/100),
		StripePaymentIntentID: pi.ID,
		CreatedAt:             now,
	}
	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error creating auto-charge transaction: %v", err)
		return false
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully charged $%.2f for auto-renewal (user %s)", float64(amount)/100, user.ID)
	return true
}

// processExpiredLicense marks a license as expired and DELETES all credentials
// This ensures proxy stops working immediately and user starts fresh when renewing
func processExpiredLicense(license models.PhoneLicense) {
	log.Printf("[Jobs] Processing expired license %s for phone %s", license.ID, license.PhoneID)

	tx := database.DB.Begin()

	// Mark license as expired
	if err := tx.Model(&license).Update("status", models.LicenseExpired).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error marking license as expired: %v", err)
		return
	}

	// Update phone - keep plan_tier/license_expires_at for UI display, clear limits
	// The UI checks license_expires_at to determine if license is expired
	if err := tx.Model(&models.Phone{}).Where("id = ?", license.PhoneID).Updates(map[string]interface{}{
		"speed_limit_mbps": 0,
		"max_connections":  0,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error updating phone: %v", err)
		return
	}

	// DELETE all credentials for this phone (not just disable)
	// This ensures proxy completely stops and user must create new credentials when renewing
	var deletedCount int64
	if result := tx.Where("phone_id = ?", license.PhoneID).Delete(&models.ConnectionCredential{}); result.Error != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error deleting credentials: %v", result.Error)
		return
	} else {
		deletedCount = result.RowsAffected
	}

	// Delete rotation token
	if err := tx.Where("phone_id = ?", license.PhoneID).Delete(&models.RotationToken{}).Error; err != nil {
		// Not critical, just log
		log.Printf("[Jobs] Error deleting rotation token: %v", err)
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully expired license for phone %s (deleted %d credentials)", license.PhoneID, deletedCount)

	// Trigger hub reconciliation to remove proxies immediately
	go triggerHubReconciliationForPhone(license.PhoneID)
}

// triggerHubReconciliationForPhone triggers a hub to resync after license expiry
func triggerHubReconciliationForPhone(phoneID uuid.UUID) {
	var phone models.Phone
	if err := database.DB.Preload("HubServer").First(&phone, "id = ?", phoneID).Error; err != nil {
		log.Printf("[Jobs] Warning: failed to load phone for reconciliation: %v", err)
		return
	}
	if phone.HubServer != nil && phone.HubServer.HubAPIKey != "" {
		if err := infra.TriggerReconcileV2(
			phone.HubServer.IP,
			phone.HubServer.HubAPIPort,
			phone.HubServer.HubAPIKey,
		); err != nil {
			log.Printf("[Jobs] Warning: failed to trigger hub reconciliation: %v", err)
		} else {
			log.Printf("[Jobs] Triggered hub reconciliation for %s after license expiry", phone.HubServer.Name)
		}
	}
}

// cleanupOldExpiredPhones deletes phones that have been expired for more than 14 days
func cleanupOldExpiredPhones() {
	cutoffDate := time.Now().AddDate(0, 0, -14) // 14 days ago

	// Find licenses expired more than 14 days ago
	var oldLicenses []models.PhoneLicense
	if err := database.DB.Where("status = ? AND expires_at < ?", models.LicenseExpired, cutoffDate).
		Find(&oldLicenses).Error; err != nil {
		log.Printf("[Jobs] Error finding old expired licenses: %v", err)
		return
	}

	if len(oldLicenses) == 0 {
		return
	}

	log.Printf("[Jobs] Found %d phones to clean up (expired > 14 days)", len(oldLicenses))

	for _, license := range oldLicenses {
		// Delete all related data
		tx := database.DB.Begin()

		phoneID := license.PhoneID

		// Delete credentials
		tx.Where("phone_id = ?", phoneID).Delete(&models.ConnectionCredential{})

		// Delete rotation token
		tx.Where("phone_id = ?", phoneID).Delete(&models.RotationToken{})

		// Delete licenses
		tx.Where("phone_id = ?", phoneID).Delete(&models.PhoneLicense{})

		// Delete phone
		tx.Where("id = ?", phoneID).Delete(&models.Phone{})

		if err := tx.Commit().Error; err != nil {
			log.Printf("[Jobs] Error cleaning up phone %s: %v", phoneID, err)
		} else {
			log.Printf("[Jobs] Cleaned up expired phone %s", phoneID)
		}
	}
}
