package handlers

import (
	"log"
	"math"
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/infra"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// roundToWholeDollars rounds cents to whole dollar amounts
// Rounds up if remainder >= 25 cents, otherwise rounds down
// e.g., 124 cents → 100 ($1), 125 cents → 200 ($2), 225 cents → 300 ($3)
func roundToWholeDollars(cents int64) int64 {
	if cents <= 0 {
		return 0
	}
	dollars := cents / 100
	remainder := cents % 100
	if remainder >= 25 {
		dollars++
	}
	// Ensure minimum of $1 if there's any charge
	if dollars == 0 && cents > 0 {
		dollars = 1
	}
	return dollars * 100
}

// Helper to get plans list
func getPlansResponse() []gin.H {
	return []gin.H{
		{
			"tier":            "lite",
			"name":            "Lite",
			"price_cents":     models.PriceLite,
			"price_formatted": "$5.00/month",
			"limits":          models.GetPlanLimits(models.PlanLite),
		},
		{
			"tier":            "turbo",
			"name":            "Turbo",
			"price_cents":     models.PriceTurbo,
			"price_formatted": "$7.00/month",
			"limits":          models.GetPlanLimits(models.PlanTurbo),
		},
		{
			"tier":            "nitro",
			"name":            "Nitro",
			"price_cents":     models.PriceNitro,
			"price_formatted": "$9.00/month",
			"limits":          models.GetPlanLimits(models.PlanNitro),
		},
	}
}

// GetPhoneLicense returns the current license for a phone
func GetPhoneLicense(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Find most recent license (active or expired status)
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ?", phoneID).
		Order("expires_at DESC").
		First(&license).Error; err == nil {
		// Check if license is actually expired (even if status hasn't been updated by job)
		now := time.Now()
		isExpired := now.After(license.ExpiresAt) || license.Status == models.LicenseExpired

		if isExpired {
			// Force status to expired for response (job may not have run yet)
			license.Status = models.LicenseExpired
			c.JSON(http.StatusOK, gin.H{
				"has_license": false,
				"license":     license.ToResponse(),
				"plans":       getPlansResponse(),
			})
			return
		}

		// Active license
		c.JSON(http.StatusOK, gin.H{
			"has_license": true,
			"license":     license.ToResponse(),
			"plans":       getPlansResponse(),
		})
		return
	}

	// No license at all
	c.JSON(http.StatusOK, gin.H{
		"has_license": false,
		"license":     nil,
		"plans":       getPlansResponse(),
	})
}

// PurchaseLicense purchases a new license for a phone
func PurchaseLicense(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var req models.PurchaseLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Check for existing active license
	var existingLicense models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ? AND expires_at > ?",
		phoneID, models.LicenseActive, time.Now()).First(&existingLicense).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already has an active license"})
		return
	}

	// Get plan tier and price
	planTier := models.PlanTier(req.PlanTier)
	price := models.GetPlanPrice(planTier)
	limits := models.GetPlanLimits(planTier)

	if price == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan tier"})
		return
	}

	// Reload user to get current balance
	if err := database.DB.First(&user, "id = ?", user.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	// Check balance
	if user.Balance < price {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "Insufficient balance",
			"required":         price,
			"current_balance":  user.Balance,
			"shortfall":        price - user.Balance,
		})
		return
	}

	// Start transaction
	tx := database.DB.Begin()

	now := time.Now()
	expiresAt := now.AddDate(0, 1, 0) // 1 month from now

	// Deduct balance
	newBalance := user.Balance - price
	if err := tx.Model(&user).Updates(map[string]interface{}{
		"balance":            newBalance,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deduct balance"})
		return
	}

	// Create balance transaction
	balanceTransaction := models.BalanceTransaction{
		UserID:      user.ID,
		Type:        models.TransactionDebit,
		Amount:      price,
		Reason:      models.ReasonLicensePurchase,
		ReferenceID: &phoneID,
		Description: "License purchase: " + string(planTier) + " plan",
		CreatedAt:   now,
	}
	if err := tx.Create(&balanceTransaction).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record transaction"})
		return
	}

	// Create license
	license := models.PhoneLicense{
		PhoneID:    phoneID,
		UserID:     user.ID,
		PlanTier:   planTier,
		PricePaid:  price,
		StartedAt:  now,
		ExpiresAt:  expiresAt,
		AutoExtend: req.AutoExtend,
		Status:     models.LicenseActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := tx.Create(&license).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create license"})
		return
	}

	// Update phone with plan info
	if err := tx.Model(&phone).Updates(map[string]interface{}{
		"plan_tier":           string(planTier),
		"license_expires_at":  expiresAt,
		"license_auto_extend": req.AutoExtend,
		"speed_limit_mbps":    limits.SpeedLimitMbps,
		"max_connections":     limits.MaxConnections,
		"log_retention_weeks": limits.LogWeeks,
	}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update phone"})
		return
	}

	tx.Commit()

	// Trigger hub reconciliation to apply new speed limits
	// This is done async to not block the response
	go func() {
		// Reload phone with hub server info
		var phoneWithHub models.Phone
		if err := database.DB.Preload("HubServer").First(&phoneWithHub, "id = ?", phoneID).Error; err != nil {
			log.Printf("Warning: failed to load phone for reconciliation: %v", err)
			return
		}
		if phoneWithHub.HubServer != nil && phoneWithHub.HubServer.HubAPIKey != "" {
			if err := infra.TriggerReconcileV2(
				phoneWithHub.HubServer.IP,
				phoneWithHub.HubServer.HubAPIPort,
				phoneWithHub.HubServer.HubAPIKey,
			); err != nil {
				log.Printf("Warning: failed to trigger hub reconciliation: %v", err)
			} else {
				log.Printf("Triggered hub reconciliation for %s after license purchase", phoneWithHub.HubServer.Name)
			}
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"message":     "License purchased successfully",
		"license":     license.ToResponse(),
		"new_balance": newBalance,
	})
}

// UpdatePhoneLicense updates license settings (auto-extend)
func UpdatePhoneLicense(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var req models.UpdateLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Find active license
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseActive).
		First(&license).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active license found"})
		return
	}

	// Update license
	updates := map[string]interface{}{
		"updated_at": time.Now(),
	}

	if req.AutoExtend != nil {
		updates["auto_extend"] = *req.AutoExtend
	}

	if err := database.DB.Model(&license).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update license"})
		return
	}

	// Also update phone
	if req.AutoExtend != nil {
		database.DB.Model(&phone).Update("license_auto_extend", *req.AutoExtend)
	}

	// Reload license
	database.DB.First(&license, "id = ?", license.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "License updated",
		"license": license.ToResponse(),
	})
}

// CancelLicense cancels auto-renewal for an active license (license remains active until expiry)
func CancelLicense(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Find active license
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseActive).
		First(&license).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active license found"})
		return
	}

	// Disable auto-extend on both license and phone (license remains active until expiry)
	now := time.Now()
	if err := database.DB.Model(&license).Updates(map[string]interface{}{
		"auto_extend": false,
		"updated_at":  now,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel license"})
		return
	}

	database.DB.Model(&phone).Update("license_auto_extend", false)

	c.JSON(http.StatusOK, gin.H{
		"message":    "License cancelled - will not renew after expiry",
		"expires_at": license.ExpiresAt,
	})
}

// GetAvailablePlans returns all available plan tiers
func GetAvailablePlans(c *gin.Context) {
	plans := []gin.H{
		{
			"tier":            "lite",
			"name":            "Lite",
			"price_cents":     models.PriceLite,
			"price_formatted": "$5.00/month",
			"limits":          models.GetPlanLimits(models.PlanLite),
		},
		{
			"tier":            "turbo",
			"name":            "Turbo",
			"price_cents":     models.PriceTurbo,
			"price_formatted": "$7.00/month",
			"limits":          models.GetPlanLimits(models.PlanTurbo),
		},
		{
			"tier":            "nitro",
			"name":            "Nitro",
			"price_cents":     models.PriceNitro,
			"price_formatted": "$9.00/month",
			"limits":          models.GetPlanLimits(models.PlanNitro),
		},
	}

	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

// PreviewPlanChange returns a preview of what upgrading/downgrading would cost
// GET /phones/:id/license/change-preview?plan_tier=nitro
func PreviewPlanChange(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	newPlanTier := models.PlanTier(c.Query("plan_tier"))
	if newPlanTier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan_tier query parameter is required"})
		return
	}

	newPrice := models.GetPlanPrice(newPlanTier)
	if newPrice == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan tier"})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Find active license
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseActive).
		First(&license).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active license found"})
		return
	}

	// Can't change to same plan
	if license.PlanTier == newPlanTier {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Already on this plan"})
		return
	}

	currentPrice := models.GetPlanPrice(license.PlanTier)
	now := time.Now()

	// Calculate days based on actual license period
	totalDays := license.ExpiresAt.Sub(license.StartedAt).Hours() / 24
	daysRemaining := license.ExpiresAt.Sub(now).Hours() / 24

	if daysRemaining < 0 {
		daysRemaining = 0
	}

	// Determine if upgrade or downgrade
	isUpgrade := newPrice > currentPrice

	if isUpgrade {
		// Calculate prorated charge
		priceDifference := newPrice - currentPrice
		fractionRemaining := daysRemaining / totalDays
		rawChargeAmount := int64(math.Round(float64(priceDifference) * fractionRemaining))
		// Round to whole dollars (up if >= 50 cents, down otherwise)
		chargeAmount := roundToWholeDollars(rawChargeAmount)

		// Reload user for current balance
		if err := database.DB.First(&user, "id = ?", user.ID).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"change_type":      "upgrade",
			"current_plan":     string(license.PlanTier),
			"new_plan":         string(newPlanTier),
			"current_price":    currentPrice,
			"new_price":        newPrice,
			"total_days":       int(totalDays),
			"days_remaining":   int(daysRemaining),
			"price_difference": priceDifference,
			"charge_amount":    chargeAmount,
			"current_balance":  user.Balance,
			"balance_after":    user.Balance - chargeAmount,
			"can_afford":       user.Balance >= chargeAmount,
			"expires_at":       license.ExpiresAt,
			"new_limits":       models.GetPlanLimits(newPlanTier),
		})
	} else {
		// Downgrade - no refund
		c.JSON(http.StatusOK, gin.H{
			"change_type":           "downgrade",
			"current_plan":          string(license.PlanTier),
			"new_plan":              string(newPlanTier),
			"current_price":         currentPrice,
			"new_price":             newPrice,
			"days_remaining":        int(daysRemaining),
			"refund_amount":         0,
			"warning":               "Downgrading does not refund any balance. Your new plan limits will take effect immediately.",
			"requires_confirmation": true,
			"expires_at":            license.ExpiresAt,
			"new_limits":            models.GetPlanLimits(newPlanTier),
		})
	}
}

// ChangePlan executes an upgrade or downgrade
// PUT /phones/:id/license/change
func ChangePlan(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var req struct {
		PlanTier        string `json:"plan_tier" binding:"required"`
		ConfirmNoRefund bool   `json:"confirm_no_refund"` // Required for downgrades
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	newPlanTier := models.PlanTier(req.PlanTier)
	newPrice := models.GetPlanPrice(newPlanTier)
	if newPrice == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan tier"})
		return
	}

	// Verify phone ownership
	var phone models.Phone
	if err := database.DB.First(&phone, "id = ? AND user_id = ?", phoneID, user.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Find active license
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseActive).
		First(&license).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active license found"})
		return
	}

	// Can't change to same plan
	if license.PlanTier == newPlanTier {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Already on this plan"})
		return
	}

	currentPrice := models.GetPlanPrice(license.PlanTier)
	now := time.Now()
	newLimits := models.GetPlanLimits(newPlanTier)

	// Calculate days based on actual license period
	totalDays := license.ExpiresAt.Sub(license.StartedAt).Hours() / 24
	daysRemaining := license.ExpiresAt.Sub(now).Hours() / 24

	if daysRemaining < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "License has expired"})
		return
	}

	isUpgrade := newPrice > currentPrice

	tx := database.DB.Begin()

	if isUpgrade {
		// Calculate prorated charge
		priceDifference := newPrice - currentPrice
		fractionRemaining := daysRemaining / totalDays
		rawChargeAmount := int64(math.Round(float64(priceDifference) * fractionRemaining))
		// Round to whole dollars (up if >= 50 cents, down otherwise)
		chargeAmount := roundToWholeDollars(rawChargeAmount)

		// Reload user for current balance
		if err := tx.First(&user, "id = ?", user.ID).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			return
		}

		// Check balance - MUST have enough to cover the upgrade
		if user.Balance < chargeAmount {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{
				"error":           "Insufficient balance",
				"required":        chargeAmount,
				"current_balance": user.Balance,
				"shortfall":       chargeAmount - user.Balance,
			})
			return
		}

		// Deduct balance
		newBalance := user.Balance - chargeAmount
		if err := tx.Model(&user).Updates(map[string]interface{}{
			"balance":            newBalance,
			"balance_updated_at": now,
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deduct balance"})
			return
		}

		// Create balance transaction
		balanceTransaction := models.BalanceTransaction{
			UserID:      user.ID,
			Type:        models.TransactionDebit,
			Amount:      chargeAmount,
			Reason:      models.ReasonLicenseUpgrade,
			ReferenceID: &phoneID,
			Description: "Plan upgrade: " + string(license.PlanTier) + " → " + string(newPlanTier),
			CreatedAt:   now,
		}
		if err := tx.Create(&balanceTransaction).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record transaction"})
			return
		}

		// Update license
		if err := tx.Model(&license).Updates(map[string]interface{}{
			"plan_tier":  string(newPlanTier),
			"updated_at": now,
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update license"})
			return
		}

		// Update phone with new limits
		if err := tx.Model(&phone).Updates(map[string]interface{}{
			"plan_tier":           string(newPlanTier),
			"speed_limit_mbps":    newLimits.SpeedLimitMbps,
			"max_connections":     newLimits.MaxConnections,
			"log_retention_weeks": newLimits.LogWeeks,
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update phone"})
			return
		}

		tx.Commit()

		// Trigger hub reconciliation
		go triggerHubReconciliation(phoneID)

		c.JSON(http.StatusOK, gin.H{
			"message":       "Plan upgraded successfully",
			"change_type":   "upgrade",
			"old_plan":      string(license.PlanTier),
			"new_plan":      string(newPlanTier),
			"charged":       chargeAmount,
			"new_balance":   newBalance,
			"expires_at":    license.ExpiresAt,
			"new_limits":    newLimits,
		})

	} else {
		// Downgrade - require confirmation
		if !req.ConfirmNoRefund {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{
				"error":                 "Downgrade requires confirmation",
				"message":               "Downgrading does not refund any balance. Set confirm_no_refund to true to proceed.",
				"requires_confirmation": true,
			})
			return
		}

		// Update license (keep same expiration, just change tier)
		if err := tx.Model(&license).Updates(map[string]interface{}{
			"plan_tier":  string(newPlanTier),
			"updated_at": now,
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update license"})
			return
		}

		// Update phone with new limits
		if err := tx.Model(&phone).Updates(map[string]interface{}{
			"plan_tier":           string(newPlanTier),
			"speed_limit_mbps":    newLimits.SpeedLimitMbps,
			"max_connections":     newLimits.MaxConnections,
			"log_retention_weeks": newLimits.LogWeeks,
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update phone"})
			return
		}

		tx.Commit()

		// Trigger hub reconciliation
		go triggerHubReconciliation(phoneID)

		c.JSON(http.StatusOK, gin.H{
			"message":     "Plan downgraded successfully",
			"change_type": "downgrade",
			"old_plan":    string(license.PlanTier),
			"new_plan":    string(newPlanTier),
			"refunded":    0,
			"expires_at":  license.ExpiresAt,
			"new_limits":  newLimits,
		})
	}
}

// triggerHubReconciliation triggers a hub to resync (used after plan changes)
func triggerHubReconciliation(phoneID uuid.UUID) {
	var phone models.Phone
	if err := database.DB.Preload("HubServer").First(&phone, "id = ?", phoneID).Error; err != nil {
		log.Printf("Warning: failed to load phone for reconciliation: %v", err)
		return
	}
	if phone.HubServer != nil && phone.HubServer.HubAPIKey != "" {
		if err := infra.TriggerReconcileV2(
			phone.HubServer.IP,
			phone.HubServer.HubAPIPort,
			phone.HubServer.HubAPIKey,
		); err != nil {
			log.Printf("Warning: failed to trigger hub reconciliation: %v", err)
		} else {
			log.Printf("Triggered hub reconciliation for %s after plan change", phone.HubServer.Name)
		}
	}
}
