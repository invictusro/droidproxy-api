package handlers

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

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

	// Find active license first
	var license models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseActive).
		Order("expires_at DESC").
		First(&license).Error; err == nil {
		// Active license found
		c.JSON(http.StatusOK, gin.H{
			"has_license": true,
			"license":     license.ToResponse(),
			"plans":       getPlansResponse(),
		})
		return
	}

	// Check for expired license (for "Extend" functionality)
	var expiredLicense models.PhoneLicense
	if err := database.DB.Where("phone_id = ? AND status = ?", phoneID, models.LicenseExpired).
		Order("expires_at DESC").
		First(&expiredLicense).Error; err == nil {
		// Expired license found - allow extending
		c.JSON(http.StatusOK, gin.H{
			"has_license": false,
			"license":     expiredLicense.ToResponse(),
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
