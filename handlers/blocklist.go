package handlers

import (
	"net/http"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateBlocklistEntryRequest is the request body for creating a blocklist entry
type CreateBlocklistEntryRequest struct {
	Pattern  string `json:"pattern" binding:"required"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// UpdateBlocklistEntryRequest is the request body for updating a blocklist entry
type UpdateBlocklistEntryRequest struct {
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
	IsActive *bool  `json:"is_active"`
}

// ListBlocklistEntries returns all blocklist entries (admin only)
func ListBlocklistEntries(c *gin.Context) {
	var entries []models.DomainBlocklist
	if err := database.DB.Order("category, pattern").Find(&entries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch blocklist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// CreateBlocklistEntry creates a new blocklist entry (admin only)
func CreateBlocklistEntry(c *gin.Context) {
	var req CreateBlocklistEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	entry := models.DomainBlocklist{
		Pattern:  req.Pattern,
		Category: req.Category,
		Reason:   req.Reason,
		IsActive: true,
	}

	if err := database.DB.Create(&entry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create blocklist entry"})
		return
	}

	c.JSON(http.StatusCreated, entry)
}

// UpdateBlocklistEntry updates a blocklist entry (admin only)
func UpdateBlocklistEntry(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var entry models.DomainBlocklist
	if err := database.DB.First(&entry, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Entry not found"})
		return
	}

	var req UpdateBlocklistEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})
	if req.Pattern != "" {
		updates["pattern"] = req.Pattern
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	if req.Reason != "" {
		updates["reason"] = req.Reason
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	if err := database.DB.Model(&entry).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update entry"})
		return
	}

	// Reload entry
	database.DB.First(&entry, "id = ?", id)
	c.JSON(http.StatusOK, entry)
}

// DeleteBlocklistEntry deletes a blocklist entry (admin only)
func DeleteBlocklistEntry(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := database.DB.Delete(&models.DomainBlocklist{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete entry"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Entry deleted"})
}

// SeedDefaultBlocklist seeds the default blocklist patterns (admin only)
func SeedDefaultBlocklist(c *gin.Context) {
	defaultPatterns := []struct {
		Pattern  string
		Category string
		Reason   string
	}{
		// Payment Gateways
		{"*.stripe.com", "payment", "Payment gateway - prevent financial fraud"},
		{"*.paypal.com", "payment", "Payment gateway - prevent financial fraud"},
		{"*.braintreegateway.com", "payment", "Payment gateway - prevent financial fraud"},
		{"*.adyen.com", "payment", "Payment gateway - prevent financial fraud"},
		{"checkout.shopify.com", "payment", "Payment checkout - prevent financial fraud"},
		{"*.square.com", "payment", "Payment gateway - prevent financial fraud"},
		{"*.paddle.com", "payment", "Payment gateway - prevent financial fraud"},

		// KYC Providers
		{"*.jumio.com", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.onfido.com", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.veriff.com", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.sumsub.com", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.au10tix.com", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.idnow.de", "kyc", "KYC provider - prevent identity verification bypass"},
		{"*.shufti.pro", "kyc", "KYC provider - prevent identity verification bypass"},

		// Payment Apps
		{"*.venmo.com", "payment_app", "Payment app - prevent financial fraud"},
		{"*.cash.app", "payment_app", "Payment app - prevent financial fraud"},
		{"*.zelle.com", "payment_app", "Payment app - prevent financial fraud"},
		{"*.wise.com", "payment_app", "Money transfer - prevent financial fraud"},
		{"*.revolut.com", "payment_app", "Banking app - prevent financial fraud"},

		// Banking
		{"*.plaid.com", "banking", "Bank aggregator - prevent financial fraud"},
		{"*.mx.com", "banking", "Bank aggregator - prevent financial fraud"},
		{"*.yodlee.com", "banking", "Bank aggregator - prevent financial fraud"},

		// Crypto
		{"*.coinbase.com", "crypto", "Crypto exchange - prevent financial fraud"},
		{"*.binance.com", "crypto", "Crypto exchange - prevent financial fraud"},
		{"*.kraken.com", "crypto", "Crypto exchange - prevent financial fraud"},
	}

	created := 0
	skipped := 0

	for _, p := range defaultPatterns {
		entry := models.DomainBlocklist{
			Pattern:  p.Pattern,
			Category: p.Category,
			Reason:   p.Reason,
			IsActive: true,
		}

		// Use FirstOrCreate to avoid duplicates
		result := database.DB.Where("pattern = ?", p.Pattern).FirstOrCreate(&entry)
		if result.RowsAffected > 0 {
			created++
		} else {
			skipped++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Default blocklist seeded",
		"created": created,
		"skipped": skipped,
	})
}
