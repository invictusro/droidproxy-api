package middleware

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	APIKeyHeader     = "X-API-Key"
	APIKeyContextKey = "api_key"
)

// APIKeyAuth middleware validates API key from X-API-Key header
func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawKey := c.GetHeader(APIKeyHeader)
		if rawKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required. Set X-API-Key header."})
			c.Abort()
			return
		}

		// Hash the provided key
		keyHash := models.HashAPIKey(rawKey)

		// Find the API key
		var apiKey models.APIKey
		if err := database.DB.Where("key_hash = ? AND is_active = ?", keyHash, true).First(&apiKey).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		// Update last used timestamp (async to not slow down requests)
		go func() {
			now := time.Now()
			database.DB.Model(&apiKey).Update("last_used_at", now)
		}()

		// Store API key in context
		c.Set(APIKeyContextKey, &apiKey)
		c.Set("userID", apiKey.UserID)

		c.Next()
	}
}

// GetAPIKey retrieves the API key from context
func GetAPIKey(c *gin.Context) *models.APIKey {
	if apiKey, exists := c.Get(APIKeyContextKey); exists {
		return apiKey.(*models.APIKey)
	}
	return nil
}

// CanAccessPhone checks if the API key can access a specific phone
func CanAccessPhone(apiKey *models.APIKey, phoneID uuid.UUID) bool {
	if apiKey.Scope == "all" {
		return true
	}

	// Check if phone is in any of the allowed groups
	if len(apiKey.GroupIDs) == 0 {
		return false
	}

	// Check group membership
	var count int64
	database.DB.Model(&models.PhoneGroupMembership{}).
		Where("phone_id = ? AND group_id IN ?", phoneID, []string(apiKey.GroupIDs)).
		Count(&count)

	return count > 0
}
