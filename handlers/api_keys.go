package handlers

import (
	"net/http"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// CreateAPIKey creates a new API key for the user
func CreateAPIKey(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req struct {
		Name     string   `json:"name" binding:"required"`
		Scope    string   `json:"scope"` // 'all' or 'groups'
		GroupIDs []string `json:"group_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}

	// Default scope to 'all'
	if req.Scope == "" {
		req.Scope = "all"
	}
	if req.Scope != "all" && req.Scope != "groups" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scope must be 'all' or 'groups'"})
		return
	}

	// Generate the key
	rawKey, keyHash, keyPrefix := models.GenerateAPIKey()

	apiKey := models.APIKey{
		UserID:    userID,
		Name:      req.Name,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scope:     req.Scope,
		GroupIDs:  pq.StringArray(req.GroupIDs),
		IsActive:  true,
	}

	if err := database.DB.Create(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Return the response with the raw key (only shown once!)
	response := models.APIKeyCreateResponse{
		APIKeyResponse: apiKey.ToResponse(),
		Key:            rawKey,
	}

	c.JSON(http.StatusCreated, response)
}

// ListAPIKeys returns all API keys for the user
func ListAPIKeys(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var keys []models.APIKey
	if err := database.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&keys).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	responses := make([]models.APIKeyResponse, len(keys))
	for i, key := range keys {
		responses[i] = key.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"api_keys": responses})
}

// DeleteAPIKey deletes an API key
func DeleteAPIKey(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	var apiKey models.APIKey
	if err := database.DB.Where("id = ? AND user_id = ?", keyID, userID).First(&apiKey).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}

	if err := database.DB.Delete(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted"})
}

// UpdateAPIKey updates an API key (name, scope, groups, active status)
func UpdateAPIKey(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	var apiKey models.APIKey
	if err := database.DB.Where("id = ? AND user_id = ?", keyID, userID).First(&apiKey).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}

	var req struct {
		Name     *string  `json:"name"`
		Scope    *string  `json:"scope"`
		GroupIDs []string `json:"group_ids"`
		IsActive *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.Name != nil {
		apiKey.Name = *req.Name
	}
	if req.Scope != nil {
		if *req.Scope != "all" && *req.Scope != "groups" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Scope must be 'all' or 'groups'"})
			return
		}
		apiKey.Scope = *req.Scope
	}
	if req.GroupIDs != nil {
		apiKey.GroupIDs = pq.StringArray(req.GroupIDs)
	}
	if req.IsActive != nil {
		apiKey.IsActive = *req.IsActive
	}

	if err := database.DB.Save(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_key": apiKey.ToResponse()})
}
