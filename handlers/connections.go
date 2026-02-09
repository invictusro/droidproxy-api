package handlers

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/infra"
	phonecomm "github.com/droidproxy/api/internal/phone"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListCredentials returns all connection credentials for a phone
func ListCredentials(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ?", phoneID).Order("created_at DESC").Find(&credentials)

	responses := make([]models.ConnectionCredentialResponse, len(credentials))
	for i, cred := range credentials {
		responses[i] = cred.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"credentials": responses})
}

// CreateCredential creates a new connection credential for a phone
func CreateCredential(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var req models.CreateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate auth type specific fields
	if req.AuthType == models.AuthTypeIP && req.AllowedIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Allowed IP is required for IP-based auth"})
		return
	}
	if req.AuthType == models.AuthTypeUserPass && (req.Username == "" || req.Password == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required for userpass auth"})
		return
	}

	credential := models.ConnectionCredential{
		PhoneID:        phoneID,
		Name:           req.Name,
		AuthType:       req.AuthType,
		ProxyType:      req.ProxyType,
		AllowedIP:      req.AllowedIP,
		Username:       req.Username,
		BandwidthLimit: req.BandwidthLimit,
		IsActive:       true,
	}

	// Set default proxy type
	if credential.ProxyType == "" {
		credential.ProxyType = models.ProxyTypeBoth
	}

	// Store plain password (proxy credentials, not user passwords)
	if req.Password != "" {
		credential.Password = req.Password
	}

	// Parse expiration date if provided
	if req.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid expiration date format"})
			return
		}
		credential.ExpiresAt = &expiresAt
	}

	if err := database.DB.Create(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Update HTTP proxy on server if this credential supports HTTP
	if credential.ProxyType == models.ProxyTypeHTTP || credential.ProxyType == models.ProxyTypeBoth {
		// Load server relationship
		database.DB.Preload("Server").First(&phone, "id = ?", phone.ID)
		go updateHTTPProxyCredentials(&phone) // Run async to not block response
	}

	// Return response with plain password (only on creation)
	response := models.ConnectionCredentialWithPassword{
		ConnectionCredentialResponse: credential.ToResponse(),
		Password:                     req.Password, // Include plain password for user to copy
	}
	c.JSON(http.StatusCreated, gin.H{"credential": response})
}

// UpdateCredential updates a connection credential
func UpdateCredential(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}
	credID, err := uuid.Parse(c.Param("credId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var credential models.ConnectionCredential
	if err := database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).First(&credential).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	var req models.UpdateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if req.Name != nil {
		credential.Name = *req.Name
	}
	if req.ProxyType != nil {
		credential.ProxyType = *req.ProxyType
	}
	if req.AllowedIP != nil {
		credential.AllowedIP = *req.AllowedIP
	}
	if req.Username != nil {
		credential.Username = *req.Username
	}
	if req.Password != nil && *req.Password != "" {
		credential.Password = *req.Password
	}
	if req.BandwidthLimit != nil {
		credential.BandwidthLimit = *req.BandwidthLimit
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			credential.ExpiresAt = nil
		} else {
			expiresAt, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid expiration date format"})
				return
			}
			credential.ExpiresAt = &expiresAt
		}
	}
	if req.IsActive != nil {
		credential.IsActive = *req.IsActive
	}

	if err := database.DB.Save(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update credential"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Update HTTP proxy on server
	database.DB.Preload("Server").First(&phone, "id = ?", phone.ID)
	go updateHTTPProxyCredentials(&phone)

	c.JSON(http.StatusOK, gin.H{"credential": credential.ToResponse()})
}

// DeleteCredential deletes a connection credential
func DeleteCredential(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}
	credID, err := uuid.Parse(c.Param("credId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	result := database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).Delete(&models.ConnectionCredential{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Update HTTP proxy on server
	database.DB.Preload("Server").First(&phone, "id = ?", phone.ID)
	go updateHTTPProxyCredentials(&phone)

	c.JSON(http.StatusOK, gin.H{"message": "Credential deleted"})
}

// GetRotationToken returns the rotation token for a phone (creates if not exists)
func GetRotationToken(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var token models.RotationToken
	if err := database.DB.Where("phone_id = ?", phoneID).First(&token).Error; err != nil {
		// Create new token
		token = models.RotationToken{
			PhoneID:  phoneID,
			IsActive: true,
		}
		if err := database.DB.Create(&token).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rotation token"})
			return
		}
		// Show token only on creation
		c.JSON(http.StatusCreated, gin.H{"rotation_token": token.ToResponse(config.AppConfig.APIBaseURL, true)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"rotation_token": token.ToResponse(config.AppConfig.APIBaseURL, false)})
}

// RegenerateRotationToken creates a new rotation token
func RegenerateRotationToken(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Delete existing token
	database.DB.Where("phone_id = ?", phoneID).Delete(&models.RotationToken{})

	// Create new token
	token := models.RotationToken{
		PhoneID:  phoneID,
		IsActive: true,
	}
	if err := database.DB.Create(&token).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rotation token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"rotation_token": token.ToResponse(config.AppConfig.APIBaseURL, true)})
}

// RotateIPByToken handles external API rotation requests
func RotateIPByToken(c *gin.Context) {
	tokenStr := c.Param("token")
	if tokenStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	var token models.RotationToken
	if err := database.DB.Where("token = ? AND is_active = ?", tokenStr, true).First(&token).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive token"})
		return
	}

	// Update last used
	now := time.Now()
	token.LastUsed = &now
	database.DB.Save(&token)

	// Send rotate command to phone
	if err := phonecomm.SendRotateIP(token.PhoneID.String()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send rotate command"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rotation command sent", "phone_id": token.PhoneID})
}

// PhoneCredential is the simplified credential sent to phones (SOCKS5 only)
type PhoneCredential struct {
	ID           string `json:"id"`
	AuthType     string `json:"auth_type"`
	ProxyType    string `json:"proxy_type"`
	AllowedIP    string `json:"allowed_ip,omitempty"`
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password,omitempty"` // bcrypt hash
}

// Helper to notify phone of credential updates with full data
// Only sends credentials that allow SOCKS5 connections (socks5 or both)
func notifyPhoneCredentialsUpdated(phoneID string) {
	// Fetch current credentials for this phone
	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ? AND is_active = ?", phoneID, true).Find(&credentials)

	// Convert to phone format - only SOCKS5-compatible credentials
	phoneCredentials := make([]PhoneCredential, 0, len(credentials))
	for _, cred := range credentials {
		// Skip expired credentials
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
			continue
		}

		// Only send credentials that allow SOCKS5 (socks5 or both)
		if cred.ProxyType != models.ProxyTypeSOCKS5 && cred.ProxyType != models.ProxyTypeBoth {
			continue
		}

		phoneCredentials = append(phoneCredentials, PhoneCredential{
			ID:           cred.ID.String(),
			AuthType:     string(cred.AuthType),
			ProxyType:    string(cred.ProxyType),
			AllowedIP:    cred.AllowedIP,
			Username:     cred.Username,
			PasswordHash: cred.Password,
		})
	}

	phonecomm.SendCredentialsUpdate(phoneID, phoneCredentials)
}

// updateHTTPProxyCredentials updates the HTTP proxy on the server with HTTP-compatible credentials
func updateHTTPProxyCredentials(phone *models.Phone) error {
	if phone.ServerID == nil || phone.HTTPPort == 0 {
		return nil // No server or HTTP port configured
	}

	// Get server
	var server models.Server
	if err := database.DB.First(&server, "id = ?", phone.ServerID).Error; err != nil {
		return err
	}

	if server.SSHPassword == "" {
		return nil // No SSH credentials
	}

	// Get HTTP-compatible credentials (http or both)
	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ? AND is_active = ? AND (proxy_type = ? OR proxy_type = ?)",
		phone.ID, true, models.ProxyTypeHTTP, models.ProxyTypeBoth).Find(&credentials)

	// Filter out expired and build credential list
	httpCreds := make([]infra.GostCredential, 0, len(credentials))
	for _, cred := range credentials {
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
			continue
		}
		// Only userpass auth works for HTTP proxy
		if cred.AuthType == models.AuthTypeUserPass && cred.Username != "" && cred.Password != "" {
			httpCreds = append(httpCreds, infra.GostCredential{
				Username: cred.Username,
				Password: cred.Password,
			})
		}
	}

	// Connect to server and update HTTP proxy
	client := infra.NewSSHClient(server.IP, server.SSHPort, server.SSHUser, server.SSHPassword)
	if err := client.Connect(); err != nil {
		return err
	}
	defer client.Close()

	proxyManager := infra.NewGostManager(client)

	if len(httpCreds) == 0 {
		// No HTTP credentials, stop HTTP proxy if running
		proxyManager.StopProxy(phone.ID.String())
	} else {
		// Start/update HTTP proxy with credentials
		_, err := proxyManager.StartProxyMultiUser(phone.ID.String(), phone.ProxyPort, phone.HTTPPort, httpCreds)
		if err != nil {
			return err
		}
	}

	return nil
}
