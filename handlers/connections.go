package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/dns"
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

	// Verify phone belongs to user (preload server for port allocation)
	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Check max credentials limit (10 per phone)
	var credentialCount int64
	database.DB.Model(&models.ConnectionCredential{}).Where("phone_id = ?", phoneID).Count(&credentialCount)
	if credentialCount >= 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 10 credentials per phone allowed"})
		return
	}

	// Assign ports if not already assigned (first credential creation)
	if phone.ProxyPort == 0 && phone.HubServer != nil {
		proxyPort, err := getNextAvailablePort(phone.HubServer)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No ports available on this server"})
			return
		}
		phone.ProxyPort = proxyPort
		phone.HTTPPort = proxyPort + 7000
		if err := database.DB.Save(&phone).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign ports"})
			return
		}
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

	// Create DNS record for this credential
	dnsManager := dns.GetManager()
	if dnsManager != nil && phone.HubServer != nil && phone.HubServer.DNSSubdomain != "" {
		proxySubdomain := dns.GenerateProxySubdomain()
		dnsRecord, err := dnsManager.CreateProxyRecord(proxySubdomain, phone.HubServer.DNSSubdomain)
		if err != nil {
			log.Printf("[CreateCredential] Failed to create DNS record: %v", err)
			// Continue without DNS - not a fatal error
		} else {
			credential.ProxyDomain = dnsRecord.FullDomain
			credential.DNSRecordID = dnsRecord.RecordID
			database.DB.Save(&credential)
			log.Printf("[CreateCredential] Created DNS record: %s -> %s", dnsRecord.FullDomain, dnsRecord.TargetHost)
		}
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Load server relationship for proxy setup
	database.DB.Preload("HubServer").First(&phone, "id = ?", phone.ID)

	// Update SOCKS5 forwarder on server if this credential supports SOCKS5
	if credential.ProxyType == models.ProxyTypeSOCKS5 || credential.ProxyType == models.ProxyTypeBoth {
		go updateSocks5Forwarder(&phone) // Run async to not block response
	}

	// Update HTTP proxy on server if this credential supports HTTP
	if credential.ProxyType == models.ProxyTypeHTTP || credential.ProxyType == models.ProxyTypeBoth {
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
	if req.BlockedDomains != nil {
		credential.BlockedDomains = *req.BlockedDomains
	}

	if err := database.DB.Save(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update credential"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Update proxies on server
	database.DB.Preload("HubServer").First(&phone, "id = ?", phone.ID)
	go updateSocks5Forwarder(&phone)
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

	// Get the credential to access DNS record ID before deletion
	var credential models.ConnectionCredential
	if err := database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).First(&credential).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	// Delete DNS record if exists
	if credential.DNSRecordID != 0 {
		dnsManager := dns.GetManager()
		if dnsManager != nil {
			if err := dnsManager.DeleteProxyRecord(credential.DNSRecordID); err != nil {
				log.Printf("[DeleteCredential] Failed to delete DNS record %d: %v", credential.DNSRecordID, err)
			} else {
				log.Printf("[DeleteCredential] Deleted DNS record for %s", credential.ProxyDomain)
			}
		}
	}

	// Delete the credential
	if err := database.DB.Delete(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete credential"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

	// Update proxies on server
	database.DB.Preload("HubServer").First(&phone, "id = ?", phone.ID)
	go updateSocks5Forwarder(&phone)
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

// GetRotationSettings returns the current rotation settings for a phone
func GetRotationSettings(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rotation_mode":             phone.RotationMode,
		"rotation_interval_minutes": phone.RotationIntervalMinutes,
	})
}

// UpdateRotationSettings updates the rotation settings for a phone
func UpdateRotationSettings(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var req models.RotationSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate interval for timed mode
	if req.RotationMode == "timed" {
		if req.RotationIntervalMinutes < 2 || req.RotationIntervalMinutes > 120 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Rotation interval must be between 2 and 120 minutes"})
			return
		}
	}

	// Update settings
	phone.RotationMode = req.RotationMode
	phone.RotationIntervalMinutes = req.RotationIntervalMinutes
	if err := database.DB.Save(&phone).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update settings"})
		return
	}

	// Notify phone of settings change
	notifyPhoneRotationSettingsUpdated(phone.ID.String(), phone.RotationMode, phone.RotationIntervalMinutes)

	c.JSON(http.StatusOK, gin.H{
		"rotation_mode":             phone.RotationMode,
		"rotation_interval_minutes": phone.RotationIntervalMinutes,
	})
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

	c.JSON(http.StatusOK, gin.H{"message": "IP rotation initiated"})
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

// notifyPhoneRotationSettingsUpdated sends rotation settings to a phone via Centrifugo
func notifyPhoneRotationSettingsUpdated(phoneID string, mode string, intervalMinutes int) {
	if err := phonecomm.SendRotationSettings(phoneID, mode, intervalMinutes); err != nil {
		// Log error but don't fail - phone will get settings on next sync
		_ = err
	}
}

// updateSocks5Forwarder sets up/updates the proxy on the server using hub-agent V2 API
// This forwards external connections from server:proxyPort to phone:1080 via WireGuard
func updateSocks5Forwarder(phone *models.Phone) error {
	if phone.HubServerID == nil || phone.ProxyPort == 0 || phone.WireGuardIP == "" {
		return nil // No server, port, or WireGuard IP configured
	}

	// Get server
	var server models.HubServer
	if err := database.DB.First(&server, "id = ?", phone.HubServerID).Error; err != nil {
		return err
	}

	if server.HubAPIKey == "" || server.HubAPIPort == 0 {
		return fmt.Errorf("hub-agent not configured for server %s", server.Name)
	}

	return updateProxyV2(phone, &server)
}

// updateProxyV2 updates the proxy using hub-agent V2 API (replaces GOST)
// This unified proxy handles both SOCKS5 and HTTP automatically
func updateProxyV2(phone *models.Phone, server *models.HubServer) error {
	// Get ALL active credentials (both SOCKS5 and HTTP)
	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ? AND is_active = ?", phone.ID, true).Find(&credentials)

	// Build credential list for V2 API
	v2Creds := make([]map[string]interface{}, 0, len(credentials))
	for _, cred := range credentials {
		// Skip expired credentials
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
			continue
		}

		credMap := map[string]interface{}{
			"id":           cred.ID.String(),
			"auth_type":    string(cred.AuthType),
			"limit_bytes":  cred.BandwidthLimit,
		}

		if cred.AuthType == models.AuthTypeIP && cred.AllowedIP != "" {
			credMap["allowed_ip"] = cred.AllowedIP
		}

		if cred.AuthType == models.AuthTypeUserPass && cred.Username != "" {
			credMap["username"] = cred.Username
			// For V2, we send the plaintext password - hub-agent will hash it
			// This is secure because we're using HTTPS to the hub
			if cred.Password != "" {
				credMap["password_hash"] = cred.Password
			}
		}

		// Add blocked domains if configured
		if len(cred.BlockedDomains) > 0 {
			credMap["blocked_domains"] = []string(cred.BlockedDomains)
		}

		v2Creds = append(v2Creds, credMap)
	}

	// Build proxy config for V2 API
	proxyConfig := map[string]interface{}{
		"phone_id":    phone.ID.String(),
		"port":        phone.ProxyPort,
		"target_ip":   phone.WireGuardIP,
		"target_port": 1080,
		"credentials": v2Creds,
	}

	return infra.StartProxyV2(server.IP, server.HubAPIPort, server.HubAPIKey, proxyConfig)
}

// updateHTTPProxyCredentials is a no-op with V2 proxy system
// The V2 proxy is unified - updateProxyV2 handles both SOCKS5 and HTTP automatically
func updateHTTPProxyCredentials(phone *models.Phone) error {
	// V2 proxy is unified - updateSocks5Forwarder/updateProxyV2 handles both protocols
	// No separate HTTP proxy needed
	return nil
}
