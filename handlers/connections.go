package handlers

import (
	"fmt"
	"log"
	"math/rand"
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

const (
	// Port range for per-credential proxies (separate from phone ports 20001-20100)
	CredentialPortStart = 10000
	CredentialPortEnd   = 19999
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

	// Verify phone has a hub server assigned
	if phone.HubServer == nil || phone.HubServerID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone is not paired to a hub server"})
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

	// Allocate a unique port for this credential
	credentialPort, err := getNextAvailableCredentialPort(phone.HubServer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No ports available on this server"})
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
		Port:           credentialPort,
		IsActive:       true,
	}

	// Set default proxy type (no longer allow 'both' for new credentials)
	if credential.ProxyType == "" {
		credential.ProxyType = models.ProxyTypeSOCKS5
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

	// Start proxy for this credential on its assigned port
	go startCredentialProxy(&phone, &credential)

	// Return response with plain password (only on creation)
	response := models.ConnectionCredentialWithPassword{
		ConnectionCredentialResponse: credential.ToResponse(),
		Password:                     req.Password, // Include plain password for user to copy
	}
	c.JSON(http.StatusCreated, gin.H{
		"credential": response,
	})
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

	// Update the credential's proxy on the hub-agent
	database.DB.Preload("HubServer").First(&phone, "id = ?", phone.ID)
	if credential.Port > 0 {
		go updateCredentialProxy(&phone, &credential)
	}

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

	// Stop the credential's proxy before deleting
	credentialPort := credential.Port
	database.DB.Preload("HubServer").First(&phone, "id = ?", phone.ID)
	if credentialPort > 0 {
		go stopCredentialProxy(&phone, credentialPort)
	}

	// Delete the credential
	if err := database.DB.Delete(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete credential"})
		return
	}

	// Notify phone to refresh SOCKS5 credentials
	notifyPhoneCredentialsUpdated(phone.ID.String())

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
// Sends ALL credentials because the hub always connects to phone via SOCKS5
func notifyPhoneCredentialsUpdated(phoneID string) {
	// Fetch current credentials for this phone
	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ? AND is_active = ?", phoneID, true).Find(&credentials)

	// Convert to phone format - send ALL credentials (hub uses SOCKS5 for all connections)
	phoneCredentials := make([]PhoneCredential, 0, len(credentials))
	for _, cred := range credentials {
		// Skip expired credentials
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
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


// getNextAvailableCredentialPort finds a random available port for a credential
// Ports are selected randomly (not sequentially) from the credential port range
func getNextAvailableCredentialPort(server *models.HubServer) (int, error) {
	// Get all currently used credential ports on this server
	var usedPorts []int
	database.DB.Model(&models.ConnectionCredential{}).
		Joins("JOIN phones ON connection_credentials.phone_id = phones.id").
		Where("phones.hub_server_id = ? AND connection_credentials.port > 0", server.ID).
		Pluck("connection_credentials.port", &usedPorts)

	// Build a set of used ports for O(1) lookup
	usedSet := make(map[int]bool, len(usedPorts))
	for _, port := range usedPorts {
		usedSet[port] = true
	}

	// Calculate available ports
	totalPorts := CredentialPortEnd - CredentialPortStart
	availableCount := totalPorts - len(usedPorts)

	if availableCount <= 0 {
		return 0, fmt.Errorf("no available ports in range %d-%d", CredentialPortStart, CredentialPortEnd)
	}

	// Try up to 100 random ports to find an available one
	for attempts := 0; attempts < 100; attempts++ {
		port := CredentialPortStart + rand.Intn(totalPorts)
		if !usedSet[port] {
			return port, nil
		}
	}

	// Fallback: linear scan for first available (shouldn't normally reach here)
	for port := CredentialPortStart; port < CredentialPortEnd; port++ {
		if !usedSet[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports found")
}

// startCredentialProxy starts a proxy for a single credential on its assigned port
func startCredentialProxy(phone *models.Phone, credential *models.ConnectionCredential) error {
	if phone.HubServerID == nil || phone.WireGuardIP == "" {
		return fmt.Errorf("phone has no hub server or WireGuard IP")
	}

	server := phone.HubServer
	if server == nil {
		var s models.HubServer
		if err := database.DB.First(&s, "id = ?", phone.HubServerID).Error; err != nil {
			return fmt.Errorf("failed to get hub server: %w", err)
		}
		server = &s
	}

	if server.HubAPIKey == "" || server.HubAPIPort == 0 {
		return fmt.Errorf("hub-agent not configured for server %s", server.Name)
	}

	// Build credential for V2 API
	credMap := map[string]interface{}{
		"id":          credential.ID.String(),
		"auth_type":   string(credential.AuthType),
		"limit_bytes": credential.BandwidthLimit,
	}

	if credential.AuthType == models.AuthTypeIP && credential.AllowedIP != "" {
		credMap["allowed_ip"] = credential.AllowedIP
	}

	if credential.AuthType == models.AuthTypeUserPass && credential.Username != "" {
		credMap["username"] = credential.Username
		if credential.Password != "" {
			credMap["password_hash"] = credential.Password
		}
	}

	if len(credential.BlockedDomains) > 0 {
		credMap["blocked_domains"] = []string(credential.BlockedDomains)
	}

	// Determine protocol from credential's proxy type
	protocol := "socks5"
	if credential.ProxyType == models.ProxyTypeHTTP {
		protocol = "http"
	}

	// Build proxy config for this single credential
	proxyConfig := map[string]interface{}{
		"port":        credential.Port,
		"target_ip":   phone.WireGuardIP,
		"target_port": 1080, // Phone SOCKS5 server
		"protocol":    protocol,
		"credentials": []map[string]interface{}{credMap},
	}

	log.Printf("[startCredentialProxy] Starting %s proxy on port %d for credential %s (phone: %s)",
		protocol, credential.Port, credential.ID, phone.Name)

	return infra.StartProxyV2(server.IP, server.HubAPIPort, server.HubAPIKey, proxyConfig)
}

// stopCredentialProxy stops the proxy for a credential
func stopCredentialProxy(phone *models.Phone, credentialPort int) error {
	if phone.HubServerID == nil {
		return nil
	}

	server := phone.HubServer
	if server == nil {
		var s models.HubServer
		if err := database.DB.First(&s, "id = ?", phone.HubServerID).Error; err != nil {
			return fmt.Errorf("failed to get hub server: %w", err)
		}
		server = &s
	}

	if server.HubAPIKey == "" || server.HubAPIPort == 0 {
		return nil
	}

	log.Printf("[stopCredentialProxy] Stopping proxy on port %d", credentialPort)
	return infra.StopProxyV2(server.IP, server.HubAPIPort, server.HubAPIKey, credentialPort)
}

// updateCredentialProxy updates an existing credential's proxy on the hub-agent
func updateCredentialProxy(phone *models.Phone, credential *models.ConnectionCredential) error {
	if phone.HubServerID == nil || phone.WireGuardIP == "" || credential.Port == 0 {
		return nil
	}

	server := phone.HubServer
	if server == nil {
		var s models.HubServer
		if err := database.DB.First(&s, "id = ?", phone.HubServerID).Error; err != nil {
			return fmt.Errorf("failed to get hub server: %w", err)
		}
		server = &s
	}

	if server.HubAPIKey == "" || server.HubAPIPort == 0 {
		return nil
	}

	// Build credential for V2 API
	credMap := map[string]interface{}{
		"id":          credential.ID.String(),
		"auth_type":   string(credential.AuthType),
		"limit_bytes": credential.BandwidthLimit,
	}

	if credential.AuthType == models.AuthTypeIP && credential.AllowedIP != "" {
		credMap["allowed_ip"] = credential.AllowedIP
	}

	if credential.AuthType == models.AuthTypeUserPass && credential.Username != "" {
		credMap["username"] = credential.Username
		if credential.Password != "" {
			credMap["password_hash"] = credential.Password
		}
	}

	if len(credential.BlockedDomains) > 0 {
		credMap["blocked_domains"] = []string(credential.BlockedDomains)
	}

	log.Printf("[updateCredentialProxy] Updating credentials on port %d for credential %s",
		credential.Port, credential.ID)

	return infra.UpdateProxyCredentialsV2(server.IP, server.HubAPIPort, server.HubAPIKey,
		credential.Port, []map[string]interface{}{credMap})
}
