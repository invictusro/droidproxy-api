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

// CreatePhoneRequest is the request body for creating a phone
type CreatePhoneRequest struct {
	Name        string `json:"name" binding:"required"`
	HubServerID string `json:"hub_server_id" binding:"required"`
}

// PhoneWithCredential extends PhoneResponse with first credential info
type PhoneWithCredential struct {
	models.PhoneResponse
	FirstCredential *CredentialSummary `json:"first_credential,omitempty"`
}

// CredentialSummary is a brief credential for display in phone list
type CredentialSummary struct {
	AuthType  string `json:"auth_type"`
	ProxyType string `json:"proxy_type"`
	Username  string `json:"username,omitempty"`
	AllowedIP string `json:"allowed_ip,omitempty"`
}

// ListPhones returns all phones for the current user
func ListPhones(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var phones []models.Phone
	if err := database.DB.Preload("HubServer").Where("user_id = ?", userID).Find(&phones).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch phones"})
		return
	}

	responses := make([]PhoneWithCredential, len(phones))
	for i, phone := range phones {
		responses[i] = PhoneWithCredential{
			PhoneResponse: phone.ToResponse(),
		}

		// Get first active credential for this phone
		var firstCred models.ConnectionCredential
		if err := database.DB.Where("phone_id = ? AND is_active = ?", phone.ID, true).
			Order("created_at ASC").First(&firstCred).Error; err == nil {
			responses[i].FirstCredential = &CredentialSummary{
				AuthType:  string(firstCred.AuthType),
				ProxyType: string(firstCred.ProxyType),
				Username:  firstCred.Username,
				AllowedIP: firstCred.AllowedIP,
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"phones": responses})
}

// CreatePhone creates a new phone and returns pairing info
func CreatePhone(c *gin.Context) {
	var req CreatePhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := middleware.GetCurrentUserID(c)
	hubServerID, err := uuid.Parse(req.HubServerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid hub server ID"})
		return
	}

	// Verify hub server exists
	var hubServer models.HubServer
	if err := database.DB.First(&hubServer, "id = ?", hubServerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hub server not found"})
		return
	}

	// Create phone (ports are assigned when credentials are created)
	// DNS records are now created per-credential, not per-phone
	phone := models.Phone{
		UserID:      userID,
		HubServerID: &hubServerID,
		Name:        req.Name,
	}

	if err := database.DB.Create(&phone).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create phone"})
		return
	}

	// Generate QR code data with phone ID (for scanning)
	apiBaseURL := config.AppConfig.APIBaseURL
	qrData, _ := phonecomm.GetQRCodeDataString(apiBaseURL, phone.ID.String(), phone.PairingCode)

	c.JSON(http.StatusCreated, models.PhoneWithPairingCode{
		Phone:       phone.ToResponse(),
		PairingCode: phone.PairingCode,
		PairingPIN:  phone.PairingPIN,
		QRCodeData:  qrData,
	})
}

// GetPhone returns a specific phone
func GetPhone(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"phone": phone.ToResponse()})
}

// SetupPhoneDNS creates a DNS record for an existing phone that doesn't have one
func SetupPhoneDNS(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Check if phone already has DNS
	if phone.DNSRecordID != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already has a DNS record", "proxy_domain": phone.ProxyDomain})
		return
	}

	// Check if server has DNS configured
	if phone.HubServer == nil || phone.HubServer.DNSSubdomain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Server does not have DNS configured. Set up server DNS first."})
		return
	}

	dnsManager := dns.GetManager()
	if dnsManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNS manager not configured"})
		return
	}

	// Generate unique subdomain for this proxy
	proxySubdomain := dns.GenerateProxySubdomain()

	// Create CNAME record pointing to server's A record
	dnsRecord, err := dnsManager.CreateProxyRecord(proxySubdomain, phone.HubServer.DNSSubdomain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DNS record: " + err.Error()})
		return
	}

	phone.ProxySubdomain = dnsRecord.Subdomain
	phone.ProxyDomain = dnsRecord.FullDomain
	phone.DNSRecordID = dnsRecord.RecordID

	if err := database.DB.Save(&phone).Error; err != nil {
		// Cleanup DNS record
		dnsManager.DeleteProxyRecord(dnsRecord.RecordID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update phone"})
		return
	}

	log.Printf("[SetupPhoneDNS] Created DNS record: %s -> %s", dnsRecord.FullDomain, dnsRecord.TargetHost)

	c.JSON(http.StatusOK, gin.H{
		"message":      "DNS record created",
		"proxy_domain": dnsRecord.FullDomain,
		"phone":        phone.ToResponse(),
	})
}

// DeletePhone removes a phone
func DeletePhone(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	// First, get the phone with server for cleanup
	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Clean up server-side resources (GOST forwarder, route, WireGuard peer)
	go cleanupPhoneServerResources(&phone)

	// Delete DNS records for all credentials associated with this phone
	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ?", phone.ID).Find(&credentials)
	dnsManager := dns.GetManager()
	if dnsManager != nil {
		for _, cred := range credentials {
			if cred.DNSRecordID != 0 {
				if err := dnsManager.DeleteProxyRecord(cred.DNSRecordID); err != nil {
					log.Printf("[DeletePhone] Failed to delete DNS record %d for credential %s: %v", cred.DNSRecordID, cred.ID, err)
				} else {
					log.Printf("[DeletePhone] Deleted DNS record for credential %s (%s)", cred.ID, cred.ProxyDomain)
				}
			}
		}
	}

	// Delete all related records (foreign key constraints)
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.ConnectionCredential{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.RotationToken{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.PhoneStats{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.PhoneDataUsage{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.PhoneUptimeLog{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.PhoneDailyUptime{})
	database.DB.Where("phone_id = ?", phone.ID).Delete(&models.PhoneGroupMembership{})

	// Delete the phone
	if err := database.DB.Delete(&phone).Error; err != nil {
		log.Printf("[DeletePhone] Failed to delete phone %s: %v", phone.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete phone"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone deleted"})
}

// RotateIP sends a rotate IP command to a phone
// Note: Status is real-time via Centrifugo, we just send the command
func RotateIP(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	if err := phonecomm.SendRotateIP(phoneID.String()); err != nil {
		fmt.Printf("[RotateIP] Failed to send command to phone %s: %v\n", phoneID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send command: " + err.Error()})
		return
	}

	fmt.Printf("[RotateIP] Command sent successfully to phone %s\n", phoneID)

	c.JSON(http.StatusOK, gin.H{"message": "Rotate IP command sent"})
}

// RestartProxy sends a restart command to a phone
func RestartProxy(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	if err := phonecomm.SendRestart(phoneID.String()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send command"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Restart command sent"})
}

// GetPhoneStats returns connection statistics for a phone
func GetPhoneStats(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	// Verify ownership
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Get recent stats
	var stats []models.PhoneStats
	database.DB.Where("phone_id = ?", phoneID).Order("recorded_at DESC").Limit(100).Find(&stats)

	responses := make([]models.StatsResponse, len(stats))
	for i, s := range stats {
		responses[i] = s.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"stats": responses})
}

// PairPhone handles pairing request from Android app (QR + PIN method)
// Security: The phone's public key is encrypted with a key derived from the PIN,
// preventing MITM attacks from injecting their own key.
func PairPhone(c *gin.Context) {
	var req models.PairingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("pairing_code = ?", req.PairingCode).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invalid pairing code"})
		return
	}

	// Verify PIN format (must be 4 digits)
	if len(req.PairingPIN) != 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PIN format"})
		return
	}

	// Verify PIN matches
	if phone.PairingPIN != req.PairingPIN {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid PIN"})
		return
	}

	if phone.PairedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already paired"})
		return
	}

	// Decrypt the phone's public key using PIN-derived key
	// This ensures MITM cannot inject their own key without knowing the PIN
	publicKeyPEM, err := phonecomm.DecryptPublicKey(req.EncryptedPublicKey, req.PairingPIN, req.PairingCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to decrypt public key - invalid PIN or corrupted data"})
		return
	}

	// Validate the public key format
	if _, err := phonecomm.ValidatePublicKey(publicKeyPEM); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	// Generate WireGuard config for this phone
	wireGuardConfig := generateWireGuardConfig(&phone)

	// Generate API token for secure phone authentication
	apiToken := models.GenerateAPIToken()

	// Hash the device fingerprint for storage (we don't need the raw value)
	fingerprintHash := phonecomm.HashDeviceFingerprint(req.DeviceFingerprint)

	// Update phone as paired
	now := time.Now()
	phone.PairedAt = &now
	phone.WireGuardConfig = wireGuardConfig
	phone.APIToken = apiToken
	phone.PublicKey = publicKeyPEM
	phone.DeviceFingerprint = fingerprintHash
	database.DB.Save(&phone)

	// Generate Centrifugo token for this phone
	centrifugoToken, _ := phonecomm.GeneratePhoneToken(phone.ID.String())

	// Get server IP for proxy connection
	serverIP := ""
	if phone.HubServer != nil {
		serverIP = phone.HubServer.IP
	}

	c.JSON(http.StatusOK, models.PairingResponse{
		PhoneID:         phone.ID.String(),
		APIToken:        apiToken,
		WireGuardConfig: wireGuardConfig,
		CentrifugoURL:   config.AppConfig.CentrifugoPublicURL,
		CentrifugoToken: centrifugoToken,
		APIBaseURL:      config.AppConfig.APIBaseURL,
		ServerIP:        serverIP,
		ProxyPort:       phone.ProxyPort,
	})
}

// Heartbeat handles status updates from Android app
// Note: Status is real-time data via Centrifugo, not stored in database
func Heartbeat(c *gin.Context) {
	var req models.HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	phoneID, err := uuid.Parse(req.PhoneID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Extract Bearer token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}
	token := authHeader[7:]

	var phone models.Phone
	if err := database.DB.First(&phone, "id = ?", phoneID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Verify token matches
	if phone.APIToken != token {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Record stats (status is real-time via Centrifugo, not stored)
	stats := models.PhoneStats{
		PhoneID:           phoneID,
		ActiveConnections: req.ActiveConnections,
		TotalConnections:  req.TotalConnections,
	}
	database.DB.Create(&stats)

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// CentrifugoPublishProxy handles proxied publish events from Centrifugo
// - "heartbeat" type: lightweight, every 10s, just passes through for dashboard (no DB writes)
// - "status" type: full update, every 5m, records analytics to database
func CentrifugoPublishProxy(c *gin.Context) {
	var req struct {
		Channel string `json:"channel"`
		Data    struct {
			Type              string `json:"type"`
			PhoneID           string `json:"phone_id"`
			Status            string `json:"status"`
			CurrentIP         string `json:"current_ip"`
			ActiveConnections int    `json:"active_connections"`
			TotalConnections  int64  `json:"total_connections"`
			BytesIn           int64  `json:"bytes_in"`  // Bytes received since last update
			BytesOut          int64  `json:"bytes_out"` // Bytes sent since last update
			SimCountry        string `json:"sim_country"`
			SimCarrier        string `json:"sim_carrier"`
		} `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Return empty result to allow publish to proceed
		c.JSON(http.StatusOK, gin.H{"result": gin.H{}})
		return
	}

	// Heartbeat: lightweight update, just pass through for dashboard (no DB writes)
	if req.Data.Type == "heartbeat" {
		c.JSON(http.StatusOK, gin.H{"result": gin.H{}})
		return
	}

	// Only process full status updates for analytics recording
	if req.Data.Type != "status" || req.Data.PhoneID == "" {
		c.JSON(http.StatusOK, gin.H{"result": gin.H{}})
		return
	}

	phoneID, err := uuid.Parse(req.Data.PhoneID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"result": gin.H{}})
		return
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Update SIM info if provided
	if req.Data.SimCountry != "" || req.Data.SimCarrier != "" {
		updates := map[string]interface{}{}
		if req.Data.SimCountry != "" {
			updates["sim_country"] = req.Data.SimCountry
		}
		if req.Data.SimCarrier != "" {
			updates["sim_carrier"] = req.Data.SimCarrier
		}
		database.DB.Model(&models.Phone{}).Where("id = ?", phoneID).Updates(updates)
	}

	// Record connection stats
	if req.Data.ActiveConnections > 0 || req.Data.TotalConnections > 0 {
		stats := models.PhoneStats{
			PhoneID:           phoneID,
			ActiveConnections: req.Data.ActiveConnections,
			TotalConnections:  req.Data.TotalConnections,
		}
		database.DB.Create(&stats)
	}

	// Record data usage (upsert for today)
	if req.Data.BytesIn > 0 || req.Data.BytesOut > 0 {
		var usage models.PhoneDataUsage
		result := database.DB.Where("phone_id = ? AND date = ?", phoneID, today).First(&usage)
		if result.Error != nil {
			// Create new record for today
			usage = models.PhoneDataUsage{
				PhoneID:  phoneID,
				Date:     today,
				BytesIn:  req.Data.BytesIn,
				BytesOut: req.Data.BytesOut,
			}
			database.DB.Create(&usage)
		} else {
			// Update existing record (add to totals)
			database.DB.Model(&usage).Updates(map[string]interface{}{
				"bytes_in":   usage.BytesIn + req.Data.BytesIn,
				"bytes_out":  usage.BytesOut + req.Data.BytesOut,
				"updated_at": now,
			})
		}
	}

	// Track uptime - log status changes
	if req.Data.Status == "online" || req.Data.Status == "offline" {
		// Check if status changed from last log
		var lastLog models.PhoneUptimeLog
		result := database.DB.Where("phone_id = ?", phoneID).Order("timestamp DESC").First(&lastLog)

		// Only log if status changed or no previous log exists
		if result.Error != nil || lastLog.Status != req.Data.Status {
			uptimeLog := models.PhoneUptimeLog{
				PhoneID:   phoneID,
				Status:    req.Data.Status,
				Timestamp: now,
				IP:        req.Data.CurrentIP,
			}
			database.DB.Create(&uptimeLog)

			// Update daily uptime for today
			updateDailyUptime(phoneID, today)
		}
	}

	// Return empty result to allow publish
	c.JSON(http.StatusOK, gin.H{"result": gin.H{}})
}

// updateDailyUptime calculates and stores daily uptime for a phone
func updateDailyUptime(phoneID uuid.UUID, date time.Time) {
	// Get all status logs for today
	startOfDay := date
	endOfDay := date.Add(24 * time.Hour)

	var logs []models.PhoneUptimeLog
	database.DB.Where("phone_id = ? AND timestamp >= ? AND timestamp < ?", phoneID, startOfDay, endOfDay).
		Order("timestamp ASC").Find(&logs)

	// Calculate online minutes
	onlineMinutes := 0
	var lastOnlineTime *time.Time

	// Check status at start of day (carry over from previous day)
	var prevLog models.PhoneUptimeLog
	if database.DB.Where("phone_id = ? AND timestamp < ?", phoneID, startOfDay).
		Order("timestamp DESC").First(&prevLog).Error == nil {
		if prevLog.Status == "online" {
			t := startOfDay
			lastOnlineTime = &t
		}
	}

	for _, log := range logs {
		if log.Status == "online" {
			lastOnlineTime = &log.Timestamp
		} else if log.Status == "offline" && lastOnlineTime != nil {
			// Calculate minutes online
			mins := int(log.Timestamp.Sub(*lastOnlineTime).Minutes())
			onlineMinutes += mins
			lastOnlineTime = nil
		}
	}

	// If still online at end of period, count until now
	now := time.Now()
	if lastOnlineTime != nil {
		endTime := now
		if now.After(endOfDay) {
			endTime = endOfDay
		}
		mins := int(endTime.Sub(*lastOnlineTime).Minutes())
		onlineMinutes += mins
	}

	// Cap at 1440 minutes (24 hours)
	if onlineMinutes > 1440 {
		onlineMinutes = 1440
	}

	// Upsert daily uptime record
	var dailyUptime models.PhoneDailyUptime
	result := database.DB.Where("phone_id = ? AND date = ?", phoneID, date).First(&dailyUptime)
	if result.Error != nil {
		dailyUptime = models.PhoneDailyUptime{
			PhoneID:       phoneID,
			Date:          date,
			OnlineMinutes: onlineMinutes,
		}
		database.DB.Create(&dailyUptime)
	} else {
		database.DB.Model(&dailyUptime).Updates(map[string]interface{}{
			"online_minutes": onlineMinutes,
			"updated_at":     now,
		})
	}
}

// GetUserPhonesForLogin returns unpaired phones for a user (for phone app login)
func GetUserPhonesForLogin(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Get unpaired phones for this user
	var phones []models.Phone
	database.DB.Preload("HubServer").Where("user_id = ? AND paired_at IS NULL", user.ID).Find(&phones)

	phoneInfos := make([]models.PhoneLoginInfo, len(phones))
	for i, p := range phones {
		serverName := ""
		if p.HubServer != nil {
			serverName = p.HubServer.Name
		}
		phoneInfos[i] = models.PhoneLoginInfo{
			ID:          p.ID.String(),
			Name:        p.Name,
			ServerName:  serverName,
			PairingCode: p.PairingCode, // Needed for client-side key derivation
		}
	}

	c.JSON(http.StatusOK, models.PhoneListForLoginResponse{Phones: phoneInfos})
}

// PhoneLogin handles login from Android app using email/password
// Security: The phone's public key is encrypted with a key derived from PIN + pairing_code,
// preventing MITM attacks from injecting their own key.
// The PIN is displayed on the dashboard and must be entered on the phone.
func PhoneLogin(c *gin.Context) {
	var req models.PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify user credentials
	var user models.User
	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Check if user registered with local auth (not Google)
	if user.AuthProvider != models.AuthLocal {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please use Google login"})
		return
	}

	if !user.CheckPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Verify phone belongs to user and is unpaired
	phoneID, err := uuid.Parse(req.PhoneID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, user.ID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	if phone.PairedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already paired"})
		return
	}

	// Verify PIN format (must be 4 digits)
	if len(req.PairingPIN) != 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PIN format"})
		return
	}

	// Verify PIN matches the phone's PIN (displayed on dashboard)
	if phone.PairingPIN != req.PairingPIN {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid PIN"})
		return
	}

	// Decrypt the phone's public key using PIN-derived key
	// Same derivation as QR flow: PIN + pairing_code
	// This ensures MITM cannot inject their own key without knowing the PIN
	publicKeyPEM, err := phonecomm.DecryptPublicKey(req.EncryptedPublicKey, req.PairingPIN, phone.PairingCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to decrypt public key - invalid PIN or corrupted data"})
		return
	}

	// Validate the public key format
	if _, err := phonecomm.ValidatePublicKey(publicKeyPEM); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	// Generate WireGuard config for this phone
	wireGuardConfig := generateWireGuardConfig(&phone)

	// Generate API token for secure phone authentication
	apiToken := models.GenerateAPIToken()

	// Hash the device fingerprint for storage
	fingerprintHash := phonecomm.HashDeviceFingerprint(req.DeviceFingerprint)

	// Update phone as paired
	now := time.Now()
	phone.PairedAt = &now
	phone.WireGuardConfig = wireGuardConfig
	phone.APIToken = apiToken
	phone.PublicKey = publicKeyPEM
	phone.DeviceFingerprint = fingerprintHash
	database.DB.Save(&phone)

	// Generate Centrifugo token for this phone
	centrifugoToken, _ := phonecomm.GeneratePhoneToken(phone.ID.String())

	// Get server IP for proxy connection
	serverIP := ""
	if phone.HubServer != nil {
		serverIP = phone.HubServer.IP
	}

	c.JSON(http.StatusOK, models.PairingResponse{
		PhoneID:         phone.ID.String(),
		APIToken:        apiToken,
		WireGuardConfig: wireGuardConfig,
		CentrifugoURL:   config.AppConfig.CentrifugoPublicURL,
		CentrifugoToken: centrifugoToken,
		APIBaseURL:      config.AppConfig.APIBaseURL,
		ServerIP:        serverIP,
		ProxyPort:       phone.ProxyPort,
	})
}

// GetProxyConfig returns the proxy configuration for an authenticated phone
// This endpoint is secured with phone token authentication
func GetProxyConfig(c *gin.Context) {
	phone := middleware.GetCurrentPhone(c)
	if phone == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not authenticated"})
		return
	}

	// Ensure server is loaded
	if phone.HubServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No server assigned to phone"})
		return
	}

	// Generate fresh Centrifugo token
	centrifugoToken, _ := phonecomm.GeneratePhoneToken(phone.ID.String())

	c.JSON(http.StatusOK, models.ProxyConfigResponse{
		PhoneID:         phone.ID.String(),
		ServerIP:        phone.HubServer.IP,
		ProxyPort:       phone.ProxyPort,
		WireGuardConfig: phone.WireGuardConfig,
		CentrifugoURL:   config.AppConfig.CentrifugoPublicURL,
		CentrifugoToken: centrifugoToken,
	})
}

// RefreshPhoneToken generates a new API token for the phone (requires current valid token)
func RefreshPhoneToken(c *gin.Context) {
	phone := middleware.GetCurrentPhone(c)
	if phone == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not authenticated"})
		return
	}

	// Generate new token
	newToken := models.GenerateAPIToken()
	phone.APIToken = newToken
	database.DB.Save(&phone)

	c.JSON(http.StatusOK, gin.H{
		"api_token": newToken,
		"message":   "Token refreshed successfully",
	})
}

// GetPhoneCredentials returns the connection credentials for an authenticated phone
// This allows the phone to validate incoming proxy connections
func GetPhoneCredentials(c *gin.Context) {
	phone := middleware.GetCurrentPhone(c)
	if phone == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not authenticated"})
		return
	}

	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ? AND is_active = ?", phone.ID, true).Find(&credentials)

	// Return simplified credential info for the phone
	type PhoneCredential struct {
		ID        string `json:"id"`
		AuthType  string `json:"auth_type"`
		ProxyType string `json:"proxy_type"`
		AllowedIP string `json:"allowed_ip,omitempty"`
		Username  string `json:"username,omitempty"`
		Password  string `json:"password,omitempty"` // Phone needs plaintext for validation
	}

	result := make([]PhoneCredential, 0, len(credentials))
	for _, cred := range credentials {
		// Skip expired credentials
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
			continue
		}

		pc := PhoneCredential{
			ID:        cred.ID.String(),
			AuthType:  string(cred.AuthType),
			ProxyType: string(cred.ProxyType),
			AllowedIP: cred.AllowedIP,
			Username:  cred.Username,
			Password:  cred.Password, // This is the bcrypt hash, phone will use bcrypt.Compare
		}
		result = append(result, pc)
	}

	c.JSON(http.StatusOK, gin.H{"credentials": result})
}

// GetDomainBlocklist returns the list of blocked domain patterns for the phone
// Phone-authenticated endpoint
func GetDomainBlocklist(c *gin.Context) {
	phone := middleware.GetCurrentPhone(c)
	if phone == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not authenticated"})
		return
	}

	// Fetch all active blocked domain patterns
	var blocklist []models.DomainBlocklist
	if err := database.DB.Where("is_active = ?", true).Find(&blocklist).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch blocklist"})
		return
	}

	// Extract just the patterns for the phone
	patterns := make([]string, 0, len(blocklist))
	for _, entry := range blocklist {
		patterns = append(patterns, entry.Pattern)
	}

	// Find the most recent update time
	var lastUpdated time.Time
	if len(blocklist) > 0 {
		for _, entry := range blocklist {
			if entry.UpdatedAt.After(lastUpdated) {
				lastUpdated = entry.UpdatedAt
			}
		}
	}

	c.JSON(http.StatusOK, models.BlocklistPatternResponse{
		Patterns:  patterns,
		UpdatedAt: lastUpdated,
	})
}

// Helper functions

func getNextAvailablePort(server *models.HubServer) (int, error) {
	var usedPorts []int
	database.DB.Model(&models.Phone{}).Where("hub_server_id = ?", server.ID).Pluck("proxy_port", &usedPorts)

	usedSet := make(map[int]bool)
	for _, p := range usedPorts {
		usedSet[p] = true
	}

	// Build list of available ports
	var availablePorts []int
	for port := server.ProxyPortStart; port <= server.ProxyPortEnd; port++ {
		if !usedSet[port] {
			availablePorts = append(availablePorts, port)
		}
	}

	if len(availablePorts) == 0 {
		return 0, fmt.Errorf("no available ports")
	}

	// Pick a random port from available ones
	randomIndex := rand.Intn(len(availablePorts))
	return availablePorts[randomIndex], nil
}

func generateWireGuardConfig(phone *models.Phone) string {
	if phone.HubServer == nil {
		return ""
	}

	// Generate WireGuard keypair for this phone
	keyPair, err := infra.GenerateWireGuardKeyPair()
	if err != nil {
		return ""
	}

	// Store the keys on the phone record
	phone.WireGuardPrivateKey = keyPair.PrivateKey
	phone.WireGuardPublicKey = keyPair.PublicKey

	// Get server's WireGuard public key (should be stored on server record)
	serverPublicKey := phone.HubServer.WireGuardPublicKey
	if serverPublicKey == "" {
		// Fallback: use a placeholder if server key not set
		serverPublicKey = "SERVER_KEY_NOT_CONFIGURED"
	}

	// Get next available WireGuard IP from server
	wireGuardIP, err := getNextWireGuardIP(phone.HubServer)
	if err != nil {
		log.Printf("[WireGuard] Failed to allocate IP: %v", err)
		return ""
	}
	phone.WireGuardIP = wireGuardIP

	// Add this phone as a WireGuard peer on the server via SSH
	go addWireGuardPeerToServer(phone.HubServer, keyPair.PublicKey, wireGuardIP)

	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/16
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, keyPair.PrivateKey, wireGuardIP, serverPublicKey, phone.HubServer.IP, phone.HubServer.WireGuardPort)
}

// getNextWireGuardIP finds the next available WireGuard IP for a hub server
// Uses 10.66.0.0/16 subnet (server is 10.66.0.1)
// Range: 10.66.0.2 - 10.66.255.254 = 65,533 phones per hub server
func getNextWireGuardIP(server *models.HubServer) (string, error) {
	// Get all used WireGuard IPs for this hub server
	var usedIPs []string
	database.DB.Model(&models.Phone{}).Where("hub_server_id = ?", server.ID).Pluck("wire_guard_ip", &usedIPs)

	usedSet := make(map[string]bool)
	for _, ip := range usedIPs {
		if ip != "" {
			usedSet[ip] = true
		}
	}

	// Find first available IP in 10.66.0.0/16 (server is 10.66.0.1, phones start at 10.66.0.2)
	// Range: 10.66.0.2 - 10.66.255.254 = 65,533 IPs per server
	for third := 0; third <= 255; third++ {
		startFourth := 2
		if third > 0 {
			startFourth = 1 // Only skip .0 and .1 in first octet
		}
		for fourth := startFourth; fourth <= 254; fourth++ {
			ip := fmt.Sprintf("10.66.%d.%d", third, fourth)
			if !usedSet[ip] {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no available WireGuard IPs on server %s (all 65,533 IPs exhausted)", server.Name)
}

// addWireGuardPeerToServer adds the phone as a WireGuard peer on the hub server
func addWireGuardPeerToServer(server *models.HubServer, publicKey, ip string) {
	if server.SSHPassword == "" {
		return // No SSH credentials configured
	}

	client := infra.NewSSHClient(server.IP, server.SSHPort, server.SSHUser, server.SSHPassword)
	if err := client.Connect(); err != nil {
		fmt.Printf("[WireGuard] Failed to connect to server %s: %v\n", server.Name, err)
		return
	}
	defer client.Close()

	wgManager := infra.NewWireGuardManager(client)
	if err := wgManager.AddPeer(publicKey, ip); err != nil {
		fmt.Printf("[WireGuard] Failed to add peer %s: %v\n", ip, err)
	} else {
		fmt.Printf("[WireGuard] Added peer %s to server %s\n", ip, server.Name)
	}
}

// cleanupPhoneServerResources removes proxy and WireGuard peer for a phone using hub-agent V2 API
func cleanupPhoneServerResources(phone *models.Phone) {
	if phone.HubServer == nil {
		return // No server configured
	}

	if phone.HubServer.HubAPIKey == "" || phone.HubServer.HubAPIPort == 0 {
		log.Printf("[Cleanup] No hub-agent configured for server %s", phone.HubServer.Name)
		return
	}

	// Stop proxy on SOCKS5 port
	if phone.ProxyPort > 0 {
		if err := infra.StopProxyV2(phone.HubServer.IP, phone.HubServer.HubAPIPort, phone.HubServer.HubAPIKey, phone.ProxyPort); err != nil {
			log.Printf("[Cleanup] Failed to stop proxy for phone %s: %v", phone.ID, err)
		} else {
			log.Printf("[Cleanup] Stopped proxy for phone %s (port %d)", phone.ID, phone.ProxyPort)
		}
	}

	// Remove WireGuard peer
	if phone.WireGuardPublicKey != "" {
		if err := infra.RemoveWireGuardPeerV2(phone.HubServer.IP, phone.HubServer.HubAPIPort, phone.HubServer.HubAPIKey, phone.WireGuardPublicKey); err != nil {
			log.Printf("[Cleanup] Failed to remove WireGuard peer for phone %s: %v", phone.ID, err)
		} else {
			log.Printf("[Cleanup] Removed WireGuard peer for phone %s", phone.ID)
		}
	}
}
