package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	phonecomm "github.com/droidproxy/api/internal/phone"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ResellerPhoneResponse is the response format for phones in reseller API
type ResellerPhoneResponse struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	Status            string    `json:"status"` // online, offline, pending
	PlanTier          string    `json:"plan_tier"`
	PlanDaysRemaining int       `json:"plan_days_remaining"`
	LicenseExpiresAt  string    `json:"license_expires_at,omitempty"`
	MaxConnections    int       `json:"max_connections"`
	SpeedLimitMbps    int       `json:"speed_limit_mbps"`
	ActiveConnections int       `json:"active_connections"`
	ServerLocation    string    `json:"server_location,omitempty"`
	ServerIP          string    `json:"server_ip,omitempty"`
	SIMCountry        string    `json:"sim_country,omitempty"`
	SIMCarrier        string    `json:"sim_carrier,omitempty"`
	CreatedAt         string    `json:"created_at"`
}

// ResellerCredentialResponse is the response format for credentials
type ResellerCredentialResponse struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	AuthType       string    `json:"auth_type"` // ip, userpass
	ProxyType      string    `json:"proxy_type"` // socks5, http, both
	Username       string    `json:"username,omitempty"`
	Password       string    `json:"password,omitempty"` // Only on creation
	AllowedIP      string    `json:"allowed_ip,omitempty"`
	Port           int       `json:"port"`
	ProxyHost      string    `json:"proxy_host"` // Server IP or domain
	SOCKS5URL      string    `json:"socks5_url,omitempty"`
	HTTPURL        string    `json:"http_url,omitempty"`
	ExpiresAt      string    `json:"expires_at,omitempty"`
	IsActive       bool      `json:"is_active"`
	BandwidthUsed  int64     `json:"bandwidth_used"`
	BandwidthLimit int64     `json:"bandwidth_limit,omitempty"`
	CreatedAt      string    `json:"created_at"`
}

// ListResellerPhones returns phones accessible by the API key (Nitro only)
func ListResellerPhones(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)

	// Base query - only Nitro phones with active license
	query := database.DB.Model(&models.Phone{}).
		Preload("HubServer").
		Where("user_id = ?", userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true)

	// Filter by groups if scope is 'groups'
	if apiKey.Scope == "groups" && len(apiKey.GroupIDs) > 0 {
		// Get phone IDs from group memberships
		var phoneIDs []uuid.UUID
		database.DB.Model(&models.PhoneGroupMembership{}).
			Where("group_id IN ?", []string(apiKey.GroupIDs)).
			Pluck("phone_id", &phoneIDs)

		if len(phoneIDs) == 0 {
			c.JSON(http.StatusOK, gin.H{"phones": []ResellerPhoneResponse{}})
			return
		}
		query = query.Where("id IN ?", phoneIDs)
	}

	var phones []models.Phone
	if err := query.Find(&phones).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch phones"})
		return
	}

	responses := make([]ResellerPhoneResponse, len(phones))
	for i, phone := range phones {
		responses[i] = phoneToResellerResponse(&phone)
	}

	c.JSON(http.StatusOK, gin.H{"phones": responses})
}

// GetResellerPhone returns a single phone by ID
func GetResellerPhone(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Preload("HubServer").
		Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible (requires Nitro plan)"})
		return
	}

	// Check API key access
	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	c.JSON(http.StatusOK, phoneToResellerResponse(&phone))
}

// ListResellerCredentials returns credentials for a phone
func ListResellerCredentials(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Preload("HubServer").
		Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	var credentials []models.ConnectionCredential
	database.DB.Where("phone_id = ?", phoneID).Order("created_at DESC").Find(&credentials)

	responses := make([]ResellerCredentialResponse, len(credentials))
	for i, cred := range credentials {
		responses[i] = credentialToResellerResponse(&cred, &phone, false)
	}

	c.JSON(http.StatusOK, gin.H{"credentials": responses})
}

// GetResellerCredential returns a single credential
func GetResellerCredential(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
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

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Preload("HubServer").
		Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	var credential models.ConnectionCredential
	if err := database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).First(&credential).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	c.JSON(http.StatusOK, credentialToResellerResponse(&credential, &phone, false))
}

// CreateResellerCredential creates a new credential for a phone
func CreateResellerCredential(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Preload("HubServer").
		Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	var req struct {
		Name           string `json:"name" binding:"required"`
		AuthType       string `json:"auth_type" binding:"required"` // ip, userpass
		ProxyType      string `json:"proxy_type"`                    // socks5, http, both (default: socks5)
		AllowedIP      string `json:"allowed_ip"`                    // Required if auth_type is 'ip'
		Username       string `json:"username"`                      // Optional for userpass
		BandwidthLimit int64  `json:"bandwidth_limit"`               // In bytes, 0 = unlimited
		ExpiresInDays  int    `json:"expires_in_days"`               // 0 = no expiry
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: name and auth_type are required"})
		return
	}

	// Validate auth_type
	if req.AuthType != "ip" && req.AuthType != "userpass" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_type must be 'ip' or 'userpass'"})
		return
	}

	// Validate proxy_type
	if req.ProxyType == "" {
		req.ProxyType = "socks5"
	}
	if req.ProxyType != "socks5" && req.ProxyType != "http" && req.ProxyType != "both" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "proxy_type must be 'socks5', 'http', or 'both'"})
		return
	}

	// Validate IP auth
	if req.AuthType == "ip" && req.AllowedIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "allowed_ip is required for IP authentication"})
		return
	}

	// Check max credentials limit based on plan
	var credCount int64
	database.DB.Model(&models.ConnectionCredential{}).Where("phone_id = ?", phoneID).Count(&credCount)
	if credCount >= int64(phone.MaxConnections) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Maximum %d credentials allowed for this plan", phone.MaxConnections)})
		return
	}

	// Allocate a port
	port, err := allocatePort(&phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to allocate port"})
		return
	}

	// Generate password if userpass auth
	var password string
	if req.AuthType == "userpass" {
		bytes := make([]byte, 12)
		rand.Read(bytes)
		password = hex.EncodeToString(bytes)
	}

	// Generate username if not provided
	username := req.Username
	if req.AuthType == "userpass" && username == "" {
		bytes := make([]byte, 4)
		rand.Read(bytes)
		username = "user_" + hex.EncodeToString(bytes)
	}

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		exp := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = &exp
	}

	credential := models.ConnectionCredential{
		PhoneID:        phoneID,
		Name:           req.Name,
		AuthType:       models.AuthType(req.AuthType),
		ProxyType:      models.ProxyType(req.ProxyType),
		AllowedIP:      req.AllowedIP,
		Username:       username,
		Port:           port,
		IsActive:       true,
		BandwidthLimit: req.BandwidthLimit,
		ExpiresAt:      expiresAt,
	}

	// Store password (plain text for proxy credentials)
	if password != "" {
		credential.Password = password
	}

	if err := database.DB.Create(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
		return
	}

	// Return response with password (only shown once)
	response := credentialToResellerResponse(&credential, &phone, true)
	response.Password = password

	c.JSON(http.StatusCreated, response)
}

// DeleteResellerCredential deletes (revokes) a credential
func DeleteResellerCredential(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
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

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	var credential models.ConnectionCredential
	if err := database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).First(&credential).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	if err := database.DB.Delete(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete credential"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Credential deleted"})
}

// GetResellerRotation returns rotation settings and URL for a phone
func GetResellerRotation(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	// Get rotation token
	var token models.RotationToken
	hasToken := database.DB.Where("phone_id = ? AND is_active = ?", phoneID, true).First(&token).Error == nil

	response := gin.H{
		"rotation_mode":     phone.RotationMode,
		"rotation_interval": phone.RotationIntervalMinutes,
		"rotation_enabled":  phone.RotationMode != "" && phone.RotationMode != "off",
	}

	if hasToken {
		response["rotation_url"] = fmt.Sprintf("https://api.droidproxy.com/rotate/%s", token.Token)
		response["has_rotation_token"] = true
	} else {
		response["has_rotation_token"] = false
	}

	c.JSON(http.StatusOK, response)
}

// SetResellerRotation configures rotation settings for a phone
func SetResellerRotation(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	var req struct {
		Mode            string `json:"mode"`             // off, timed, api
		IntervalMinutes int    `json:"interval_minutes"` // For timed mode (2-120)
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate mode
	if req.Mode != "off" && req.Mode != "timed" && req.Mode != "api" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'off', 'timed', or 'api'"})
		return
	}

	updates := map[string]interface{}{
		"rotation_mode": req.Mode,
	}

	if req.Mode == "timed" {
		if req.IntervalMinutes < 2 || req.IntervalMinutes > 120 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "interval_minutes must be between 2 and 120"})
			return
		}
		updates["rotation_interval"] = req.IntervalMinutes
	}

	if err := database.DB.Model(&phone).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rotation settings"})
		return
	}

	// If API mode, ensure rotation token exists
	var token models.RotationToken
	var tokenEndpoint string
	if req.Mode == "api" {
		if err := database.DB.Where("phone_id = ? AND is_active = ?", phoneID, true).First(&token).Error; err != nil {
			// Create new token
			tokenBytes := make([]byte, 32)
			rand.Read(tokenBytes)
			tokenStr := hex.EncodeToString(tokenBytes)

			token = models.RotationToken{
				PhoneID:  phoneID,
				Token:    tokenStr,
				IsActive: true,
			}
			database.DB.Create(&token)
		}
		tokenEndpoint = fmt.Sprintf("https://api.droidproxy.com/rotate/%s", token.Token)
	}

	response := gin.H{
		"rotation_mode":     req.Mode,
		"rotation_interval": req.IntervalMinutes,
		"message":           "Rotation settings updated",
	}
	if tokenEndpoint != "" {
		response["rotation_url"] = tokenEndpoint
	}

	c.JSON(http.StatusOK, response)
}

// ResellerRotateIP triggers an IP rotation for a phone
func ResellerRotateIP(c *gin.Context) {
	apiKey := middleware.GetAPIKey(c)
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone access
	var phone models.Phone
	if err := database.DB.Preload("HubServer").
		Where("id = ? AND user_id = ?", phoneID, userID).
		Where("plan_tier = ? AND has_active_license = ?", "nitro", true).
		First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found or not eligible"})
		return
	}

	if !middleware.CanAccessPhone(apiKey, phoneID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API key does not have access to this phone"})
		return
	}

	// Send rotation command via Centrifugo
	if err := phonecomm.SendRotateIP(phoneID.String()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to trigger rotation: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "IP rotation triggered",
		"note":    "New IP will be reflected in phone status within 10-30 seconds",
	})
}

// Helper functions

func phoneToResellerResponse(phone *models.Phone) ResellerPhoneResponse {
	status := "offline"
	if phone.PairedAt == nil {
		status = "pending"
	}
	// Note: Real-time status would come from Centrifugo, not stored

	daysRemaining := 0
	expiresAt := ""
	if phone.LicenseExpiresAt != nil {
		expiresAt = phone.LicenseExpiresAt.Format(time.RFC3339)
		daysRemaining = int(math.Ceil(time.Until(*phone.LicenseExpiresAt).Hours() / 24))
		if daysRemaining < 0 {
			daysRemaining = 0
		}
	}

	serverLocation := ""
	serverIP := ""
	if phone.HubServer != nil {
		serverLocation = phone.HubServer.Location
		serverIP = phone.HubServer.IP
	}

	return ResellerPhoneResponse{
		ID:                phone.ID,
		Name:              phone.Name,
		Status:            status,
		PlanTier:          phone.PlanTier,
		PlanDaysRemaining: daysRemaining,
		LicenseExpiresAt:  expiresAt,
		MaxConnections:    phone.MaxConnections,
		SpeedLimitMbps:    phone.SpeedLimitMbps,
		ActiveConnections: phone.ActiveConnections,
		ServerLocation:    serverLocation,
		ServerIP:          serverIP,
		SIMCountry:        phone.SimCountry,
		SIMCarrier:        phone.SimCarrier,
		CreatedAt:         phone.CreatedAt.Format(time.RFC3339),
	}
}

func credentialToResellerResponse(cred *models.ConnectionCredential, phone *models.Phone, includePassword bool) ResellerCredentialResponse {
	expiresAt := ""
	if cred.ExpiresAt != nil {
		expiresAt = cred.ExpiresAt.Format(time.RFC3339)
	}

	proxyHost := ""
	if phone.HubServer != nil {
		proxyHost = phone.HubServer.IP
	}

	response := ResellerCredentialResponse{
		ID:             cred.ID,
		Name:           cred.Name,
		AuthType:       string(cred.AuthType),
		ProxyType:      string(cred.ProxyType),
		Username:       cred.Username,
		AllowedIP:      cred.AllowedIP,
		Port:           cred.Port,
		ProxyHost:      proxyHost,
		ExpiresAt:      expiresAt,
		IsActive:       cred.IsActive,
		BandwidthUsed:  cred.BandwidthUsed,
		BandwidthLimit: cred.BandwidthLimit,
		CreatedAt:      cred.CreatedAt.Format(time.RFC3339),
	}

	// Build connection URLs
	if proxyHost != "" && cred.Port > 0 {
		if cred.AuthType == "userpass" {
			if cred.ProxyType == "socks5" || cred.ProxyType == "both" {
				response.SOCKS5URL = fmt.Sprintf("socks5://%s:PASSWORD@%s:%d", cred.Username, proxyHost, cred.Port)
			}
			if cred.ProxyType == "http" || cred.ProxyType == "both" {
				response.HTTPURL = fmt.Sprintf("http://%s:PASSWORD@%s:%d", cred.Username, proxyHost, cred.Port)
			}
		} else {
			if cred.ProxyType == "socks5" || cred.ProxyType == "both" {
				response.SOCKS5URL = fmt.Sprintf("socks5://%s:%d", proxyHost, cred.Port)
			}
			if cred.ProxyType == "http" || cred.ProxyType == "both" {
				response.HTTPURL = fmt.Sprintf("http://%s:%d", proxyHost, cred.Port)
			}
		}
	}

	return response
}

// allocatePort finds an available port for a new credential
func allocatePort(phone *models.Phone) (int, error) {
	if phone.HubServer == nil {
		return 0, fmt.Errorf("phone has no hub server")
	}

	// Get used ports
	var usedPorts []int
	database.DB.Model(&models.ConnectionCredential{}).
		Joins("JOIN phones ON phones.id = connection_credentials.phone_id").
		Where("phones.hub_server_id = ?", phone.HubServerID).
		Pluck("port", &usedPorts)

	usedSet := make(map[int]bool)
	for _, p := range usedPorts {
		usedSet[p] = true
	}

	// Find first available port
	for port := phone.HubServer.ProxyPortStart; port <= phone.HubServer.ProxyPortEnd; port++ {
		if !usedSet[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports")
}
