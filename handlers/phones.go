package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/droidproxy/api/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreatePhoneRequest is the request body for creating a phone
type CreatePhoneRequest struct {
	Name     string `json:"name" binding:"required"`
	ServerID string `json:"server_id" binding:"required"`
}

// ListPhones returns all phones for the current user
func ListPhones(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var phones []models.Phone
	if err := database.DB.Preload("Server").Where("user_id = ?", userID).Find(&phones).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch phones"})
		return
	}

	responses := make([]models.PhoneResponse, len(phones))
	for i, phone := range phones {
		responses[i] = phone.ToResponse()
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
	serverID, err := uuid.Parse(req.ServerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// Verify server exists
	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Assign next available port
	proxyPort, err := getNextAvailablePort(&server)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No ports available on this server"})
		return
	}

	// Create phone
	phone := models.Phone{
		UserID:    userID,
		ServerID:  &serverID,
		Name:      req.Name,
		ProxyPort: proxyPort,
		Status:    models.StatusPending,
	}

	if err := database.DB.Create(&phone).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create phone"})
		return
	}

	// Generate QR code data with phone ID (for scanning)
	apiBaseURL := config.AppConfig.APIBaseURL
	qrData, _ := services.GetQRCodeDataString(apiBaseURL, phone.ID.String(), phone.PairingCode)

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
	if err := database.DB.Preload("Server").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"phone": phone.ToResponse()})
}

// DeletePhone removes a phone
func DeletePhone(c *gin.Context) {
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	result := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).Delete(&models.Phone{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone deleted"})
}

// RotateIP sends a rotate IP command to a phone
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

	if phone.Status != models.StatusOnline {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone is not online"})
		return
	}

	if err := services.SendRotateIP(phoneID.String()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send command"})
		return
	}

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

	if err := services.SendRestartProxy(phoneID.String()); err != nil {
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
func PairPhone(c *gin.Context) {
	var req models.PairingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var phone models.Phone
	if err := database.DB.Preload("Server").Where("pairing_code = ?", req.PairingCode).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invalid pairing code"})
		return
	}

	// Verify PIN
	if phone.PairingPIN != req.PairingPIN {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid PIN"})
		return
	}

	if phone.PairedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already paired"})
		return
	}

	// Generate WireGuard config for this phone
	wireGuardConfig := generateWireGuardConfig(&phone)

	// Update phone as paired
	now := time.Now()
	phone.PairedAt = &now
	phone.WireGuardConfig = wireGuardConfig
	phone.Status = models.StatusOffline
	database.DB.Save(&phone)

	// Generate Centrifugo token for this phone
	centrifugoToken, _ := services.GenerateClientToken(phone.ID.String(), "phone:"+phone.ID.String())

	c.JSON(http.StatusOK, models.PairingResponse{
		PhoneID:         phone.ID.String(),
		WireGuardConfig: wireGuardConfig,
		CentrifugoURL:   config.AppConfig.CentrifugoURL,
		CentrifugoToken: centrifugoToken,
		APIBaseURL:      config.AppConfig.APIBaseURL,
	})
}

// Heartbeat handles status updates from Android app
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

	var phone models.Phone
	if err := database.DB.First(&phone, "id = ?", phoneID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Update phone status
	now := time.Now()
	phone.LastSeen = &now
	phone.CurrentIP = req.CurrentIP
	if req.Status == "online" {
		phone.Status = models.StatusOnline
	}
	database.DB.Save(&phone)

	// Record stats
	stats := models.PhoneStats{
		PhoneID:           phoneID,
		ActiveConnections: req.ActiveConnections,
		TotalConnections:  req.TotalConnections,
	}
	database.DB.Create(&stats)

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
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
	database.DB.Preload("Server").Where("user_id = ? AND paired_at IS NULL", user.ID).Find(&phones)

	phoneInfos := make([]models.PhoneLoginInfo, len(phones))
	for i, p := range phones {
		serverName := ""
		if p.Server != nil {
			serverName = p.Server.Name
		}
		phoneInfos[i] = models.PhoneLoginInfo{
			ID:         p.ID.String(),
			Name:       p.Name,
			Status:     string(p.Status),
			ServerName: serverName,
		}
	}

	c.JSON(http.StatusOK, models.PhoneListForLoginResponse{Phones: phoneInfos})
}

// PhoneLogin handles login from Android app using email/password
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
	if err := database.DB.Preload("Server").Where("id = ? AND user_id = ?", phoneID, user.ID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	if phone.PairedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone already paired"})
		return
	}

	// Generate WireGuard config for this phone
	wireGuardConfig := generateWireGuardConfig(&phone)

	// Update phone as paired
	now := time.Now()
	phone.PairedAt = &now
	phone.WireGuardConfig = wireGuardConfig
	phone.Status = models.StatusOffline
	database.DB.Save(&phone)

	// Generate Centrifugo token for this phone
	centrifugoToken, _ := services.GenerateClientToken(phone.ID.String(), "phone:"+phone.ID.String())

	c.JSON(http.StatusOK, models.PairingResponse{
		PhoneID:         phone.ID.String(),
		WireGuardConfig: wireGuardConfig,
		CentrifugoURL:   config.AppConfig.CentrifugoURL,
		CentrifugoToken: centrifugoToken,
		APIBaseURL:      config.AppConfig.APIBaseURL,
	})
}

// Helper functions

func getNextAvailablePort(server *models.Server) (int, error) {
	var usedPorts []int
	database.DB.Model(&models.Phone{}).Where("server_id = ?", server.ID).Pluck("proxy_port", &usedPorts)

	usedSet := make(map[int]bool)
	for _, p := range usedPorts {
		usedSet[p] = true
	}

	for port := server.ProxyPortStart; port <= server.ProxyPortEnd; port++ {
		if !usedSet[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports")
}

func generateWireGuardConfig(phone *models.Phone) string {
	if phone.Server == nil {
		return ""
	}

	// This is a simplified config generator
	// In production, you'd integrate with the VPS provisioning API
	return fmt.Sprintf(`[Interface]
PrivateKey = <GENERATED_PRIVATE_KEY>
Address = 10.66.66.%d/32
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, phone.ProxyPort%200+10, phone.Server.IP, phone.Server.WireGuardPort)
}
