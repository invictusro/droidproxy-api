package handlers

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/infra"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateServerRequest is the request body for creating a server
type CreateServerRequest struct {
	Name           string `json:"name" binding:"required"`
	Location       string `json:"location" binding:"required"`
	IP             string `json:"ip" binding:"required"`
	WireGuardPort  int    `json:"wireguard_port"`
	ProxyPortStart int    `json:"proxy_port_start"`
	ProxyPortEnd   int    `json:"proxy_port_end"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SSHPassword    string `json:"ssh_password"`
}

// UpdateServerRequest is the request body for updating a server
type UpdateServerRequest struct {
	Name           string `json:"name"`
	Location       string `json:"location"`
	IP             string `json:"ip"`
	WireGuardPort  int    `json:"wireguard_port"`
	ProxyPortStart int    `json:"proxy_port_start"`
	ProxyPortEnd   int    `json:"proxy_port_end"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SSHPassword    string `json:"ssh_password"`
	IsActive       *bool  `json:"is_active"`
}

// SSHCommandRequest is the request body for running SSH commands
type SSHCommandRequest struct {
	Command string `json:"command" binding:"required"`
}

// HTTPProxyRequest is the request body for managing HTTP proxies
type HTTPProxyRequest struct {
	PhoneID  string `json:"phone_id" binding:"required"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// FirewallRuleRequest is the request body for firewall rules
type FirewallRuleRequest struct {
	Port     int    `json:"port" binding:"required"`
	Protocol string `json:"protocol" binding:"required"`
	Action   string `json:"action" binding:"required"` // allow, deny, delete
}

// ListServers returns all servers
// Regular users see only location, admins see full details
func ListServers(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var servers []models.Server
	if err := database.DB.Preload("Phones").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}

	if user.IsAdmin() {
		// Return full details for admins
		responses := make([]models.ServerAdminResponse, len(servers))
		for i, server := range servers {
			responses[i] = server.ToAdminResponse()
		}
		c.JSON(http.StatusOK, gin.H{"servers": responses})
	} else {
		// Return limited info for regular users
		responses := make([]models.ServerResponse, len(servers))
		for i, server := range servers {
			responses[i] = server.ToResponse()
		}
		c.JSON(http.StatusOK, gin.H{"servers": responses})
	}
}

// CreateServer creates a new server (admin only)
func CreateServer(c *gin.Context) {
	var req CreateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server := models.Server{
		Name:           req.Name,
		Location:       req.Location,
		IP:             req.IP,
		WireGuardPort:  req.WireGuardPort,
		ProxyPortStart: req.ProxyPortStart,
		ProxyPortEnd:   req.ProxyPortEnd,
		SSHPort:        req.SSHPort,
		SSHUser:        req.SSHUser,
		SSHPassword:    req.SSHPassword,
		IsActive:       true,
	}

	// Set defaults
	if server.WireGuardPort == 0 {
		server.WireGuardPort = 51820
	}
	if server.ProxyPortStart == 0 {
		server.ProxyPortStart = 10001
	}
	if server.ProxyPortEnd == 0 {
		server.ProxyPortEnd = 10100
	}
	if server.SSHPort == 0 {
		server.SSHPort = 22
	}
	if server.SSHUser == "" {
		server.SSHUser = "root"
	}

	if err := database.DB.Create(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"server": server.ToAdminResponse()})
}

// GetServer returns a specific server
func GetServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	user := middleware.GetCurrentUser(c)

	var server models.Server
	if err := database.DB.Preload("Phones").First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if user.IsAdmin() {
		c.JSON(http.StatusOK, gin.H{"server": server.ToAdminResponse()})
	} else {
		c.JSON(http.StatusOK, gin.H{"server": server.ToResponse()})
	}
}

// UpdateServer updates a server (admin only)
func UpdateServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req UpdateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		server.Name = req.Name
	}
	if req.Location != "" {
		server.Location = req.Location
	}
	if req.IP != "" {
		server.IP = req.IP
	}
	if req.WireGuardPort != 0 {
		server.WireGuardPort = req.WireGuardPort
	}
	if req.ProxyPortStart != 0 {
		server.ProxyPortStart = req.ProxyPortStart
	}
	if req.ProxyPortEnd != 0 {
		server.ProxyPortEnd = req.ProxyPortEnd
	}
	if req.SSHPort != 0 {
		server.SSHPort = req.SSHPort
	}
	if req.SSHUser != "" {
		server.SSHUser = req.SSHUser
	}
	if req.SSHPassword != "" {
		server.SSHPassword = req.SSHPassword
	}
	if req.IsActive != nil {
		server.IsActive = *req.IsActive
	}

	if err := database.DB.Save(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update server"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"server": server.ToAdminResponse()})
}

// DeleteServer removes a server (admin only)
func DeleteServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// Check if server has phones
	var phoneCount int64
	database.DB.Model(&models.Phone{}).Where("server_id = ?", serverID).Count(&phoneCount)
	if phoneCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete server with active phones"})
		return
	}

	result := database.DB.Delete(&models.Server{}, "id = ?", serverID)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Server deleted"})
}

// getSSHClient creates an SSH client for a server
func getSSHClient(server *models.Server) (*infra.SSHClient, error) {
	if server.SSHPassword == "" {
		return nil, nil
	}
	client := infra.NewSSHClient(server.IP, server.SSHPort, server.SSHUser, server.SSHPassword)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// TestSSHConnection tests SSH connection to a server (admin only)
func TestSSHConnection(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.SSHPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}

	client := infra.NewSSHClient(server.IP, server.SSHPort, server.SSHUser, server.SSHPassword)
	if err := client.TestConnection(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	defer client.Close()

	// Update last check time
	now := time.Now()
	server.LastCheckAt = &now
	database.DB.Save(&server)

	c.JSON(http.StatusOK, gin.H{"message": "SSH connection successful"})
}

// RunSSHCommand runs a command on a server (admin only)
func RunSSHCommand(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req SSHCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	result, err := client.Run(req.Command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Command execution failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

// SetupServer runs the full server setup (admin only)
func SetupServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	setup := infra.NewServerSetup(client)
	if err := setup.FullSetup(server.ProxyPortStart, server.ProxyPortEnd); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server setup failed: " + err.Error()})
		return
	}

	// Mark server as set up
	server.IsSetup = true
	now := time.Now()
	server.LastCheckAt = &now
	database.DB.Save(&server)

	c.JSON(http.StatusOK, gin.H{"message": "Server setup completed successfully"})
}

// StartHTTPProxy starts an HTTP proxy for a phone (admin only)
func StartHTTPProxy(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req HTTPProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Find the phone to get its SOCKS5 port
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

	if phone.ProxyPort == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone has no proxy port assigned"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	httpPort := phone.ProxyPort + 7000
	proxyManager := infra.NewGostManager(client)
	result, err := proxyManager.StartProxy(req.PhoneID, phone.ProxyPort, httpPort, req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start HTTP proxy: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":   "HTTP proxy started",
		"http_port": httpPort,
		"result":    result,
	})
}

// StopHTTPProxy stops an HTTP proxy for a phone (admin only)
func StopHTTPProxy(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	phoneID := c.Param("phone_id")
	if phoneID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone ID is required"})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	proxyManager := infra.NewGostManager(client)
	result, err := proxyManager.StopProxy(phoneID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stop HTTP proxy: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "HTTP proxy stopped", "result": result})
}

// ManageFirewall manages firewall rules on a server (admin only)
func ManageFirewall(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req FirewallRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	firewall := infra.NewFirewallManager(client)

	var result *infra.CommandResult
	switch req.Action {
	case "allow":
		result, err = firewall.AllowPort(req.Port, req.Protocol)
	case "deny":
		result, err = firewall.DenyPort(req.Port, req.Protocol)
	case "delete":
		result, err = firewall.DeleteRule(req.Port, req.Protocol)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action. Use: allow, deny, or delete"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Firewall operation failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Firewall rule applied", "result": result})
}

// GetFirewallStatus gets the firewall status of a server (admin only)
func GetFirewallStatus(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var server models.Server
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	client, err := getSSHClient(&server)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	if client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No SSH credentials configured"})
		return
	}
	defer client.Close()

	firewall := infra.NewFirewallManager(client)
	result, err := firewall.GetStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get firewall status: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": result})
}
