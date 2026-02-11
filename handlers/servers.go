package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/dns"
	"github.com/droidproxy/api/internal/infra"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateHubServerRequest is the request body for creating a hub server
type CreateHubServerRequest struct {
	Name           string `json:"name" binding:"required"`
	Location       string `json:"location" binding:"required"`
	IP             string `json:"ip" binding:"required"`
	WireGuardPort  int    `json:"wireguard_port"`
	ProxyPortStart int    `json:"proxy_port_start"`
	ProxyPortEnd   int    `json:"proxy_port_end"`
	HubAPIKey      string `json:"hub_api_key"`  // Hub Agent API key
	HubAPIPort     int    `json:"hub_api_port"` // Hub Agent API port
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SSHPassword    string `json:"ssh_password"`
	DNSSubdomain   string `json:"dns_subdomain"` // Server subdomain (e.g., "x1" for x1.yalx.in)
}

// UpdateHubServerRequest is the request body for updating a hub server
type UpdateHubServerRequest struct {
	Name           string `json:"name"`
	Location       string `json:"location"`
	IP             string `json:"ip"`
	WireGuardPort  int    `json:"wireguard_port"`
	ProxyPortStart int    `json:"proxy_port_start"`
	ProxyPortEnd   int    `json:"proxy_port_end"`
	HubAPIKey      string `json:"hub_api_key"`
	HubAPIPort     int    `json:"hub_api_port"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SSHPassword    string `json:"ssh_password"`
	IsActive       *bool  `json:"is_active"`
	DNSSubdomain   string `json:"dns_subdomain"` // Server subdomain (e.g., "x1" for x1.yalx.in)
}

// Legacy type aliases for backwards compatibility
type CreateServerRequest = CreateHubServerRequest
type UpdateServerRequest = UpdateHubServerRequest

// FailoverRequest is the request body for server failover
type FailoverRequest struct {
	TargetServerID string `json:"target_server_id" binding:"required"` // Server to failover to
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

// ListServers returns all hub servers
// Regular users see only location, admins see full details
func ListServers(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var servers []models.HubServer
	if err := database.DB.Preload("Phones").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}

	if user.IsAdmin() {
		// Return full details for admins
		responses := make([]models.HubServerAdminResponse, len(servers))
		for i, server := range servers {
			responses[i] = server.ToAdminResponse()
		}
		c.JSON(http.StatusOK, gin.H{"servers": responses})
	} else {
		// Return limited info for regular users
		responses := make([]models.HubServerResponse, len(servers))
		for i, server := range servers {
			responses[i] = server.ToResponse()
		}
		c.JSON(http.StatusOK, gin.H{"servers": responses})
	}
}

// CreateServer creates a new hub server (admin only)
func CreateServer(c *gin.Context) {
	var req CreateHubServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server := models.HubServer{
		Name:           req.Name,
		Location:       req.Location,
		IP:             req.IP,
		WireGuardPort:  req.WireGuardPort,
		ProxyPortStart: req.ProxyPortStart,
		ProxyPortEnd:   req.ProxyPortEnd,
		HubAPIKey:      req.HubAPIKey,
		HubAPIPort:     req.HubAPIPort,
		SSHPort:        req.SSHPort,
		SSHUser:        req.SSHUser,
		SSHPassword:    req.SSHPassword,
		DNSSubdomain:   req.DNSSubdomain,
		IsActive:       true,
	}

	// Set defaults
	if server.WireGuardPort == 0 {
		server.WireGuardPort = 51820
	}
	if server.ProxyPortStart == 0 {
		server.ProxyPortStart = 20001
	}
	if server.ProxyPortEnd == 0 {
		server.ProxyPortEnd = 20100
	}
	if server.HubAPIPort == 0 {
		server.HubAPIPort = 8081
	}
	if server.SSHPort == 0 {
		server.SSHPort = 22
	}
	if server.SSHUser == "" {
		server.SSHUser = "root"
	}

	// Create DNS A record if subdomain is provided and DNS manager is configured
	if req.DNSSubdomain != "" {
		dnsManager := dns.GetManager()
		if dnsManager != nil {
			dnsRecord, err := dnsManager.CreateServerRecord(req.DNSSubdomain, req.IP)
			if err != nil {
				log.Printf("[CreateServer] Failed to create DNS record: %v", err)
				// Continue without DNS - not a fatal error
			} else {
				server.DNSDomain = dnsRecord.FullDomain
				server.DNSRecordID = dnsRecord.RecordID
				log.Printf("[CreateServer] Created DNS record: %s -> %s", dnsRecord.FullDomain, req.IP)
			}
		}
	}

	if err := database.DB.Create(&server).Error; err != nil {
		// Cleanup DNS record if creation failed
		if server.DNSRecordID != 0 {
			dnsManager := dns.GetManager()
			if dnsManager != nil {
				dnsManager.DeleteServerRecord(server.DNSRecordID)
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"server": server.ToAdminResponse()})
}

// GetServer returns a specific hub server
func GetServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	user := middleware.GetCurrentUser(c)

	var server models.HubServer
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

// UpdateServer updates a hub server (admin only)
func UpdateServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req UpdateHubServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.HubServer
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Track if IP changed for DNS update
	ipChanged := req.IP != "" && req.IP != server.IP
	oldIP := server.IP

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
	if req.HubAPIKey != "" {
		server.HubAPIKey = req.HubAPIKey
	}
	if req.HubAPIPort != 0 {
		server.HubAPIPort = req.HubAPIPort
	}
	if req.SSHPassword != "" {
		server.SSHPassword = req.SSHPassword
	}
	if req.IsActive != nil {
		server.IsActive = *req.IsActive
	}

	// Handle DNS subdomain changes
	dnsManager := dns.GetManager()
	if req.DNSSubdomain != "" && req.DNSSubdomain != server.DNSSubdomain {
		// Subdomain is being changed or set for first time
		if dnsManager != nil {
			// Delete old DNS record if exists
			if server.DNSRecordID != 0 {
				if err := dnsManager.DeleteServerRecord(server.DNSRecordID); err != nil {
					log.Printf("[UpdateServer] Failed to delete old DNS record: %v", err)
				}
			}
			// Create new DNS record
			ip := server.IP
			if req.IP != "" {
				ip = req.IP
			}
			dnsRecord, err := dnsManager.CreateServerRecord(req.DNSSubdomain, ip)
			if err != nil {
				log.Printf("[UpdateServer] Failed to create DNS record: %v", err)
			} else {
				server.DNSSubdomain = req.DNSSubdomain
				server.DNSDomain = dnsRecord.FullDomain
				server.DNSRecordID = dnsRecord.RecordID
				log.Printf("[UpdateServer] Created DNS record: %s -> %s", dnsRecord.FullDomain, ip)
			}
		}
	} else if ipChanged && server.DNSRecordID != 0 && dnsManager != nil {
		// IP changed, update existing DNS record
		if err := dnsManager.UpdateServerRecord(server.DNSRecordID, server.DNSSubdomain, req.IP); err != nil {
			log.Printf("[UpdateServer] Failed to update DNS record: %v (old IP: %s, new IP: %s)", err, oldIP, req.IP)
		} else {
			log.Printf("[UpdateServer] Updated DNS record: %s -> %s", server.DNSDomain, req.IP)
		}
	}

	if err := database.DB.Save(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update server"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"server": server.ToAdminResponse()})
}

// DeleteServer removes a hub server (admin only)
func DeleteServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// Check if server has phones
	var phoneCount int64
	database.DB.Model(&models.Phone{}).Where("hub_server_id = ?", serverID).Count(&phoneCount)
	if phoneCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete server with active phones"})
		return
	}

	result := database.DB.Delete(&models.HubServer{}, "id = ?", serverID)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Server deleted"})
}

// getSSHClient creates an SSH client for a hub server
func getSSHClient(server *models.HubServer) (*infra.SSHClient, error) {
	if server.SSHPassword == "" {
		return nil, nil
	}
	client := infra.NewSSHClient(server.IP, server.SSHPort, server.SSHUser, server.SSHPassword)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// TestSSHConnection tests SSH connection to a hub server (admin only)
func TestSSHConnection(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var server models.HubServer
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

// RunSSHCommand runs a command on a hub server (admin only)
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

	var server models.HubServer
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

// SetupServer runs the full hub server setup (admin only)
func SetupServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var server models.HubServer
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

	var server models.HubServer
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

	var server models.HubServer
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

	var server models.HubServer
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

	var server models.HubServer
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

// FailoverServer redirects all phones from this server to a target server (admin only)
// This updates all CNAME records to point to the new server
func FailoverServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req FailoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targetServerID, err := uuid.Parse(req.TargetServerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid target server ID"})
		return
	}

	// Get source server
	var sourceServer models.HubServer
	if err := database.DB.First(&sourceServer, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Source server not found"})
		return
	}

	// Get target server
	var targetServer models.HubServer
	if err := database.DB.First(&targetServer, "id = ?", targetServerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target server not found"})
		return
	}

	// Validate DNS is configured
	if targetServer.DNSSubdomain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Target server has no DNS subdomain configured"})
		return
	}

	dnsManager := dns.GetManager()
	if dnsManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNS manager not configured"})
		return
	}

	// Get all phones on the source server that have DNS records
	var phones []models.Phone
	if err := database.DB.Where("hub_server_id = ? AND dns_record_id != 0", serverID).Find(&phones).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch phones"})
		return
	}

	if len(phones) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message":   "No phones with DNS records to failover",
			"succeeded": 0,
			"failed":    0,
		})
		return
	}

	// Build list of DNS records to update
	var records []dns.ProxyDNSRecord
	for _, phone := range phones {
		records = append(records, dns.ProxyDNSRecord{
			Subdomain:  phone.ProxySubdomain,
			FullDomain: phone.ProxyDomain,
			RecordID:   phone.DNSRecordID,
		})
	}

	// Perform bulk failover
	succeeded, failed := dnsManager.BulkFailover(records, targetServer.DNSSubdomain)

	// Update phone records to point to new server (optional - depends on whether you want to track the change)
	// For now, we'll just update the DNS records, not the phone's server_id
	// This allows the original association to remain while traffic is redirected

	log.Printf("[FailoverServer] Failover from %s to %s: %d succeeded, %d failed",
		sourceServer.Name, targetServer.Name, succeeded, failed)

	c.JSON(http.StatusOK, gin.H{
		"message":   "Failover completed",
		"succeeded": succeeded,
		"failed":    failed,
		"source":    sourceServer.Name,
		"target":    targetServer.Name,
	})
}

// SetupServerDNS creates a DNS A record for a server that doesn't have one (admin only)
func SetupServerDNS(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	type SetupDNSRequest struct {
		DNSSubdomain string `json:"dns_subdomain" binding:"required"`
	}

	var req SetupDNSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var server models.HubServer
	if err := database.DB.First(&server, "id = ?", serverID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.DNSRecordID != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Server already has a DNS record"})
		return
	}

	dnsManager := dns.GetManager()
	if dnsManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNS manager not configured"})
		return
	}

	dnsRecord, err := dnsManager.CreateServerRecord(req.DNSSubdomain, server.IP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DNS record: " + err.Error()})
		return
	}

	server.DNSSubdomain = req.DNSSubdomain
	server.DNSDomain = dnsRecord.FullDomain
	server.DNSRecordID = dnsRecord.RecordID

	if err := database.DB.Save(&server).Error; err != nil {
		// Cleanup DNS record
		dnsManager.DeleteServerRecord(dnsRecord.RecordID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update server"})
		return
	}

	log.Printf("[SetupServerDNS] Created DNS record: %s -> %s", dnsRecord.FullDomain, server.IP)

	c.JSON(http.StatusOK, gin.H{
		"message":    "DNS record created",
		"dns_domain": dnsRecord.FullDomain,
		"server":     server.ToAdminResponse(),
	})
}
