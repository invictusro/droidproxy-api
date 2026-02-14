package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// SyncState structures for hub-agent communication

type SyncPeer struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
}

type SyncCredential struct {
	ID              string   `json:"id"`
	AuthType        string   `json:"auth_type"`
	AllowedIP       string   `json:"allowed_ip,omitempty"`
	Username        string   `json:"username,omitempty"`
	PasswordHash    string   `json:"password_hash,omitempty"`
	LimitBytes      uint64   `json:"limit_bytes"`
	ConnectionLimit int      `json:"connection_limit"` // Max unique IPs (30min TTL), 0 = unlimited
	BlockedDomains  []string `json:"blocked_domains,omitempty"`
	UdpEnabled      bool     `json:"udp_enabled"` // Enable UDP ASSOCIATE for SOCKS5
}

type SyncProxy struct {
	PhoneID        string           `json:"phone_id"`
	Port           int              `json:"port"`
	TargetIP       string           `json:"target_ip"`
	TargetPort     int              `json:"target_port"`
	Credentials    []SyncCredential `json:"credentials"`
	SpeedLimitMbps int              `json:"speed_limit_mbps"` // Plan speed limit in Mbps (0 = unlimited)
	MaxConnections int              `json:"max_connections"`  // Plan max unique IPs (0 = unlimited)
}

type SyncState struct {
	Peers   []SyncPeer  `json:"peers"`
	Proxies []SyncProxy `json:"proxies"`
}

// UsageReport represents bandwidth usage for a credential
type UsageReport struct {
	CredentialID    string `json:"credential_id"`
	PhoneID         string `json:"phone_id"`
	BytesIn         uint64 `json:"bytes_in"`
	BytesOut        uint64 `json:"bytes_out"`
	ConnectionCount uint64 `json:"connection_count"`
}

// UsageBatch represents a batch of usage reports from a hub
type UsageBatch struct {
	HubID            string             `json:"hub_id"`
	Timestamp        time.Time          `json:"timestamp"`
	Reports          []UsageReport      `json:"reports"`
	PhoneConnections []PhoneActiveConns `json:"phone_connections,omitempty"` // Real-time unique IPs per phone
}

// PhoneActiveConns represents current active connections for a phone
type PhoneActiveConns struct {
	PhoneID           string `json:"phone_id"`
	ActiveConnections int    `json:"active_connections"` // Current unique IPs (30-min TTL)
}

// GetHubSyncState returns the full state for a hub to restore after reboot
// GET /api/internal/hubs/:id/sync-state
func GetHubSyncState(c *gin.Context) {
	hubID := c.Param("id")

	// Verify hub exists and API key matches
	var server models.HubServer
	if err := database.DB.Where("id = ?", hubID).First(&server).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hub not found"})
		return
	}

	// Verify API key
	apiKey := c.GetHeader("X-API-Key")
	if apiKey != server.HubAPIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Get all paired phones on this hub
	var phones []models.Phone
	if err := database.DB.Where("hub_server_id = ? AND paired_at IS NOT NULL", hubID).
		Find(&phones).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch phones"})
		return
	}

	// Build sync state
	state := SyncState{
		Peers:   make([]SyncPeer, 0),
		Proxies: make([]SyncProxy, 0),
	}

	for _, phone := range phones {
		// Add WireGuard peer
		if phone.WireGuardPublicKey != "" && phone.WireGuardIP != "" {
			state.Peers = append(state.Peers, SyncPeer{
				PublicKey: phone.WireGuardPublicKey,
				AllowedIP: phone.WireGuardIP,
			})
		}

		// Add one proxy per credential (each credential has its own port now)
		if phone.WireGuardIP != "" {
			var credentials []models.ConnectionCredential
			database.DB.Where("phone_id = ? AND is_active = ? AND port > 0", phone.ID, true).Find(&credentials)

			for _, cred := range credentials {
				syncCred := SyncCredential{
					ID:              cred.ID.String(),
					AuthType:        string(cred.AuthType),
					LimitBytes:      uint64(cred.BandwidthLimit),
					ConnectionLimit: cred.ConnectionLimit,
					BlockedDomains:  cred.BlockedDomains,
					UdpEnabled:      cred.UdpEnabled,
				}

				if cred.AuthType == models.AuthTypeIP {
					syncCred.AllowedIP = cred.AllowedIP
				} else if cred.AuthType == models.AuthTypeUserPass {
					syncCred.Username = cred.Username
					syncCred.PasswordHash = cred.Password
				}

				proxy := SyncProxy{
					PhoneID:        phone.ID.String(),
					Port:           cred.Port,
					TargetIP:       phone.WireGuardIP,
					TargetPort:     1080, // SOCKS5 port on phone
					Credentials:    []SyncCredential{syncCred},
					SpeedLimitMbps: phone.SpeedLimitMbps,  // From plan
					MaxConnections: phone.MaxConnections,  // From plan
				}

				state.Proxies = append(state.Proxies, proxy)
			}
		}
	}

	c.JSON(http.StatusOK, state)
}

// ReportHubReady marks a hub as ready after startup
// POST /api/internal/hubs/:id/ready
func ReportHubReady(c *gin.Context) {
	hubID := c.Param("id")

	// Verify hub exists and API key matches
	var server models.HubServer
	if err := database.DB.Where("id = ?", hubID).First(&server).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hub not found"})
		return
	}

	// Verify API key
	apiKey := c.GetHeader("X-API-Key")
	if apiKey != server.HubAPIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Update last heartbeat to mark as ready
	now := time.Now()
	database.DB.Model(&server).Update("last_heartbeat", &now)

	c.JSON(http.StatusOK, gin.H{"message": "Hub marked as ready"})
}

// HubHeartbeat receives heartbeat from hub-agent
// POST /api/hub/heartbeat
func HubHeartbeat(c *gin.Context) {
	var payload struct {
		HubID             string    `json:"hub_id"`
		Version           string    `json:"version"` // Hub agent version (OTA tracking)
		Timestamp         time.Time `json:"timestamp"`
		Health            struct {
			CPUPercent    float64 `json:"cpu_percent"`
			MemoryPercent float64 `json:"memory_percent"`
			DiskPercent   float64 `json:"disk_percent"`
		} `json:"health"`
		ActiveConnections int    `json:"active_connections"`
		WireGuardStatus   string `json:"wireguard_status"`
		WireGuardPeers    int    `json:"wireguard_peers"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update hub server record
	now := time.Now()
	updates := map[string]interface{}{
		"last_heartbeat": &now,
		"cpu_percent":    payload.Health.CPUPercent,
		"memory_percent": payload.Health.MemoryPercent,
	}

	// Include version if provided
	if payload.Version != "" {
		updates["current_version"] = payload.Version
	}

	database.DB.Model(&models.HubServer{}).
		Where("id = ?", payload.HubID).
		Updates(updates)

	c.JSON(http.StatusOK, gin.H{"message": "Heartbeat received"})
}

// HubConnectionLogs receives connection logs from hub-agent
// POST /api/hub/connections
func HubConnectionLogs(c *gin.Context) {
	var payload struct {
		HubID       string `json:"hub_id"`
		Connections []struct {
			PhoneID   string `json:"phone_id"`
			ClientIP  string `json:"client_ip"`
			Target    string `json:"target"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			BytesIn   int64  `json:"bytes_in"`
			BytesOut  int64  `json:"bytes_out"`
		} `json:"connections"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For now, just log - could store in database for analytics
	// log.Printf("Received %d connection logs from hub %s", len(payload.Connections), payload.HubID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Connection logs received",
		"count":   len(payload.Connections),
	})
}

// ReportUsage receives bandwidth usage reports from a hub
// POST /api/internal/usage
func ReportUsage(c *gin.Context) {
	var batch UsageBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify hub exists
	var server models.HubServer
	if err := database.DB.Where("id = ?", batch.HubID).First(&server).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hub not found"})
		return
	}

	// Verify API key (accept both X-API-Key and X-Hub-API-Key headers)
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		apiKey = c.GetHeader("X-Hub-API-Key")
	}
	if apiKey != server.HubAPIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Apply 1.1x multiplier for VPN overhead
	const overheadMultiplier = 1.1

	// Aggregate usage by phone for daily tracking
	phoneUsage := make(map[string]struct {
		BytesIn  int64
		BytesOut int64
	})

	// Update bandwidth usage and connection count for each credential
	for _, report := range batch.Reports {
		adjustedIn := uint64(float64(report.BytesIn) * overheadMultiplier)
		adjustedOut := uint64(float64(report.BytesOut) * overheadMultiplier)

		// Update credential bandwidth usage and connection count
		database.DB.Model(&models.ConnectionCredential{}).
			Where("id = ?", report.CredentialID).
			Updates(map[string]interface{}{
				"bandwidth_used":   database.DB.Raw("bandwidth_used + ?", adjustedIn+adjustedOut),
				"connection_count": database.DB.Raw("connection_count + ?", report.ConnectionCount),
			})

		// Aggregate by phone for daily usage tracking
		if usage, ok := phoneUsage[report.PhoneID]; ok {
			usage.BytesIn += int64(adjustedIn)
			usage.BytesOut += int64(adjustedOut)
			phoneUsage[report.PhoneID] = usage
		} else {
			phoneUsage[report.PhoneID] = struct {
				BytesIn  int64
				BytesOut int64
			}{int64(adjustedIn), int64(adjustedOut)}
		}
	}

	// Update PhoneDataUsage table for daily tracking
	today := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.UTC)
	for phoneID, usage := range phoneUsage {
		// Upsert daily usage record
		var existing models.PhoneDataUsage
		result := database.DB.Where("phone_id = ? AND date = ?", phoneID, today).First(&existing)
		if result.Error != nil {
			// Create new record
			database.DB.Create(&models.PhoneDataUsage{
				PhoneID:  mustParseUUID(phoneID),
				Date:     today,
				BytesIn:  usage.BytesIn,
				BytesOut: usage.BytesOut,
			})
		} else {
			// Update existing record
			database.DB.Model(&existing).Updates(map[string]interface{}{
				"bytes_in":  database.DB.Raw("bytes_in + ?", usage.BytesIn),
				"bytes_out": database.DB.Raw("bytes_out + ?", usage.BytesOut),
			})
		}
	}

	// Update per-phone active connections (real-time unique IPs from hub)
	for _, phoneConn := range batch.PhoneConnections {
		database.DB.Model(&models.Phone{}).
			Where("id = ?", phoneConn.PhoneID).
			Update("active_connections", phoneConn.ActiveConnections)
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":       "Usage reported",
		"count":         len(batch.Reports),
		"phones_updated": len(batch.PhoneConnections),
	})
}

// mustParseUUID parses a UUID string, returning uuid.Nil if invalid
func mustParseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}

// ReceiveAccessLogs receives access logs from hub-agent
// POST /api/internal/access-logs
func ReceiveAccessLogs(c *gin.Context) {
	var batch models.AccessLogBatchRequest
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify hub exists
	var server models.HubServer
	if err := database.DB.Where("id = ?", batch.HubID).First(&server).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hub not found"})
		return
	}

	// Verify API key
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		apiKey = c.GetHeader("X-Hub-API-Key")
	}
	if apiKey != server.HubAPIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Batch insert access logs
	if len(batch.Logs) > 0 {
		accessLogs := make([]models.AccessLog, 0, len(batch.Logs))
		for _, entry := range batch.Logs {
			accessLogs = append(accessLogs, models.AccessLog{
				CredentialID: mustParseUUID(entry.CredentialID),
				PhoneID:      mustParseUUID(entry.PhoneID),
				HubServerID:  mustParseUUID(batch.HubID),
				ClientIP:     entry.ClientIP,
				Domain:       entry.Domain,
				Port:         entry.Port,
				Protocol:     entry.Protocol,
				BytesIn:      int64(entry.BytesIn),
				BytesOut:     int64(entry.BytesOut),
				DurationMS:   entry.DurationMS,
				Blocked:      entry.Blocked,
				Timestamp:    entry.Timestamp,
			})
		}

		// Bulk insert
		if err := database.DB.CreateInBatches(accessLogs, 100).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store access logs"})
			return
		}
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Access logs received",
		"count":   len(batch.Logs),
	})
}

// DownloadHubAgent serves the hub-agent binary for OTA updates
// GET /api/hub/downloads/hub-agent
// Protected by hub API key authentication
func DownloadHubAgent(c *gin.Context) {
	// Verify hub authentication (X-API-Key header)
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing API key"})
		return
	}

	// Verify this is a valid hub key
	var server models.HubServer
	if err := database.DB.Where("hub_api_key = ?", apiKey).First(&server).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Serve the binary
	binaryPath := "/app/binaries/hub-agent-linux-amd64"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Binary not found"})
		return
	}

	c.FileAttachment(binaryPath, "hub-agent")
}
