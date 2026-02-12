package handlers

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
)

// SyncState structures for hub-agent communication

type SyncPeer struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
}

type SyncCredential struct {
	ID             string   `json:"id"`
	AuthType       string   `json:"auth_type"`
	AllowedIP      string   `json:"allowed_ip,omitempty"`
	Username       string   `json:"username,omitempty"`
	PasswordHash   string   `json:"password_hash,omitempty"`
	LimitBytes     uint64   `json:"limit_bytes"`
	BlockedDomains []string `json:"blocked_domains,omitempty"`
}

type SyncProxy struct {
	PhoneID     string           `json:"phone_id"`
	Port        int              `json:"port"`
	TargetIP    string           `json:"target_ip"`
	TargetPort  int              `json:"target_port"`
	Credentials []SyncCredential `json:"credentials"`
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
	HubID     string        `json:"hub_id"`
	Timestamp time.Time     `json:"timestamp"`
	Reports   []UsageReport `json:"reports"`
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

		// Add proxy if phone has a port assigned
		if phone.ProxyPort > 0 && phone.WireGuardIP != "" {
			proxy := SyncProxy{
				PhoneID:     phone.ID.String(),
				Port:        phone.ProxyPort,
				TargetIP:    phone.WireGuardIP,
				TargetPort:  1080, // SOCKS5 port on phone
				Credentials: make([]SyncCredential, 0),
			}

			// Query credentials for this phone
			var credentials []models.ConnectionCredential
			database.DB.Where("phone_id = ? AND is_active = ?", phone.ID, true).Find(&credentials)

			// Add credentials
			for _, cred := range credentials {
				syncCred := SyncCredential{
					ID:             cred.ID.String(),
					AuthType:       string(cred.AuthType),
					LimitBytes:     uint64(cred.BandwidthLimit),
					BlockedDomains: cred.BlockedDomains,
				}

				if cred.AuthType == models.AuthTypeIP {
					syncCred.AllowedIP = cred.AllowedIP
				} else if cred.AuthType == models.AuthTypeUserPass {
					syncCred.Username = cred.Username
					syncCred.PasswordHash = cred.Password // Already hashed in DB
				}

				proxy.Credentials = append(proxy.Credentials, syncCred)
			}

			state.Proxies = append(state.Proxies, proxy)
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
	database.DB.Model(&models.HubServer{}).
		Where("id = ?", payload.HubID).
		Updates(map[string]interface{}{
			"last_heartbeat": &now,
			"cpu_percent":    payload.Health.CPUPercent,
			"memory_percent": payload.Health.MemoryPercent,
		})

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

	// Verify API key
	apiKey := c.GetHeader("X-API-Key")
	if apiKey != server.HubAPIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Apply 1.1x multiplier for VPN overhead
	const overheadMultiplier = 1.1

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
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Usage reported",
		"count":   len(batch.Reports),
	})
}
