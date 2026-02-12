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
	ID           string `json:"id"`
	AuthType     string `json:"auth_type"`
	AllowedIP    string `json:"allowed_ip,omitempty"`
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	LimitBytes   uint64 `json:"limit_bytes"`
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
	CredentialID string `json:"credential_id"`
	PhoneID      string `json:"phone_id"`
	BytesIn      uint64 `json:"bytes_in"`
	BytesOut     uint64 `json:"bytes_out"`
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
		Preload("ConnectionCredentials").
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

			// Add credentials
			for _, cred := range phone.ConnectionCredentials {
				if !cred.IsActive {
					continue
				}

				syncCred := SyncCredential{
					ID:         cred.ID.String(),
					AuthType:   cred.AuthType,
					LimitBytes: uint64(cred.BandwidthLimit),
				}

				if cred.AuthType == "ip" {
					syncCred.AllowedIP = cred.AllowedIP
				} else if cred.AuthType == "userpass" {
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

	// Update bandwidth usage for each credential
	for _, report := range batch.Reports {
		adjustedIn := uint64(float64(report.BytesIn) * overheadMultiplier)
		adjustedOut := uint64(float64(report.BytesOut) * overheadMultiplier)

		// Update credential bandwidth usage
		database.DB.Model(&models.ConnectionCredential{}).
			Where("id = ?", report.CredentialID).
			Updates(map[string]interface{}{
				"bandwidth_used": database.DB.Raw("bandwidth_used + ?", adjustedIn+adjustedOut),
			})

		// Also update phone data usage if tracking exists
		// This is optional and can be used for analytics
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Usage reported",
		"count":   len(batch.Reports),
	})
}
