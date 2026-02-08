package handlers

import (
	"net/http"

	"github.com/droidproxy/api/database"
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
}

// UpdateServerRequest is the request body for updating a server
type UpdateServerRequest struct {
	Name           string `json:"name"`
	Location       string `json:"location"`
	IP             string `json:"ip"`
	WireGuardPort  int    `json:"wireguard_port"`
	ProxyPortStart int    `json:"proxy_port_start"`
	ProxyPortEnd   int    `json:"proxy_port_end"`
	IsActive       *bool  `json:"is_active"`
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
