package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/droidproxy/api/database"
	phonecomm "github.com/droidproxy/api/internal/phone"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListGroups returns all groups for the current user
func ListGroups(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var groups []models.PhoneGroup
	if err := database.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&groups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
		return
	}

	responses := make([]models.GroupResponse, len(groups))
	for i, group := range groups {
		// Get phone IDs for this group
		var memberships []models.PhoneGroupMembership
		database.DB.Where("group_id = ?", group.ID).Find(&memberships)

		phoneIDs := make([]string, len(memberships))
		for j, m := range memberships {
			phoneIDs[j] = m.PhoneID.String()
		}

		responses[i] = group.ToResponse(phoneIDs)
	}

	c.JSON(http.StatusOK, gin.H{"groups": responses})
}

// CreateGroup creates a new phone group
func CreateGroup(c *gin.Context) {
	var req models.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	// Set default color if not provided
	if req.Color == "" {
		req.Color = "#6366f1"
	}

	group := models.PhoneGroup{
		UserID:      userID,
		Name:        req.Name,
		Color:       req.Color,
		Description: req.Description,
	}

	if err := database.DB.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group"})
		return
	}

	// Add phones if provided
	phoneIDs := []string{}
	if len(req.PhoneIDs) > 0 {
		for _, phoneIDStr := range req.PhoneIDs {
			phoneID, err := uuid.Parse(phoneIDStr)
			if err != nil {
				continue
			}

			// Verify phone belongs to user
			var phone models.Phone
			if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
				continue
			}

			membership := models.PhoneGroupMembership{
				GroupID: group.ID,
				PhoneID: phoneID,
			}
			if err := database.DB.Create(&membership).Error; err == nil {
				phoneIDs = append(phoneIDs, phoneIDStr)
			}
		}
	}

	c.JSON(http.StatusCreated, group.ToResponse(phoneIDs))
}

// GetGroup returns a specific group
func GetGroup(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var group models.PhoneGroup
	if err := database.DB.Where("id = ? AND user_id = ?", groupID, userID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Get phone IDs
	var memberships []models.PhoneGroupMembership
	database.DB.Where("group_id = ?", groupID).Find(&memberships)

	phoneIDs := make([]string, len(memberships))
	for i, m := range memberships {
		phoneIDs[i] = m.PhoneID.String()
	}

	c.JSON(http.StatusOK, group.ToResponse(phoneIDs))
}

// UpdateGroup updates a group's details
func UpdateGroup(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req models.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var group models.PhoneGroup
	if err := database.DB.Where("id = ? AND user_id = ?", groupID, userID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Update fields if provided
	if req.Name != nil {
		group.Name = *req.Name
	}
	if req.Color != nil {
		group.Color = *req.Color
	}
	if req.Description != nil {
		group.Description = *req.Description
	}

	if err := database.DB.Save(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group"})
		return
	}

	// Get phone IDs
	var memberships []models.PhoneGroupMembership
	database.DB.Where("group_id = ?", groupID).Find(&memberships)

	phoneIDs := make([]string, len(memberships))
	for i, m := range memberships {
		phoneIDs[i] = m.PhoneID.String()
	}

	c.JSON(http.StatusOK, group.ToResponse(phoneIDs))
}

// DeleteGroup deletes a group (does not delete phones)
func DeleteGroup(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var group models.PhoneGroup
	if err := database.DB.Where("id = ? AND user_id = ?", groupID, userID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Delete memberships first
	database.DB.Where("group_id = ?", groupID).Delete(&models.PhoneGroupMembership{})

	// Delete group
	if err := database.DB.Delete(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Group deleted"})
}

// AddPhonesToGroup adds phones to a group
func AddPhonesToGroup(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req models.AddPhonesToGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify group belongs to user
	var group models.PhoneGroup
	if err := database.DB.Where("id = ? AND user_id = ?", groupID, userID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	added := 0
	errors := []string{}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid phone ID: %s", phoneIDStr))
			continue
		}

		// Verify phone belongs to user
		var phone models.Phone
		if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
			errors = append(errors, fmt.Sprintf("Phone not found: %s", phoneIDStr))
			continue
		}

		// Check if already a member
		var existing models.PhoneGroupMembership
		if database.DB.Where("group_id = ? AND phone_id = ?", groupID, phoneID).First(&existing).Error == nil {
			// Already a member, skip
			continue
		}

		membership := models.PhoneGroupMembership{
			GroupID: groupID,
			PhoneID: phoneID,
		}
		if err := database.DB.Create(&membership).Error; err != nil {
			errors = append(errors, fmt.Sprintf("Failed to add phone: %s", phoneIDStr))
			continue
		}
		added++
	}

	c.JSON(http.StatusOK, gin.H{
		"added":  added,
		"errors": errors,
	})
}

// RemovePhoneFromGroup removes a phone from a group
func RemovePhoneFromGroup(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}
	phoneID, err := uuid.Parse(c.Param("phoneId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify group belongs to user
	var group models.PhoneGroup
	if err := database.DB.Where("id = ? AND user_id = ?", groupID, userID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Delete membership
	result := database.DB.Where("group_id = ? AND phone_id = ?", groupID, phoneID).Delete(&models.PhoneGroupMembership{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove phone from group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone removed from group"})
}

// ========== Mass Actions ==========

// MassRotateIP rotates IP for multiple phones
func MassRotateIP(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.MassActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := models.MassActionResult{
		Total: len(req.PhoneIDs),
	}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid ID: %s", phoneIDStr))
			continue
		}

		// Verify phone belongs to user and is paired
		var phone models.Phone
		if err := database.DB.Where("id = ? AND user_id = ? AND paired_at IS NOT NULL", phoneID, userID).First(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Phone not found or not paired: %s", phoneIDStr))
			continue
		}

		// Send rotate command via Centrifugo
		if err := phonecomm.SendRotateIP(phoneIDStr); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to send command: %s", phoneIDStr))
			continue
		}

		result.Succeeded++
	}

	c.JSON(http.StatusOK, result)
}

// MassUpdateRotationSettings updates rotation settings for multiple phones
func MassUpdateRotationSettings(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.MassRotationSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate interval for timed mode
	if req.RotationMode == "timed" {
		if req.RotationIntervalMinutes < 2 || req.RotationIntervalMinutes > 120 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Interval must be between 2 and 120 minutes for timed mode"})
			return
		}
	}

	result := models.MassActionResult{
		Total: len(req.PhoneIDs),
	}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid ID: %s", phoneIDStr))
			continue
		}

		// Verify phone belongs to user
		var phone models.Phone
		if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Phone not found: %s", phoneIDStr))
			continue
		}

		// Update settings
		phone.RotationMode = req.RotationMode
		if req.RotationMode == "timed" {
			phone.RotationIntervalMinutes = req.RotationIntervalMinutes
		} else {
			phone.RotationIntervalMinutes = 0
		}

		if err := database.DB.Save(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to update: %s", phoneIDStr))
			continue
		}

		// Notify phone of settings change via Centrifugo (only if paired)
		if phone.PairedAt != nil {
			phonecomm.SendRotationSettings(phoneIDStr, req.RotationMode, phone.RotationIntervalMinutes)
		}

		result.Succeeded++
	}

	c.JSON(http.StatusOK, result)
}

// MassCreateCredentials creates credentials for multiple phones
func MassCreateCredentials(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.MassCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate based on auth type
	if req.AuthType == "ip_whitelist" && req.AllowedIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "allowed_ip is required for IP whitelist auth"})
		return
	}
	if req.AuthType == "username_password" && (req.Username == "" || req.Password == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required for username/password auth"})
		return
	}

	result := models.MassActionResult{
		Total: len(req.PhoneIDs),
	}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid ID: %s", phoneIDStr))
			continue
		}

		// Verify phone belongs to user
		var phone models.Phone
		if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Phone not found: %s", phoneIDStr))
			continue
		}

		// Create credential
		credential := models.ConnectionCredential{
			PhoneID:        phoneID,
			AuthType:       models.AuthType(req.AuthType),
			ProxyType:      models.ProxyType(req.ProxyType),
			AllowedIP:      req.AllowedIP,
			Username:       req.Username,
			Password:       req.Password,
			BandwidthLimit: req.BandwidthLimit,
			IsActive:       true,
		}

		if err := database.DB.Create(&credential).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to create credential: %s", phoneIDStr))
			continue
		}

		// Send credential to phone via Centrifugo
		if phone.PairedAt != nil {
			notifyPhoneCredentialsUpdated(phoneIDStr)
		}

		result.Succeeded++
	}

	c.JSON(http.StatusOK, result)
}

// MassDeletePhones deletes multiple phones
func MassDeletePhones(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.MassActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := models.MassActionResult{
		Total: len(req.PhoneIDs),
	}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid ID: %s", phoneIDStr))
			continue
		}

		// Verify phone belongs to user
		var phone models.Phone
		if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Phone not found: %s", phoneIDStr))
			continue
		}

		// Delete group memberships
		database.DB.Where("phone_id = ?", phoneID).Delete(&models.PhoneGroupMembership{})

		// Delete credentials
		database.DB.Where("phone_id = ?", phoneID).Delete(&models.ConnectionCredential{})

		// Delete rotation tokens
		database.DB.Where("phone_id = ?", phoneID).Delete(&models.RotationToken{})

		// Delete phone stats
		database.DB.Where("phone_id = ?", phoneID).Delete(&models.PhoneStats{})

		// Delete phone
		if err := database.DB.Delete(&phone).Error; err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to delete: %s", phoneIDStr))
			continue
		}

		result.Succeeded++
	}

	c.JSON(http.StatusOK, result)
}

// ========== Export ==========

// ExportProxies exports proxy configurations in various formats
func ExportProxies(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.ExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	type proxyInfo struct {
		Phone      models.Phone
		Credential *models.ConnectionCredential
		RotationURL string
	}

	proxies := []proxyInfo{}

	for _, phoneIDStr := range req.PhoneIDs {
		phoneID, err := uuid.Parse(phoneIDStr)
		if err != nil {
			continue
		}

		// Get phone with server
		var phone models.Phone
		if err := database.DB.Preload("HubServer").Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
			continue
		}

		info := proxyInfo{Phone: phone}

		// Get credential
		if req.CredentialID != nil {
			credID, _ := uuid.Parse(*req.CredentialID)
			var cred models.ConnectionCredential
			if database.DB.Where("id = ? AND phone_id = ?", credID, phoneID).First(&cred).Error == nil {
				info.Credential = &cred
			}
		} else {
			// Get first active credential
			var cred models.ConnectionCredential
			if database.DB.Where("phone_id = ? AND is_active = ?", phoneID, true).Order("created_at ASC").First(&cred).Error == nil {
				info.Credential = &cred
			}
		}

		// Get rotation URL if requested
		if req.IncludeRotation && phone.RotationMode == "api" {
			var token models.RotationToken
			if database.DB.Where("phone_id = ?", phoneID).First(&token).Error == nil {
				info.RotationURL = fmt.Sprintf("https://api.yalx.in/api/rotate/%s", token.Token)
			}
		}

		proxies = append(proxies, info)
	}

	lines := []string{}

	for _, p := range proxies {
		host := ""
		if p.Phone.ProxyDomain != "" {
			host = p.Phone.ProxyDomain
		} else if p.Phone.HubServer != nil {
			host = p.Phone.HubServer.IP
		}

		// Use credential port (each credential has its own port now)
		port := 0
		if p.Credential != nil {
			port = p.Credential.Port
		}
		if port == 0 {
			continue // Skip if no credential with port
		}

		switch req.Format {
		case "plain":
			// host:port
			lines = append(lines, fmt.Sprintf("%s:%d", host, port))

		case "auth":
			// host:port:user:pass or host:port (for IP auth)
			if p.Credential != nil && p.Credential.AuthType == models.AuthTypeUserPass {
				lines = append(lines, fmt.Sprintf("%s:%d:%s:%s", host, port, p.Credential.Username, p.Credential.Password))
			} else {
				lines = append(lines, fmt.Sprintf("%s:%d", host, port))
			}

		case "json":
			// JSON object per line
			proto := "socks5"
			if req.ProxyType == "http" {
				proto = "http"
			}
			jsonLine := fmt.Sprintf(`{"host":"%s","port":%d,"protocol":"%s"`, host, port, proto)
			if p.Credential != nil && p.Credential.AuthType == models.AuthTypeUserPass {
				jsonLine += fmt.Sprintf(`,"username":"%s","password":"%s"`, p.Credential.Username, p.Credential.Password)
			}
			if p.RotationURL != "" {
				jsonLine += fmt.Sprintf(`,"rotation_url":"%s"`, p.RotationURL)
			}
			jsonLine += "}"
			lines = append(lines, jsonLine)

		case "csv":
			// host,port,protocol,username,password,rotation_url
			proto := "socks5"
			if req.ProxyType == "http" {
				proto = "http"
			}
			user, pass := "", ""
			if p.Credential != nil && p.Credential.AuthType == models.AuthTypeUserPass {
				user = p.Credential.Username
				pass = p.Credential.Password
			}
			lines = append(lines, fmt.Sprintf("%s,%d,%s,%s,%s,%s", host, port, proto, user, pass, p.RotationURL))

		case "curl":
			// curl command
			proto := "socks5"
			if req.ProxyType == "http" {
				proto = "http"
			}
			proxyArg := fmt.Sprintf("%s://%s:%d", proto, host, port)
			if p.Credential != nil && p.Credential.AuthType == models.AuthTypeUserPass {
				proxyArg = fmt.Sprintf("%s://%s:%s@%s:%d", proto, p.Credential.Username, p.Credential.Password, host, port)
			}
			lines = append(lines, fmt.Sprintf("curl -x %s https://api.ipify.org", proxyArg))
		}
	}

	// Add CSV header if CSV format
	content := strings.Join(lines, "\n")
	if req.Format == "csv" && len(lines) > 0 {
		content = "host,port,protocol,username,password,rotation_url\n" + content
	}

	c.JSON(http.StatusOK, models.ExportResponse{
		Format:  req.Format,
		Content: content,
		Lines:   lines,
	})
}

// Helper function to assign ports (duplicated from connections.go for now)
