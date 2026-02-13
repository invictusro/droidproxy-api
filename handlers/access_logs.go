package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetPhoneLogRetention returns the log retention setting for a phone
// GET /phones/:id/log-retention
func GetPhoneLogRetention(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Default to 12 weeks if not set
	retention := phone.LogRetentionWeeks
	if retention <= 0 {
		retention = 12
	}

	c.JSON(http.StatusOK, gin.H{
		"phone_id":            phoneID.String(),
		"log_retention_weeks": retention,
	})
}

// UpdatePhoneLogRetention updates the log retention setting for a phone
// PUT /phones/:id/log-retention
func UpdatePhoneLogRetention(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	var req struct {
		LogRetentionWeeks int `json:"log_retention_weeks" binding:"required,min=1,max=12"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "log_retention_weeks must be between 1 and 12"})
		return
	}

	// Update setting
	phone.LogRetentionWeeks = req.LogRetentionWeeks
	if err := database.DB.Save(&phone).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"phone_id":            phoneID.String(),
		"log_retention_weeks": phone.LogRetentionWeeks,
	})
}

// GetPhoneAccessLogs returns access logs for a specific phone
// GET /phones/:id/access-logs?limit=100&offset=0&start_date=2024-01-01&end_date=2024-01-31&domain=example.com
func GetPhoneAccessLogs(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	// Parse query params
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 500 {
		limit = 500
	}

	query := database.DB.Model(&models.AccessLog{}).Where("phone_id = ?", phoneID)

	// Date filters
	if startDate := c.Query("start_date"); startDate != "" {
		if t, err := time.Parse("2006-01-02", startDate); err == nil {
			query = query.Where("timestamp >= ?", t)
		}
	}
	if endDate := c.Query("end_date"); endDate != "" {
		if t, err := time.Parse("2006-01-02", endDate); err == nil {
			query = query.Where("timestamp <= ?", t.Add(24*time.Hour))
		}
	}

	// Domain filter
	if domain := c.Query("domain"); domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}

	// Blocked filter
	if blocked := c.Query("blocked"); blocked != "" {
		query = query.Where("blocked = ?", blocked == "true")
	}

	// Credential filter
	if credID := c.Query("credential_id"); credID != "" {
		if uid, err := uuid.Parse(credID); err == nil {
			query = query.Where("credential_id = ?", uid)
		}
	}

	// Get total count
	var total int64
	query.Count(&total)

	// Get logs with ordering and pagination
	var logs []models.AccessLog
	query.Order("timestamp DESC").Limit(limit).Offset(offset).Find(&logs)

	// Convert to response format with credential names
	response := make([]models.AccessLogResponse, len(logs))
	credCache := make(map[uuid.UUID]string)

	for i, log := range logs {
		credName := ""
		if name, ok := credCache[log.CredentialID]; ok {
			credName = name
		} else {
			var cred models.ConnectionCredential
			if database.DB.Select("name").Where("id = ?", log.CredentialID).First(&cred).Error == nil {
				credName = cred.Name
				credCache[log.CredentialID] = credName
			}
		}

		response[i] = models.AccessLogResponse{
			ID:             log.ID,
			CredentialID:   log.CredentialID,
			CredentialName: credName,
			PhoneID:        log.PhoneID,
			PhoneName:      phone.Name,
			ClientIP:       log.ClientIP,
			Domain:         log.Domain,
			Port:           log.Port,
			Protocol:       log.Protocol,
			BytesIn:        log.BytesIn,
			BytesOut:       log.BytesOut,
			DurationMS:     log.DurationMS,
			Blocked:        log.Blocked,
			Timestamp:      log.Timestamp,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":   response,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetPhoneDomainStats returns aggregated domain statistics for a phone
// GET /phones/:id/domain-stats?start_date=2024-01-01&end_date=2024-01-31&limit=50
func GetPhoneDomainStats(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)
	phoneID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone ID"})
		return
	}

	// Verify phone belongs to user
	var phone models.Phone
	if err := database.DB.Where("id = ? AND user_id = ?", phoneID, userID).First(&phone).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Phone not found"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit > 200 {
		limit = 200
	}

	query := database.DB.Model(&models.AccessLog{}).Where("phone_id = ?", phoneID)

	// Date filters
	if startDate := c.Query("start_date"); startDate != "" {
		if t, err := time.Parse("2006-01-02", startDate); err == nil {
			query = query.Where("timestamp >= ?", t)
		}
	}
	if endDate := c.Query("end_date"); endDate != "" {
		if t, err := time.Parse("2006-01-02", endDate); err == nil {
			query = query.Where("timestamp <= ?", t.Add(24*time.Hour))
		}
	}

	var stats []models.DomainStats
	query.Select(`
		domain,
		COUNT(*) as access_count,
		SUM(bytes_in) as bytes_in,
		SUM(bytes_out) as bytes_out,
		MAX(timestamp) as last_access
	`).
		Group("domain").
		Order("access_count DESC").
		Limit(limit).
		Scan(&stats)

	c.JSON(http.StatusOK, gin.H{
		"phone_id":   phoneID.String(),
		"phone_name": phone.Name,
		"stats":      stats,
	})
}

// GetAllAccessLogs returns access logs across all phones for admin
// GET /admin/access-logs?limit=100&offset=0&phone_id=...&credential_id=...
func GetAllAccessLogs(c *gin.Context) {
	// Parse query params
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 500 {
		limit = 500
	}

	query := database.DB.Model(&models.AccessLog{})

	// Phone filter
	if phoneIDStr := c.Query("phone_id"); phoneIDStr != "" {
		if uid, err := uuid.Parse(phoneIDStr); err == nil {
			query = query.Where("phone_id = ?", uid)
		}
	}

	// Credential filter
	if credIDStr := c.Query("credential_id"); credIDStr != "" {
		if uid, err := uuid.Parse(credIDStr); err == nil {
			query = query.Where("credential_id = ?", uid)
		}
	}

	// Date filters
	if startDate := c.Query("start_date"); startDate != "" {
		if t, err := time.Parse("2006-01-02", startDate); err == nil {
			query = query.Where("timestamp >= ?", t)
		}
	}
	if endDate := c.Query("end_date"); endDate != "" {
		if t, err := time.Parse("2006-01-02", endDate); err == nil {
			query = query.Where("timestamp <= ?", t.Add(24*time.Hour))
		}
	}

	// Domain filter
	if domain := c.Query("domain"); domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}

	// Blocked filter
	if blocked := c.Query("blocked"); blocked != "" {
		query = query.Where("blocked = ?", blocked == "true")
	}

	// Client IP filter
	if clientIP := c.Query("client_ip"); clientIP != "" {
		query = query.Where("client_ip = ?", clientIP)
	}

	// Get total count
	var total int64
	query.Count(&total)

	// Get logs
	var logs []models.AccessLog
	query.Order("timestamp DESC").Limit(limit).Offset(offset).Find(&logs)

	// Convert to response with cached names
	response := make([]models.AccessLogResponse, len(logs))
	credCache := make(map[uuid.UUID]string)
	phoneCache := make(map[uuid.UUID]string)

	for i, log := range logs {
		credName := ""
		if name, ok := credCache[log.CredentialID]; ok {
			credName = name
		} else {
			var cred models.ConnectionCredential
			if database.DB.Select("name").Where("id = ?", log.CredentialID).First(&cred).Error == nil {
				credName = cred.Name
				credCache[log.CredentialID] = credName
			}
		}

		phoneName := ""
		if name, ok := phoneCache[log.PhoneID]; ok {
			phoneName = name
		} else {
			var phone models.Phone
			if database.DB.Select("name").Where("id = ?", log.PhoneID).First(&phone).Error == nil {
				phoneName = phone.Name
				phoneCache[log.PhoneID] = phoneName
			}
		}

		response[i] = models.AccessLogResponse{
			ID:             log.ID,
			CredentialID:   log.CredentialID,
			CredentialName: credName,
			PhoneID:        log.PhoneID,
			PhoneName:      phoneName,
			ClientIP:       log.ClientIP,
			Domain:         log.Domain,
			Port:           log.Port,
			Protocol:       log.Protocol,
			BytesIn:        log.BytesIn,
			BytesOut:       log.BytesOut,
			DurationMS:     log.DurationMS,
			Blocked:        log.Blocked,
			Timestamp:      log.Timestamp,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":   response,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetAccessLogStats returns aggregated statistics for admin dashboard
// GET /admin/access-logs/stats
func GetAccessLogStats(c *gin.Context) {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	weekAgo := today.AddDate(0, 0, -7)

	// Total logs today
	var todayCount int64
	database.DB.Model(&models.AccessLog{}).Where("timestamp >= ?", today).Count(&todayCount)

	// Blocked requests today
	var blockedToday int64
	database.DB.Model(&models.AccessLog{}).Where("timestamp >= ? AND blocked = ?", today, true).Count(&blockedToday)

	// Top domains (last 7 days)
	var topDomains []models.DomainStats
	database.DB.Model(&models.AccessLog{}).
		Where("timestamp >= ?", weekAgo).
		Select(`
			domain,
			COUNT(*) as access_count,
			SUM(bytes_in) as bytes_in,
			SUM(bytes_out) as bytes_out,
			MAX(timestamp) as last_access
		`).
		Group("domain").
		Order("access_count DESC").
		Limit(10).
		Scan(&topDomains)

	// Unique client IPs today
	var uniqueIPs int64
	database.DB.Model(&models.AccessLog{}).
		Where("timestamp >= ?", today).
		Distinct("client_ip").
		Count(&uniqueIPs)

	c.JSON(http.StatusOK, gin.H{
		"today_requests":  todayCount,
		"blocked_today":   blockedToday,
		"unique_ips":      uniqueIPs,
		"top_domains":     topDomains,
	})
}
