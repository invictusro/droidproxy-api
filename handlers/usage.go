package handlers

import (
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetPhoneDataUsage returns data usage for a specific phone
// Supports optional query params: start_date, end_date (format: 2006-01-02)
func GetPhoneDataUsage(c *gin.Context) {
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

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Parse optional date range params
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", startDateStr); err == nil {
			startDate = parsed
		}
	}
	if endDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", endDateStr); err == nil {
			endDate = parsed.Add(24*time.Hour - time.Second) // End of day
		}
	}

	// Default to last 90 days if no date range specified
	if startDate.IsZero() {
		startDate = today.AddDate(0, 0, -90)
	}
	if endDate.IsZero() {
		endDate = today.Add(24*time.Hour - time.Second)
	}

	// Get usage for date range
	var dailyUsage []models.PhoneDataUsage
	database.DB.Where("phone_id = ? AND date >= ? AND date <= ?", phoneID, startDate, endDate).
		Order("date DESC").Find(&dailyUsage)

	// Calculate totals for the period
	totalSummary := models.DataUsageSummary{}
	daily := make([]models.DailyDataUsage, len(dailyUsage))
	for i, u := range dailyUsage {
		totalSummary.BytesIn += u.BytesIn
		totalSummary.BytesOut += u.BytesOut
		daily[i] = models.DailyDataUsage{
			Date:     u.Date.Format("2006-01-02"),
			BytesIn:  u.BytesIn,
			BytesOut: u.BytesOut,
			Total:    u.BytesIn + u.BytesOut,
		}
	}
	totalSummary.Total = totalSummary.BytesIn + totalSummary.BytesOut

	c.JSON(http.StatusOK, gin.H{
		"phone_id":   phoneID.String(),
		"phone_name": phone.Name,
		"start_date": startDate.Format("2006-01-02"),
		"end_date":   endDate.Format("2006-01-02"),
		"total":      totalSummary,
		"daily":      daily,
	})
}

// GetPhoneUptime returns uptime stats for a specific phone
// Supports optional query params: start_date, end_date (format: 2006-01-02)
func GetPhoneUptime(c *gin.Context) {
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

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	oneDayAgo := now.Add(-24 * time.Hour)

	// Parse optional date range params (default: last 30 days)
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	var startDate, endDate time.Time
	if startDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", startDateStr); err == nil {
			startDate = parsed
		}
	}
	if endDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", endDateStr); err == nil {
			endDate = parsed
		}
	}

	// Default to last 30 days
	if startDate.IsZero() {
		startDate = today.AddDate(0, 0, -30)
	}
	if endDate.IsZero() {
		endDate = today
	}

	// Get current status
	var lastLog models.PhoneUptimeLog
	currentStatus := "offline"
	if database.DB.Where("phone_id = ?", phoneID).Order("timestamp DESC").First(&lastLog).Error == nil {
		currentStatus = lastLog.Status
	}

	// Calculate last 24 hours uptime from logs
	var logs24h []models.PhoneUptimeLog
	database.DB.Where("phone_id = ? AND timestamp >= ?", phoneID, oneDayAgo).
		Order("timestamp ASC").Find(&logs24h)

	last24Hours := calculateUptimeFromLogs(phoneID, logs24h, oneDayAgo, now)

	// Get daily uptime for date range
	var dailyUptimes []models.PhoneDailyUptime
	database.DB.Where("phone_id = ? AND date >= ? AND date <= ?", phoneID, startDate, endDate).
		Order("date DESC").Find(&dailyUptimes)

	// Calculate average for the period
	totalMinutes := 0
	dayCount := 0
	daily := []models.DailyUptime{}

	for _, u := range dailyUptimes {
		totalMinutes += u.OnlineMinutes
		dayCount++
		daily = append(daily, models.DailyUptime{
			Date:             u.Date.Format("2006-01-02"),
			OnlineMinutes:    u.OnlineMinutes,
			UptimePercentage: u.UptimePercentage(),
		})
	}

	periodAverage := 0.0
	if dayCount > 0 {
		avgMinutes := float64(totalMinutes) / float64(dayCount)
		periodAverage = avgMinutes / 1440.0 * 100.0
	}

	// Get hourly breakdown for the current day or selected single day
	hourlyData := []gin.H{}
	targetDate := today
	if startDate.Equal(endDate) {
		targetDate = startDate
	}

	// Get logs for the target day to calculate hourly uptime
	dayStart := time.Date(targetDate.Year(), targetDate.Month(), targetDate.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	var dayLogs []models.PhoneUptimeLog
	database.DB.Where("phone_id = ? AND timestamp >= ? AND timestamp < ?", phoneID, dayStart, dayEnd).
		Order("timestamp ASC").Find(&dayLogs)

	// Calculate uptime for each hour
	for hour := 0; hour < 24; hour++ {
		hourStart := dayStart.Add(time.Duration(hour) * time.Hour)
		hourEnd := hourStart.Add(time.Hour)
		if hourEnd.After(now) {
			hourEnd = now
		}
		if hourStart.After(now) {
			break // Don't include future hours
		}

		// Filter logs for this hour
		var hourLogs []models.PhoneUptimeLog
		for _, log := range dayLogs {
			if !log.Timestamp.Before(hourStart) && log.Timestamp.Before(hourEnd) {
				hourLogs = append(hourLogs, log)
			}
		}

		uptimePct := calculateUptimeFromLogs(phoneID, hourLogs, hourStart, hourEnd)
		hourlyData = append(hourlyData, gin.H{
			"hour":    hour,
			"uptime":  uptimePct,
			"minutes": int(uptimePct * 0.6), // 60 min * percentage / 100
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"phone_id":       phoneID.String(),
		"phone_name":     phone.Name,
		"start_date":     startDate.Format("2006-01-02"),
		"end_date":       endDate.Format("2006-01-02"),
		"last_24_hours":  last24Hours,
		"period_average": periodAverage,
		"current_status": currentStatus,
		"daily":          daily,
		"hourly":         hourlyData,
	})
}

// GetAllPhonesUsage returns usage overview for all phones
func GetAllPhonesUsage(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	// Get all phones for user
	var phones []models.Phone
	database.DB.Where("user_id = ?", userID).Find(&phones)

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	sevenDaysAgo := today.AddDate(0, 0, -7)

	result := models.AllPhonesUsageResponse{
		Phones: make([]models.PhoneUsageSummary, 0, len(phones)),
	}

	for _, phone := range phones {
		summary := models.PhoneUsageSummary{
			PhoneID:       phone.ID.String(),
			PhoneName:     phone.Name,
			CurrentStatus: "offline",
		}

		// Get today's usage
		var todayUsage models.PhoneDataUsage
		if database.DB.Where("phone_id = ? AND date = ?", phone.ID, today).First(&todayUsage).Error == nil {
			summary.TodayBytes = todayUsage.BytesIn + todayUsage.BytesOut
		}

		// Get this month's total
		var monthUsage []models.PhoneDataUsage
		database.DB.Where("phone_id = ? AND date >= ?", phone.ID, startOfMonth).Find(&monthUsage)
		for _, u := range monthUsage {
			summary.MonthBytes += u.BytesIn + u.BytesOut
		}

		// Get 7-day uptime average
		var dailyUptimes []models.PhoneDailyUptime
		database.DB.Where("phone_id = ? AND date >= ?", phone.ID, sevenDaysAgo).Find(&dailyUptimes)

		if len(dailyUptimes) > 0 {
			totalMinutes := 0
			for _, u := range dailyUptimes {
				totalMinutes += u.OnlineMinutes
			}
			avgMinutes := float64(totalMinutes) / float64(len(dailyUptimes))
			summary.UptimePct = avgMinutes / 1440.0 * 100.0
		}

		// Get current status
		var lastLog models.PhoneUptimeLog
		if database.DB.Where("phone_id = ?", phone.ID).Order("timestamp DESC").First(&lastLog).Error == nil {
			summary.CurrentStatus = lastLog.Status
		}

		result.Phones = append(result.Phones, summary)
		result.TotalIn += summary.TodayBytes / 2  // Approximate split
		result.TotalOut += summary.TodayBytes / 2
		result.TotalBytes += summary.MonthBytes
	}

	c.JSON(http.StatusOK, result)
}

// CleanupOldUsageData removes old data
// Data usage: 90 days, Uptime: 30 days, Access logs: per-user setting (1-12 weeks)
// Should be called periodically (e.g., daily cron job)
func CleanupOldUsageData(c *gin.Context) {
	now := time.Now()
	ninetyDaysAgo := now.AddDate(0, 0, -90)
	thirtyDaysAgo := now.AddDate(0, 0, -30)

	// Delete data usage older than 90 days
	result := database.DB.Where("date < ?", ninetyDaysAgo).Delete(&models.PhoneDataUsage{})
	deletedUsage := result.RowsAffected

	// Delete uptime logs older than 30 days
	result = database.DB.Where("timestamp < ?", thirtyDaysAgo).Delete(&models.PhoneUptimeLog{})
	deletedLogs := result.RowsAffected

	// Delete daily uptime older than 30 days
	result = database.DB.Where("date < ?", thirtyDaysAgo).Delete(&models.PhoneDailyUptime{})
	deletedDaily := result.RowsAffected

	// Delete old phone stats (keep last 24 hours)
	oneDayAgo := now.Add(-24 * time.Hour)
	result = database.DB.Where("recorded_at < ?", oneDayAgo).Delete(&models.PhoneStats{})
	deletedStats := result.RowsAffected

	// Clean access logs per-user based on their retention settings
	deletedAccessLogs := cleanupAccessLogs()

	c.JSON(http.StatusOK, gin.H{
		"message":              "Cleanup completed",
		"deleted_usage":        deletedUsage,
		"deleted_uptime_logs":  deletedLogs,
		"deleted_daily_uptime": deletedDaily,
		"deleted_stats":        deletedStats,
		"deleted_access_logs":  deletedAccessLogs,
	})
}

// cleanupAccessLogs removes old access logs based on per-phone retention settings
func cleanupAccessLogs() int64 {
	var totalDeleted int64

	// Get all phones with their retention settings
	var phones []models.Phone
	database.DB.Select("id, log_retention_weeks").Find(&phones)

	for _, phone := range phones {
		// Default to 12 weeks if not set, cap at 12 weeks max
		retentionWeeks := phone.LogRetentionWeeks
		if retentionWeeks <= 0 {
			retentionWeeks = 12
		}
		if retentionWeeks > 12 {
			retentionWeeks = 12
		}

		cutoffDate := time.Now().AddDate(0, 0, -retentionWeeks*7)

		// Delete access logs for this phone older than its retention period
		result := database.DB.Where("phone_id = ? AND timestamp < ?", phone.ID, cutoffDate).
			Delete(&models.AccessLog{})
		totalDeleted += result.RowsAffected
	}

	// Also clean up orphaned access logs (phones that no longer exist) older than 1 week
	oneWeekAgo := time.Now().AddDate(0, 0, -7)
	var existingPhoneIDs []uuid.UUID
	database.DB.Model(&models.Phone{}).Pluck("id", &existingPhoneIDs)

	if len(existingPhoneIDs) > 0 {
		result := database.DB.Where("phone_id NOT IN ? AND timestamp < ?", existingPhoneIDs, oneWeekAgo).
			Delete(&models.AccessLog{})
		totalDeleted += result.RowsAffected
	} else {
		// No phones exist, clean all old logs
		result := database.DB.Where("timestamp < ?", oneWeekAgo).Delete(&models.AccessLog{})
		totalDeleted += result.RowsAffected
	}

	return totalDeleted
}

// calculateUptimeFromLogs calculates uptime percentage from log entries
func calculateUptimeFromLogs(phoneID uuid.UUID, logs []models.PhoneUptimeLog, start, end time.Time) float64 {
	if len(logs) == 0 {
		// Check if phone was online before the period
		var prevLog models.PhoneUptimeLog
		if database.DB.Where("phone_id = ? AND timestamp < ?", phoneID, start).
			Order("timestamp DESC").First(&prevLog).Error == nil {
			if prevLog.Status == "online" {
				return 100.0 // Was online the whole time
			}
		}
		return 0.0 // No data
	}

	totalDuration := end.Sub(start).Minutes()
	onlineMinutes := 0.0
	var lastOnlineTime *time.Time

	// Check status at start of period
	var prevLog models.PhoneUptimeLog
	if database.DB.Where("phone_id = ? AND timestamp < ?", phoneID, start).
		Order("timestamp DESC").First(&prevLog).Error == nil {
		if prevLog.Status == "online" {
			t := start
			lastOnlineTime = &t
		}
	}

	for _, log := range logs {
		if log.Status == "online" {
			lastOnlineTime = &log.Timestamp
		} else if log.Status == "offline" && lastOnlineTime != nil {
			onlineMinutes += log.Timestamp.Sub(*lastOnlineTime).Minutes()
			lastOnlineTime = nil
		}
	}

	// If still online at end of period
	if lastOnlineTime != nil {
		onlineMinutes += end.Sub(*lastOnlineTime).Minutes()
	}

	if totalDuration <= 0 {
		return 0.0
	}

	return (onlineMinutes / totalDuration) * 100.0
}
