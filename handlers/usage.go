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
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	startOfLastMonth := startOfMonth.AddDate(0, -1, 0)

	// Get this month's usage
	var thisMonthUsage []models.PhoneDataUsage
	database.DB.Where("phone_id = ? AND date >= ?", phoneID, startOfMonth).Find(&thisMonthUsage)

	thisMonth := models.DataUsageSummary{}
	for _, u := range thisMonthUsage {
		thisMonth.BytesIn += u.BytesIn
		thisMonth.BytesOut += u.BytesOut
	}
	thisMonth.Total = thisMonth.BytesIn + thisMonth.BytesOut

	// Get last month's usage
	var lastMonthUsage []models.PhoneDataUsage
	database.DB.Where("phone_id = ? AND date >= ? AND date < ?", phoneID, startOfLastMonth, startOfMonth).Find(&lastMonthUsage)

	lastMonth := models.DataUsageSummary{}
	for _, u := range lastMonthUsage {
		lastMonth.BytesIn += u.BytesIn
		lastMonth.BytesOut += u.BytesOut
	}
	lastMonth.Total = lastMonth.BytesIn + lastMonth.BytesOut

	// Get daily breakdown (last 30 days)
	thirtyDaysAgo := today.AddDate(0, 0, -30)
	var dailyUsage []models.PhoneDataUsage
	database.DB.Where("phone_id = ? AND date >= ?", phoneID, thirtyDaysAgo).
		Order("date DESC").Find(&dailyUsage)

	daily := make([]models.DailyDataUsage, len(dailyUsage))
	for i, u := range dailyUsage {
		daily[i] = models.DailyDataUsage{
			Date:     u.Date.Format("2006-01-02"),
			BytesIn:  u.BytesIn,
			BytesOut: u.BytesOut,
			Total:    u.BytesIn + u.BytesOut,
		}
	}

	c.JSON(http.StatusOK, models.PhoneDataUsageDetail{
		PhoneID:    phoneID.String(),
		PhoneName:  phone.Name,
		ThisMonth:  thisMonth,
		LastMonth:  lastMonth,
		DailyUsage: daily,
	})
}

// GetPhoneUptime returns uptime stats for a specific phone
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
	sevenDaysAgo := today.AddDate(0, 0, -7)
	oneDayAgo := now.Add(-24 * time.Hour)

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

	// Get last 7 days from daily uptime records
	var dailyUptimes []models.PhoneDailyUptime
	database.DB.Where("phone_id = ? AND date >= ?", phoneID, sevenDaysAgo).
		Order("date DESC").Find(&dailyUptimes)

	// Calculate 7-day average
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

	last7Days := 0.0
	if dayCount > 0 {
		avgMinutes := float64(totalMinutes) / float64(dayCount)
		last7Days = avgMinutes / 1440.0 * 100.0
	}

	c.JSON(http.StatusOK, models.PhoneUptimeDetail{
		PhoneID:       phoneID.String(),
		PhoneName:     phone.Name,
		Last24Hours:   last24Hours,
		Last7Days:     last7Days,
		CurrentStatus: currentStatus,
		DailyUptime:   daily,
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

// CleanupOldUsageData removes data older than last month
// Should be called periodically (e.g., daily cron job)
func CleanupOldUsageData(c *gin.Context) {
	now := time.Now()
	startOfLastMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
	sevenDaysAgo := now.AddDate(0, 0, -7)

	// Delete data usage older than start of last month
	result := database.DB.Where("date < ?", startOfLastMonth).Delete(&models.PhoneDataUsage{})
	deletedUsage := result.RowsAffected

	// Delete uptime logs older than 7 days
	result = database.DB.Where("timestamp < ?", sevenDaysAgo).Delete(&models.PhoneUptimeLog{})
	deletedLogs := result.RowsAffected

	// Delete daily uptime older than 7 days
	result = database.DB.Where("date < ?", sevenDaysAgo).Delete(&models.PhoneDailyUptime{})
	deletedDaily := result.RowsAffected

	// Delete old phone stats (keep last 24 hours)
	oneDayAgo := now.Add(-24 * time.Hour)
	result = database.DB.Where("recorded_at < ?", oneDayAgo).Delete(&models.PhoneStats{})
	deletedStats := result.RowsAffected

	c.JSON(http.StatusOK, gin.H{
		"message":              "Cleanup completed",
		"deleted_usage":        deletedUsage,
		"deleted_uptime_logs":  deletedLogs,
		"deleted_daily_uptime": deletedDaily,
		"deleted_stats":        deletedStats,
	})
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
