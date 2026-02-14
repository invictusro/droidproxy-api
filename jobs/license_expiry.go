package jobs

import (
	"log"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
)

// StartLicenseExpiryJob runs the license expiry check periodically
func StartLicenseExpiryJob() {
	// Run immediately on startup
	go checkExpiredLicenses()

	// Then run every hour
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			checkExpiredLicenses()
		}
	}()

	log.Println("[Jobs] License expiry job started (runs every hour)")
}

// checkExpiredLicenses finds expired licenses and disables credentials
func checkExpiredLicenses() {
	log.Println("[Jobs] Checking for expired licenses...")

	now := time.Now()

	// Find all active licenses that have expired
	var expiredLicenses []models.PhoneLicense
	if err := database.DB.Where("status = ? AND expires_at < ?", models.LicenseActive, now).
		Find(&expiredLicenses).Error; err != nil {
		log.Printf("[Jobs] Error finding expired licenses: %v", err)
		return
	}

	if len(expiredLicenses) == 0 {
		log.Println("[Jobs] No expired licenses found")
		return
	}

	log.Printf("[Jobs] Found %d expired licenses to process", len(expiredLicenses))

	for _, license := range expiredLicenses {
		processExpiredLicense(license)
	}

	// Also clean up phones that expired more than 14 days ago
	cleanupOldExpiredPhones()
}

// processExpiredLicense marks a license as expired and disables credentials
func processExpiredLicense(license models.PhoneLicense) {
	log.Printf("[Jobs] Processing expired license %s for phone %s", license.ID, license.PhoneID)

	tx := database.DB.Begin()

	// Mark license as expired
	if err := tx.Model(&license).Update("status", models.LicenseExpired).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error marking license as expired: %v", err)
		return
	}

	// Update phone - clear plan info
	if err := tx.Model(&models.Phone{}).Where("id = ?", license.PhoneID).Updates(map[string]interface{}{
		"plan_tier":          nil,
		"license_expires_at": nil,
		"has_active_license": false,
		"speed_limit_mbps":   0,
		"max_connections":    0,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error updating phone: %v", err)
		return
	}

	// Disable all credentials for this phone
	if err := tx.Model(&models.ConnectionCredential{}).
		Where("phone_id = ?", license.PhoneID).
		Update("is_active", false).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error disabling credentials: %v", err)
		return
	}

	// Delete rotation token
	if err := tx.Where("phone_id = ?", license.PhoneID).Delete(&models.RotationToken{}).Error; err != nil {
		// Not critical, just log
		log.Printf("[Jobs] Error deleting rotation token: %v", err)
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully expired license for phone %s", license.PhoneID)
}

// cleanupOldExpiredPhones deletes phones that have been expired for more than 14 days
func cleanupOldExpiredPhones() {
	cutoffDate := time.Now().AddDate(0, 0, -14) // 14 days ago

	// Find licenses expired more than 14 days ago
	var oldLicenses []models.PhoneLicense
	if err := database.DB.Where("status = ? AND expires_at < ?", models.LicenseExpired, cutoffDate).
		Find(&oldLicenses).Error; err != nil {
		log.Printf("[Jobs] Error finding old expired licenses: %v", err)
		return
	}

	if len(oldLicenses) == 0 {
		return
	}

	log.Printf("[Jobs] Found %d phones to clean up (expired > 14 days)", len(oldLicenses))

	for _, license := range oldLicenses {
		// Delete all related data
		tx := database.DB.Begin()

		phoneID := license.PhoneID

		// Delete credentials
		tx.Where("phone_id = ?", phoneID).Delete(&models.ConnectionCredential{})

		// Delete rotation token
		tx.Where("phone_id = ?", phoneID).Delete(&models.RotationToken{})

		// Delete licenses
		tx.Where("phone_id = ?", phoneID).Delete(&models.PhoneLicense{})

		// Delete phone
		tx.Where("id = ?", phoneID).Delete(&models.Phone{})

		if err := tx.Commit().Error; err != nil {
			log.Printf("[Jobs] Error cleaning up phone %s: %v", phoneID, err)
		} else {
			log.Printf("[Jobs] Cleaned up expired phone %s", phoneID)
		}
	}
}
