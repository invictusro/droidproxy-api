package jobs

import (
	"log"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/internal/infra"
	"github.com/droidproxy/api/models"
	"github.com/google/uuid"
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

// processExpiredLicense marks a license as expired and DELETES all credentials
// This ensures proxy stops working immediately and user starts fresh when renewing
func processExpiredLicense(license models.PhoneLicense) {
	log.Printf("[Jobs] Processing expired license %s for phone %s", license.ID, license.PhoneID)

	tx := database.DB.Begin()

	// Mark license as expired
	if err := tx.Model(&license).Update("status", models.LicenseExpired).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error marking license as expired: %v", err)
		return
	}

	// Update phone - keep plan_tier/license_expires_at for UI display, clear limits
	// The UI checks license_expires_at to determine if license is expired
	if err := tx.Model(&models.Phone{}).Where("id = ?", license.PhoneID).Updates(map[string]interface{}{
		"speed_limit_mbps": 0,
		"max_connections":  0,
	}).Error; err != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error updating phone: %v", err)
		return
	}

	// DELETE all credentials for this phone (not just disable)
	// This ensures proxy completely stops and user must create new credentials when renewing
	var deletedCount int64
	if result := tx.Where("phone_id = ?", license.PhoneID).Delete(&models.ConnectionCredential{}); result.Error != nil {
		tx.Rollback()
		log.Printf("[Jobs] Error deleting credentials: %v", result.Error)
		return
	} else {
		deletedCount = result.RowsAffected
	}

	// Delete rotation token
	if err := tx.Where("phone_id = ?", license.PhoneID).Delete(&models.RotationToken{}).Error; err != nil {
		// Not critical, just log
		log.Printf("[Jobs] Error deleting rotation token: %v", err)
	}

	tx.Commit()
	log.Printf("[Jobs] Successfully expired license for phone %s (deleted %d credentials)", license.PhoneID, deletedCount)

	// Trigger hub reconciliation to remove proxies immediately
	go triggerHubReconciliationForPhone(license.PhoneID)
}

// triggerHubReconciliationForPhone triggers a hub to resync after license expiry
func triggerHubReconciliationForPhone(phoneID uuid.UUID) {
	var phone models.Phone
	if err := database.DB.Preload("HubServer").First(&phone, "id = ?", phoneID).Error; err != nil {
		log.Printf("[Jobs] Warning: failed to load phone for reconciliation: %v", err)
		return
	}
	if phone.HubServer != nil && phone.HubServer.HubAPIKey != "" {
		if err := infra.TriggerReconcileV2(
			phone.HubServer.IP,
			phone.HubServer.HubAPIPort,
			phone.HubServer.HubAPIKey,
		); err != nil {
			log.Printf("[Jobs] Warning: failed to trigger hub reconciliation: %v", err)
		} else {
			log.Printf("[Jobs] Triggered hub reconciliation for %s after license expiry", phone.HubServer.Name)
		}
	}
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
