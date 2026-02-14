package allocator

import (
	"fmt"
	"sync"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
)

var (
	ipMutex   sync.Mutex
	portMutex sync.Mutex
)

// InitializeSettings ensures system settings exist with correct initial values
// Should be called on startup after migration
func InitializeSettings() error {
	// Check if settings exist, if not create them with values based on existing data
	var ipSetting models.SystemSetting
	if err := database.DB.Where("key = ?", models.SettingNextWireGuardIP).First(&ipSetting).Error; err != nil {
		// Find max IP currently in use
		var maxIP int64
		database.DB.Model(&models.Phone{}).
			Select("COALESCE(MAX(CAST(SPLIT_PART(wire_guard_ip, '.', 3) AS INTEGER) * 256 + CAST(SPLIT_PART(wire_guard_ip, '.', 4) AS INTEGER)), 1)").
			Where("wire_guard_ip IS NOT NULL AND wire_guard_ip != ''").
			Scan(&maxIP)

		nextIP := maxIP + 1
		if nextIP < models.DefaultFirstWireGuardIP {
			nextIP = models.DefaultFirstWireGuardIP
		}

		database.DB.Create(&models.SystemSetting{
			Key:      models.SettingNextWireGuardIP,
			ValueInt: nextIP,
		})
	}

	var portSetting models.SystemSetting
	if err := database.DB.Where("key = ?", models.SettingNextProxyPort).First(&portSetting).Error; err != nil {
		// Find max port currently in use
		var maxPort int64
		database.DB.Model(&models.ConnectionCredential{}).
			Select("COALESCE(MAX(port), 9999)").
			Scan(&maxPort)

		nextPort := maxPort + 1
		if nextPort < models.DefaultFirstProxyPort {
			nextPort = models.DefaultFirstProxyPort
		}

		database.DB.Create(&models.SystemSetting{
			Key:      models.SettingNextProxyPort,
			ValueInt: nextPort,
		})
	}

	return nil
}

// AllocateWireGuardIP allocates a globally unique WireGuard IP
// Returns IP in format "10.66.x.y"
func AllocateWireGuardIP() (string, error) {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	var setting models.SystemSetting

	// Atomically increment and get the new value
	result := database.DB.Raw(`
		UPDATE system_settings
		SET value_int = value_int + 1, updated_at = NOW()
		WHERE key = ?
		RETURNING value_int
	`, models.SettingNextWireGuardIP).Scan(&setting.ValueInt)

	if result.Error != nil {
		return "", fmt.Errorf("failed to allocate WireGuard IP: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return "", fmt.Errorf("WireGuard IP setting not found")
	}

	ipNum := setting.ValueInt - 1 // We incremented, so use previous value

	if ipNum > models.MaxWireGuardIP {
		return "", fmt.Errorf("WireGuard IP space exhausted (max: %d)", models.MaxWireGuardIP)
	}

	ip := numberToIP(ipNum)
	return ip, nil
}

// AllocateProxyPort allocates a globally unique proxy port
func AllocateProxyPort() (int, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	var setting models.SystemSetting

	// Atomically increment and get the new value
	result := database.DB.Raw(`
		UPDATE system_settings
		SET value_int = value_int + 1, updated_at = NOW()
		WHERE key = ?
		RETURNING value_int
	`, models.SettingNextProxyPort).Scan(&setting.ValueInt)

	if result.Error != nil {
		return 0, fmt.Errorf("failed to allocate proxy port: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return 0, fmt.Errorf("proxy port setting not found")
	}

	port := int(setting.ValueInt - 1) // We incremented, so use previous value

	if port > models.MaxProxyPort {
		return 0, fmt.Errorf("proxy port space exhausted (max: %d)", models.MaxProxyPort)
	}

	return port, nil
}

// numberToIP converts a sequential number to a WireGuard IP
// Uses 10.66.0.0/16 subnet
// n=2 -> 10.66.0.2, n=256 -> 10.66.1.0, n=65534 -> 10.66.255.254
func numberToIP(n int64) string {
	thirdOctet := n / 256
	fourthOctet := n % 256
	return fmt.Sprintf("10.66.%d.%d", thirdOctet, fourthOctet)
}

// IPToNumber converts a WireGuard IP back to a sequential number
// Used for finding the max IP in use
func IPToNumber(ip string) (int64, error) {
	var a, b, c, d int
	_, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil {
		return 0, err
	}
	return int64(c*256 + d), nil
}
