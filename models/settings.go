package models

import (
	"time"
)

// SystemSetting stores global system configuration
type SystemSetting struct {
	Key       string    `gorm:"primaryKey;type:varchar(50)"`
	ValueInt  int64     `gorm:"not null;default:0"`
	ValueStr  string    `gorm:"type:text"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// Setting keys
const (
	SettingNextWireGuardIP = "next_wireguard_ip"
	SettingNextProxyPort   = "next_proxy_port"
)

// WireGuard network configuration
// All hub servers MUST use this same subnet for phones to connect
const (
	WireGuardNetworkPrefix = "10.66"           // Network prefix for all WireGuard IPs
	WireGuardServerIP      = "10.66.0.1/16"    // Hub server's WireGuard address (same for all servers)
	WireGuardSubnetMask    = 16                // /16 = 65,534 possible phone IPs
)

// Default values
const (
	DefaultFirstWireGuardIP = 2     // 10.66.0.2 (first phone IP)
	DefaultFirstProxyPort   = 10000
	MaxWireGuardIP          = 65534 // 10.66.255.254
	MaxProxyPort            = 19999 // ~10,000 credentials
)
