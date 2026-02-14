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

// Default values
const (
	DefaultFirstWireGuardIP = 2     // 10.66.0.2
	DefaultFirstProxyPort   = 10000
	MaxWireGuardIP          = 65534 // 10.66.255.254
	MaxProxyPort            = 19999 // ~10,000 credentials
)
