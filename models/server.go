package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// HubServer represents a VPS hub server that routes proxy traffic
type HubServer struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name           string    `gorm:"not null" json:"name"`
	Location       string    `gorm:"not null" json:"location"` // e.g., "New York, US"
	IP             string    `gorm:"not null" json:"-"`        // Hidden from non-admin users
	WireGuardPort      int    `gorm:"default:51820" json:"-"`
	WireGuardPublicKey string `json:"-"` // Server's WireGuard public key
	ProxyPortStart     int    `gorm:"default:10000" json:"-"` // Credential proxy port range start
	ProxyPortEnd   int       `gorm:"default:19999" json:"-"` // Credential proxy port range end
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`

	// Hub Agent settings (preferred over SSH)
	HubAPIKey  string `json:"-"`                    // Shared secret for Hub Agent authentication
	HubAPIPort int    `gorm:"default:8081" json:"-"` // Hub Agent API port

	// SSH credentials for server management (legacy, prefer Hub Agent)
	SSHPort     int    `gorm:"default:22" json:"-"`
	SSHUser     string `gorm:"default:root" json:"-"`
	SSHPassword string `json:"-"` // Stored encrypted
	SSHKeyPath  string `json:"-"` // Alternative: path to SSH private key

	// Server status
	IsSetup     bool      `gorm:"default:false" json:"-"` // Whether server has been set up
	LastCheckAt *time.Time `json:"-"`                      // Last health check

	// Hub Agent telemetry (updated via heartbeat)
	CPUPercent     float64    `json:"-"`
	MemoryPercent  float64    `json:"-"`
	BandwidthIn    int64      `json:"-"` // bytes/sec
	BandwidthOut   int64      `json:"-"` // bytes/sec
	CurrentVersion string     `gorm:"type:varchar(20);default:'unknown'" json:"-"` // Hub agent version
	LastHeartbeat  *time.Time `json:"-"`

	// DNS routing fields (for dynamic proxy routing)
	DNSSubdomain string `json:"dns_subdomain"` // Server subdomain (e.g., "x1" for x1.yalx.in)
	DNSDomain    string `json:"dns_domain"`    // Full server domain (e.g., "x1.yalx.in")
	DNSRecordID  int64  `json:"-"`             // Rage4 DNS record ID for updates/deletion

	// Relationships
	Phones []Phone `gorm:"foreignKey:HubServerID" json:"phones,omitempty"`
}

// TableName overrides the table name
func (HubServer) TableName() string {
	return "hub_servers"
}

func (s *HubServer) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// HubServerResponse for regular users (hides IP)
type HubServerResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Location  string    `json:"location"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// HubServerAdminResponse for admins (includes IP and config)
type HubServerAdminResponse struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Location       string     `json:"location"`
	IP             string     `json:"ip"`
	WireGuardPort  int        `json:"wireguard_port"`
	ProxyPortStart int        `json:"proxy_port_start"`
	ProxyPortEnd   int        `json:"proxy_port_end"`
	HubAPIPort     int        `json:"hub_api_port"`
	HasHubAPIKey   bool       `json:"has_hub_api_key"`
	SSHPort        int        `json:"ssh_port"`
	SSHUser        string     `json:"ssh_user"`
	HasSSHPassword bool       `json:"has_ssh_password"`
	IsSetup        bool       `json:"is_setup"`
	IsActive       bool       `json:"is_active"`
	DNSSubdomain   string     `json:"dns_subdomain,omitempty"`
	DNSDomain      string     `json:"dns_domain,omitempty"`
	LastCheckAt    *time.Time `json:"last_check_at,omitempty"`
	LastHeartbeat  *time.Time `json:"last_heartbeat,omitempty"`
	CPUPercent     float64    `json:"cpu_percent,omitempty"`
	MemoryPercent  float64    `json:"memory_percent,omitempty"`
	CurrentVersion string     `json:"current_version,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	PhoneCount     int        `json:"phone_count"`
}

func (s *HubServer) ToResponse() HubServerResponse {
	return HubServerResponse{
		ID:        s.ID,
		Name:      s.Name,
		Location:  s.Location,
		IsActive:  s.IsActive,
		CreatedAt: s.CreatedAt,
	}
}

func (s *HubServer) ToAdminResponse() HubServerAdminResponse {
	return HubServerAdminResponse{
		ID:             s.ID,
		Name:           s.Name,
		Location:       s.Location,
		IP:             s.IP,
		WireGuardPort:  s.WireGuardPort,
		ProxyPortStart: s.ProxyPortStart,
		ProxyPortEnd:   s.ProxyPortEnd,
		HubAPIPort:     s.HubAPIPort,
		HasHubAPIKey:   s.HubAPIKey != "",
		SSHPort:        s.SSHPort,
		SSHUser:        s.SSHUser,
		HasSSHPassword: s.SSHPassword != "",
		IsSetup:        s.IsSetup,
		IsActive:       s.IsActive,
		DNSSubdomain:   s.DNSSubdomain,
		DNSDomain:      s.DNSDomain,
		LastCheckAt:    s.LastCheckAt,
		LastHeartbeat:  s.LastHeartbeat,
		CPUPercent:     s.CPUPercent,
		MemoryPercent:  s.MemoryPercent,
		CurrentVersion: s.CurrentVersion,
		CreatedAt:      s.CreatedAt,
		PhoneCount:     len(s.Phones),
	}
}

// Legacy aliases for backwards compatibility during migration
type Server = HubServer
type ServerResponse = HubServerResponse
type ServerAdminResponse = HubServerAdminResponse
