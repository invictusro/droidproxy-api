package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Server struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name           string    `gorm:"not null" json:"name"`
	Location       string    `gorm:"not null" json:"location"` // e.g., "New York, US"
	IP             string    `gorm:"not null" json:"-"`        // Hidden from non-admin users
	WireGuardPort      int    `gorm:"default:51820" json:"-"`
	WireGuardPublicKey string `json:"-"` // Server's WireGuard public key
	ProxyPortStart     int    `gorm:"default:10001" json:"-"`
	ProxyPortEnd   int       `gorm:"default:19999" json:"-"`
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`

	// Relationships
	Phones []Phone `gorm:"foreignKey:ServerID" json:"phones,omitempty"`
}

func (s *Server) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// ServerResponse for regular users (hides IP)
type ServerResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Location  string    `json:"location"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// ServerAdminResponse for admins (includes IP)
type ServerAdminResponse struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Location       string    `json:"location"`
	IP             string    `json:"ip"`
	WireGuardPort  int       `json:"wireguard_port"`
	ProxyPortStart int       `json:"proxy_port_start"`
	ProxyPortEnd   int       `json:"proxy_port_end"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	PhoneCount     int       `json:"phone_count"`
}

func (s *Server) ToResponse() ServerResponse {
	return ServerResponse{
		ID:        s.ID,
		Name:      s.Name,
		Location:  s.Location,
		IsActive:  s.IsActive,
		CreatedAt: s.CreatedAt,
	}
}

func (s *Server) ToAdminResponse() ServerAdminResponse {
	return ServerAdminResponse{
		ID:             s.ID,
		Name:           s.Name,
		Location:       s.Location,
		IP:             s.IP,
		WireGuardPort:  s.WireGuardPort,
		ProxyPortStart: s.ProxyPortStart,
		ProxyPortEnd:   s.ProxyPortEnd,
		IsActive:       s.IsActive,
		CreatedAt:      s.CreatedAt,
		PhoneCount:     len(s.Phones),
	}
}
