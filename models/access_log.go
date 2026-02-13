package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AccessLog records proxy access events with domain/credential tracking
type AccessLog struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	CredentialID uuid.UUID `gorm:"type:uuid;not null;index" json:"credential_id"`
	PhoneID      uuid.UUID `gorm:"type:uuid;not null;index" json:"phone_id"`
	HubServerID  uuid.UUID `gorm:"type:uuid;index" json:"hub_server_id"`
	ClientIP     string    `gorm:"not null;index" json:"client_ip"`
	Domain       string    `gorm:"not null;index" json:"domain"`
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"` // "socks5" or "http"
	BytesIn      int64     `json:"bytes_in"`
	BytesOut     int64     `json:"bytes_out"`
	DurationMS   int64     `json:"duration_ms"`
	Blocked      bool      `gorm:"default:false" json:"blocked"`
	Timestamp    time.Time `gorm:"not null;index" json:"timestamp"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships (for querying)
	Credential ConnectionCredential `gorm:"foreignKey:CredentialID" json:"-"`
	Phone      Phone                `gorm:"foreignKey:PhoneID" json:"-"`
}

func (a *AccessLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

// AccessLogResponse is the public representation with denormalized data
type AccessLogResponse struct {
	ID             uuid.UUID `json:"id"`
	CredentialID   uuid.UUID `json:"credential_id"`
	CredentialName string    `json:"credential_name,omitempty"`
	PhoneID        uuid.UUID `json:"phone_id"`
	PhoneName      string    `json:"phone_name,omitempty"`
	ClientIP       string    `json:"client_ip"`
	Domain         string    `json:"domain"`
	Port           int       `json:"port"`
	Protocol       string    `json:"protocol"`
	BytesIn        int64     `json:"bytes_in"`
	BytesOut       int64     `json:"bytes_out"`
	DurationMS     int64     `json:"duration_ms"`
	Blocked        bool      `json:"blocked"`
	Timestamp      time.Time `json:"timestamp"`
}

// AccessLogBatchRequest is the request from hub-api to store access logs
type AccessLogBatchRequest struct {
	HubID     string           `json:"hub_id"`
	Timestamp time.Time        `json:"timestamp"`
	Logs      []AccessLogEntry `json:"logs"`
}

// AccessLogEntry is a single access log entry from hub-api
type AccessLogEntry struct {
	CredentialID string    `json:"credential_id"`
	PhoneID      string    `json:"phone_id"`
	ClientIP     string    `json:"client_ip"`
	Domain       string    `json:"domain"`
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"`
	BytesIn      uint64    `json:"bytes_in"`
	BytesOut     uint64    `json:"bytes_out"`
	Timestamp    time.Time `json:"timestamp"`
	DurationMS   int64     `json:"duration_ms"`
	Blocked      bool      `json:"blocked"`
}

// AccessLogFilter for querying access logs
type AccessLogFilter struct {
	PhoneID      *uuid.UUID
	CredentialID *uuid.UUID
	ClientIP     *string
	Domain       *string
	StartDate    *time.Time
	EndDate      *time.Time
	Blocked      *bool
	Limit        int
	Offset       int
}

// DomainStats aggregates access by domain
type DomainStats struct {
	Domain     string `json:"domain"`
	AccessCount int64  `json:"access_count"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	LastAccess time.Time `json:"last_access"`
}
