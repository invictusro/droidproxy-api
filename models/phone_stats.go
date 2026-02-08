package models

import (
	"time"

	"github.com/google/uuid"
)

type PhoneStats struct {
	ID                int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	PhoneID           uuid.UUID `gorm:"type:uuid;not null;index" json:"phone_id"`
	ActiveConnections int       `gorm:"default:0" json:"active_connections"`
	TotalConnections  int64     `gorm:"default:0" json:"total_connections"`
	RecordedAt        time.Time `gorm:"default:now()" json:"recorded_at"`

	// Relationship
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

// StatsResponse for API
type StatsResponse struct {
	PhoneID           uuid.UUID `json:"phone_id"`
	ActiveConnections int       `json:"active_connections"`
	TotalConnections  int64     `json:"total_connections"`
	RecordedAt        time.Time `json:"recorded_at"`
}

func (s *PhoneStats) ToResponse() StatsResponse {
	return StatsResponse{
		PhoneID:           s.PhoneID,
		ActiveConnections: s.ActiveConnections,
		TotalConnections:  s.TotalConnections,
		RecordedAt:        s.RecordedAt,
	}
}
