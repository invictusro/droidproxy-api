package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PhoneDataUsage tracks daily data consumption per phone
// Data older than last month is automatically cleaned up
type PhoneDataUsage struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID   uuid.UUID `gorm:"type:uuid;not null;index:idx_phone_date,unique" json:"phone_id"`
	Date      time.Time `gorm:"type:date;not null;index:idx_phone_date,unique" json:"date"` // Date only, no time
	BytesIn   int64     `gorm:"default:0" json:"bytes_in"`                                  // Bytes received by proxy
	BytesOut  int64     `gorm:"default:0" json:"bytes_out"`                                 // Bytes sent by proxy
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

func (u *PhoneDataUsage) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TotalBytes returns total bytes (in + out)
func (u *PhoneDataUsage) TotalBytes() int64 {
	return u.BytesIn + u.BytesOut
}

// PhoneUptimeLog tracks online/offline status changes
// Used to calculate uptime percentage
type PhoneUptimeLog struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID   uuid.UUID `gorm:"type:uuid;not null;index:idx_phone_uptime" json:"phone_id"`
	Status    string    `gorm:"not null" json:"status"`        // "online" or "offline"
	Timestamp time.Time `gorm:"not null;index" json:"timestamp"`
	IP        string    `json:"ip,omitempty"`                  // IP address when coming online

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

func (l *PhoneUptimeLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	return nil
}

// PhoneDailyUptime stores pre-calculated daily uptime for faster queries
type PhoneDailyUptime struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PhoneID       uuid.UUID `gorm:"type:uuid;not null;index:idx_phone_uptime_date,unique" json:"phone_id"`
	Date          time.Time `gorm:"type:date;not null;index:idx_phone_uptime_date,unique" json:"date"`
	OnlineMinutes int       `gorm:"default:0" json:"online_minutes"` // Minutes online (0-1440)
	UpdatedAt     time.Time `json:"updated_at"`

	// Relationships
	Phone Phone `gorm:"foreignKey:PhoneID" json:"-"`
}

func (u *PhoneDailyUptime) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// UptimePercentage returns uptime as percentage (0-100)
func (u *PhoneDailyUptime) UptimePercentage() float64 {
	return float64(u.OnlineMinutes) / 1440.0 * 100.0
}

// ========== Response Types ==========

// DataUsageResponse for API responses
type DataUsageResponse struct {
	PhoneID   string `json:"phone_id"`
	PhoneName string `json:"phone_name"`
	Period    string `json:"period"` // "today", "yesterday", "this_month", "last_month"
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	Total     int64  `json:"total"`
}

// DailyDataUsage for daily breakdown
type DailyDataUsage struct {
	Date     string `json:"date"` // YYYY-MM-DD
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Total    int64  `json:"total"`
}

// PhoneDataUsageDetail includes daily breakdown
type PhoneDataUsageDetail struct {
	PhoneID    string           `json:"phone_id"`
	PhoneName  string           `json:"phone_name"`
	ThisMonth  DataUsageSummary `json:"this_month"`
	LastMonth  DataUsageSummary `json:"last_month"`
	DailyUsage []DailyDataUsage `json:"daily_usage"` // Last 30 days
}

// DataUsageSummary for month summaries
type DataUsageSummary struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Total    int64 `json:"total"`
}

// UptimeResponse for API responses
type UptimeResponse struct {
	PhoneID       string  `json:"phone_id"`
	PhoneName     string  `json:"phone_name"`
	Last24Hours   float64 `json:"last_24_hours"`   // Percentage
	Last7Days     float64 `json:"last_7_days"`     // Percentage
	CurrentStatus string  `json:"current_status"`  // "online" or "offline"
	LastSeen      string  `json:"last_seen,omitempty"`
}

// DailyUptime for daily breakdown
type DailyUptime struct {
	Date             string  `json:"date"` // YYYY-MM-DD
	OnlineMinutes    int     `json:"online_minutes"`
	UptimePercentage float64 `json:"uptime_percentage"`
}

// PhoneUptimeDetail includes daily breakdown
type PhoneUptimeDetail struct {
	PhoneID       string        `json:"phone_id"`
	PhoneName     string        `json:"phone_name"`
	Last24Hours   float64       `json:"last_24_hours"`
	Last7Days     float64       `json:"last_7_days"`
	CurrentStatus string        `json:"current_status"`
	DailyUptime   []DailyUptime `json:"daily_uptime"` // Last 7 days
}

// AllPhonesUsageResponse for dashboard overview
type AllPhonesUsageResponse struct {
	Phones     []PhoneUsageSummary `json:"phones"`
	TotalIn    int64               `json:"total_in"`
	TotalOut   int64               `json:"total_out"`
	TotalBytes int64               `json:"total_bytes"`
}

// PhoneUsageSummary for overview
type PhoneUsageSummary struct {
	PhoneID       string  `json:"phone_id"`
	PhoneName     string  `json:"phone_name"`
	TodayBytes    int64   `json:"today_bytes"`
	MonthBytes    int64   `json:"month_bytes"`
	UptimePct     float64 `json:"uptime_pct"` // Last 7 days
	CurrentStatus string  `json:"current_status"`
}
