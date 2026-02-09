package phone

import (
	"time"
)

// Status represents the connection status of a phone
type Status string

const (
	StatusPending Status = "pending"
	StatusOnline  Status = "online"
	StatusOffline Status = "offline"
)

// HeartbeatData represents data received from a phone heartbeat
type HeartbeatData struct {
	PhoneID           string `json:"phone_id"`
	Status            string `json:"status"`
	CurrentIP         string `json:"current_ip"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}

// StatusUpdate represents a phone status update to send to dashboard
type StatusUpdate struct {
	PhoneID           string    `json:"phone_id"`
	Status            Status    `json:"status"`
	CurrentIP         string    `json:"current_ip"`
	ActiveConnections int       `json:"active_connections"`
	TotalConnections  int64     `json:"total_connections"`
	LastSeen          time.Time `json:"last_seen"`
}

// StatusTracker tracks phone statuses and notifies dashboards
type StatusTracker struct {
	realtime *RealtimeService
}

// NewStatusTracker creates a new status tracker
func NewStatusTracker(realtime *RealtimeService) *StatusTracker {
	return &StatusTracker{realtime: realtime}
}

// NotifyStatusChange sends a status update to the phone owner's dashboard
func (t *StatusTracker) NotifyStatusChange(userID string, update StatusUpdate) error {
	if t.realtime == nil {
		return nil
	}

	return t.realtime.PublishToUser(userID, map[string]interface{}{
		"type": "phone_status",
		"data": update,
	})
}

// NotifyIPChange sends an IP change notification to the dashboard
func (t *StatusTracker) NotifyIPChange(userID, phoneID, oldIP, newIP string) error {
	if t.realtime == nil {
		return nil
	}

	return t.realtime.PublishToUser(userID, map[string]interface{}{
		"type": "ip_changed",
		"data": map[string]string{
			"phone_id": phoneID,
			"old_ip":   oldIP,
			"new_ip":   newIP,
		},
	})
}

// CheckPhoneOnline checks if a phone was recently online based on last seen time
func CheckPhoneOnline(lastSeen *time.Time, timeout time.Duration) bool {
	if lastSeen == nil {
		return false
	}
	return time.Since(*lastSeen) < timeout
}
