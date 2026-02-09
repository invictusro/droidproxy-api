package user

import (
	"time"
)

// Role represents a user role
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User represents a system user
type User struct {
	ID           string       `json:"id"`
	Email        string       `json:"email"`
	Name         string       `json:"name"`
	Role         Role         `json:"role"`
	AuthProvider AuthProvider `json:"auth_provider"`
	CreatedAt    time.Time    `json:"created_at"`
	LastLoginAt  *time.Time   `json:"last_login_at,omitempty"`
}

// UserProfile is the public profile information
type UserProfile struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// IsAdmin checks if the user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// ToProfile converts a User to a UserProfile
func (u *User) ToProfile() UserProfile {
	return UserProfile{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}
}

// UserStats contains statistics about a user's resources
type UserStats struct {
	TotalPhones   int   `json:"total_phones"`
	OnlinePhones  int   `json:"online_phones"`
	TotalBandwidth int64 `json:"total_bandwidth"`
}

// ValidateEmail performs basic email validation
func ValidateEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	// Basic check for @ symbol
	atIndex := -1
	for i, c := range email {
		if c == '@' {
			if atIndex != -1 {
				return false // Multiple @ symbols
			}
			atIndex = i
		}
	}
	return atIndex > 0 && atIndex < len(email)-1
}

// ValidatePassword checks if a password meets requirements
func ValidatePassword(password string) bool {
	// Minimum 8 characters
	return len(password) >= 8
}

// ValidateName checks if a name is valid
func ValidateName(name string) bool {
	return len(name) >= 1 && len(name) <= 100
}
