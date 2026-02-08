package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

type AuthProvider string

const (
	AuthLocal  AuthProvider = "local"
	AuthGoogle AuthProvider = "google"
)

type User struct {
	ID           uuid.UUID    `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email        string       `gorm:"uniqueIndex;not null" json:"email"`
	Name         string       `gorm:"not null" json:"name"`
	Password     string       `gorm:"" json:"-"`
	Picture      string       `json:"picture"`
	Role         UserRole     `gorm:"default:user" json:"role"`
	AuthProvider AuthProvider `gorm:"default:local" json:"auth_provider"`
	GoogleID     *string      `gorm:"uniqueIndex" json:"-"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`

	// Relationships
	Phones []Phone `gorm:"foreignKey:UserID" json:"phones,omitempty"`
}

// HashPassword hashes the user's password
func (u *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(bytes)
	return nil
}

// CheckPassword compares password with hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// UserResponse is the public representation of a user
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Picture   string    `json:"picture"`
	Role      UserRole  `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Picture:   u.Picture,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}
}
