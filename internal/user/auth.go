package user

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthProvider represents the authentication provider
type AuthProvider string

const (
	AuthLocal  AuthProvider = "local"
	AuthGoogle AuthProvider = "google"
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// AuthService handles user authentication
type AuthService struct {
	jwtSecret     string
	tokenDuration time.Duration
}

// NewAuthService creates a new authentication service
func NewAuthService(jwtSecret string) *AuthService {
	return &AuthService{
		jwtSecret:     jwtSecret,
		tokenDuration: 24 * time.Hour,
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken generates a JWT token for a user
func (s *AuthService) GenerateToken(userID, email, role string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

// ValidateToken validates a JWT token and returns the claims
func (s *AuthService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken generates a new token with extended expiry
func (s *AuthService) RefreshToken(claims *JWTClaims) (string, error) {
	return s.GenerateToken(claims.UserID, claims.Email, claims.Role)
}
