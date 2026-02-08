package middleware

import (
	"net/http"
	"strings"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// AuthRequired middleware validates JWT tokens
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.AppConfig.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Get user from database
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		var user models.User
		if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		// Store user in context
		c.Set("user", &user)
		c.Set("userID", user.ID)
		c.Next()
	}
}

// GetCurrentUser retrieves the authenticated user from context
func GetCurrentUser(c *gin.Context) *models.User {
	user, exists := c.Get("user")
	if !exists {
		return nil
	}
	return user.(*models.User)
}

// GetCurrentUserID retrieves the authenticated user ID from context
func GetCurrentUserID(c *gin.Context) uuid.UUID {
	userID, exists := c.Get("userID")
	if !exists {
		return uuid.Nil
	}
	return userID.(uuid.UUID)
}

// PhoneAuthRequired middleware validates phone API tokens
// Phones must provide X-Phone-ID and X-Phone-Token headers
func PhoneAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		phoneID := c.GetHeader("X-Phone-ID")
		phoneToken := c.GetHeader("X-Phone-Token")

		if phoneID == "" || phoneToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone authentication required"})
			c.Abort()
			return
		}

		// Validate phone ID format
		parsedPhoneID, err := uuid.Parse(phoneID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone ID"})
			c.Abort()
			return
		}

		// Find phone and validate token
		var phone models.Phone
		if err := database.DB.Preload("Server").First(&phone, "id = ?", parsedPhoneID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not found"})
			c.Abort()
			return
		}

		// Verify the phone is paired
		if phone.PairedAt == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone not paired"})
			c.Abort()
			return
		}

		// Constant-time comparison to prevent timing attacks
		if phone.APIToken == "" || phone.APIToken != phoneToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone token"})
			c.Abort()
			return
		}

		// Store phone in context
		c.Set("phone", &phone)
		c.Set("phoneID", phone.ID)
		c.Next()
	}
}

// GetCurrentPhone retrieves the authenticated phone from context
func GetCurrentPhone(c *gin.Context) *models.Phone {
	phone, exists := c.Get("phone")
	if !exists {
		return nil
	}
	return phone.(*models.Phone)
}

// GetCurrentPhoneID retrieves the authenticated phone ID from context
func GetCurrentPhoneID(c *gin.Context) uuid.UUID {
	phoneID, exists := c.Get("phoneID")
	if !exists {
		return uuid.Nil
	}
	return phoneID.(uuid.UUID)
}
