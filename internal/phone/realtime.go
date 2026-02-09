package phone

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/centrifugal/gocent/v3"
	"github.com/golang-jwt/jwt/v5"
)

// RealtimeService handles Centrifugo real-time communication
type RealtimeService struct {
	client      *gocent.Client
	tokenSecret string
}

var defaultRealtime *RealtimeService

// InitRealtime initializes the global realtime service
func InitRealtime(centrifugoURL, apiKey, tokenSecret string) {
	apiURL := centrifugoURL + "/api"
	client := gocent.New(gocent.Config{
		Addr: apiURL,
		Key:  apiKey,
	})
	defaultRealtime = &RealtimeService{
		client:      client,
		tokenSecret: tokenSecret,
	}
	log.Printf("[Phone] Realtime service initialized")
}

// NewRealtimeService creates a new realtime service instance
func NewRealtimeService(centrifugoURL, apiKey, tokenSecret string) *RealtimeService {
	apiURL := centrifugoURL + "/api"
	client := gocent.New(gocent.Config{
		Addr: apiURL,
		Key:  apiKey,
	})
	return &RealtimeService{
		client:      client,
		tokenSecret: tokenSecret,
	}
}

// GeneratePhoneToken generates a JWT token for a phone to connect to Centrifugo
func (r *RealtimeService) GeneratePhoneToken(phoneID string) (string, error) {
	channel := "phone:" + phoneID

	claims := jwt.MapClaims{
		"sub":     phoneID,
		"channel": channel,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(r.tokenSecret))
}

// GenerateUserToken generates a JWT token for a dashboard user to connect to Centrifugo
func (r *RealtimeService) GenerateUserToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(r.tokenSecret))
}

// PublishToPhone sends data to a phone's channel
func (r *RealtimeService) PublishToPhone(phoneID string, data interface{}) error {
	channel := "phone:" + phoneID
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = r.client.Publish(context.Background(), channel, encoded)
	return err
}

// PublishToUser sends data to a user's dashboard channel
func (r *RealtimeService) PublishToUser(userID string, data interface{}) error {
	channel := "user:" + userID
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = r.client.Publish(context.Background(), channel, encoded)
	return err
}

// Global convenience functions

// GeneratePhoneToken generates a phone token using the default service
func GeneratePhoneToken(phoneID string) (string, error) {
	if defaultRealtime == nil {
		return "", nil
	}
	return defaultRealtime.GeneratePhoneToken(phoneID)
}

// GenerateUserToken generates a user token using the default service
func GenerateUserToken(userID string) (string, error) {
	if defaultRealtime == nil {
		return "", nil
	}
	return defaultRealtime.GenerateUserToken(userID)
}

// PublishToPhone publishes to a phone using the default service
func PublishToPhone(phoneID string, data interface{}) error {
	if defaultRealtime == nil {
		return nil
	}
	return defaultRealtime.PublishToPhone(phoneID, data)
}

// PublishToUser publishes to a user using the default service
func PublishToUser(userID string, data interface{}) error {
	if defaultRealtime == nil {
		return nil
	}
	return defaultRealtime.PublishToUser(userID, data)
}
