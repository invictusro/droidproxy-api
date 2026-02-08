package services

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/centrifugal/gocent/v3"
	"github.com/droidproxy/api/config"
	"github.com/golang-jwt/jwt/v5"
)

var centrifugoClient *gocent.Client

// CommandType represents different commands sent to phones
type CommandType string

const (
	CmdRotateIP     CommandType = "ROTATE_IP"
	CmdRestartProxy CommandType = "RESTART_PROXY"
	CmdUpdateConfig CommandType = "UPDATE_CONFIG"
	CmdDisconnect   CommandType = "DISCONNECT"
)

// PhoneCommand is the structure sent to phones via Centrifugo
type PhoneCommand struct {
	Type    CommandType `json:"type"`
	PhoneID string      `json:"phone_id"`
	Data    interface{} `json:"data,omitempty"`
}

// InitCentrifugo initializes the Centrifugo client
func InitCentrifugo(cfg *config.Config) {
	centrifugoClient = gocent.New(gocent.Config{
		Addr: cfg.CentrifugoURL + "/api",
		Key:  cfg.CentrifugoAPIKey,
	})
	log.Println("Centrifugo client initialized")
}

// PublishToPhone sends a command to a specific phone
func PublishToPhone(phoneID string, cmd PhoneCommand) error {
	channel := "phone:" + phoneID
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	_, err = centrifugoClient.Publish(context.Background(), channel, data)
	if err != nil {
		log.Printf("Failed to publish to phone %s: %v", phoneID, err)
		return err
	}

	log.Printf("Published command %s to phone %s", cmd.Type, phoneID)
	return nil
}

// PublishToUser sends a status update to a user's dashboard
func PublishToUser(userID string, data interface{}) error {
	channel := "user:" + userID
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = centrifugoClient.Publish(context.Background(), channel, encoded)
	return err
}

// GenerateClientToken generates a JWT token for a client to connect to Centrifugo
func GenerateClientToken(userID, channel string) (string, error) {
	cfg := config.AppConfig
	if cfg == nil {
		return "", nil
	}

	// Token expires in 24 hours
	claims := jwt.MapClaims{
		"sub":     userID,
		"channel": channel,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Use the token secret from config (must match CENTRIFUGO_TOKEN_HMAC_SECRET_KEY)
	return token.SignedString([]byte(cfg.CentrifugoTokenSecret))
}

// SendRotateIP sends a rotate IP command to a phone
func SendRotateIP(phoneID string) error {
	return PublishToPhone(phoneID, PhoneCommand{
		Type:    CmdRotateIP,
		PhoneID: phoneID,
	})
}

// SendRestartProxy sends a restart proxy command to a phone
func SendRestartProxy(phoneID string) error {
	return PublishToPhone(phoneID, PhoneCommand{
		Type:    CmdRestartProxy,
		PhoneID: phoneID,
	})
}
