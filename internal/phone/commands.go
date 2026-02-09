package phone

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/centrifugal/gocent/v3"
)

// CommandType represents the type of command sent to phones
type CommandType string

const (
	CommandRotateIP           CommandType = "rotate_ip"
	CommandRestart            CommandType = "restart"
	CommandCredentialsUpdate  CommandType = "credentials_update"
	CommandConfigUpdate       CommandType = "config_update"
)

// Command represents a command sent to a phone via Centrifugo
type Command struct {
	Command CommandType `json:"command"`
	PhoneID string      `json:"phone_id,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Commander handles sending commands to phones via Centrifugo
type Commander struct {
	client *gocent.Client
}

var defaultCommander *Commander

// InitCommander initializes the global commander instance
func InitCommander(centrifugoURL, apiKey string) {
	apiURL := centrifugoURL + "/api"
	client := gocent.New(gocent.Config{
		Addr: apiURL,
		Key:  apiKey,
	})
	defaultCommander = &Commander{client: client}
	log.Printf("[Phone] Commander initialized: %s", apiURL)
}

// NewCommander creates a new Commander instance
func NewCommander(centrifugoURL, apiKey string) *Commander {
	apiURL := centrifugoURL + "/api"
	client := gocent.New(gocent.Config{
		Addr: apiURL,
		Key:  apiKey,
	})
	return &Commander{client: client}
}

// SendCommand sends a command to a specific phone
func (c *Commander) SendCommand(phoneID string, cmd Command) error {
	if c.client == nil {
		return fmt.Errorf("commander not initialized")
	}

	channel := "phone:" + phoneID
	data, err := json.Marshal(cmd)
	if err != nil {
		log.Printf("[Phone] Failed to marshal command: %v", err)
		return err
	}

	log.Printf("[Phone] Sending command %s to %s", cmd.Command, phoneID)

	result, err := c.client.Publish(context.Background(), channel, data)
	if err != nil {
		log.Printf("[Phone] Failed to send command to %s: %v", phoneID, err)
		return err
	}

	log.Printf("[Phone] Command %s sent to %s (offset: %d)", cmd.Command, phoneID, result.Offset)
	return nil
}

// SendRotateIP sends a rotate IP command to a phone
func (c *Commander) SendRotateIP(phoneID string) error {
	return c.SendCommand(phoneID, Command{
		Command: CommandRotateIP,
	})
}

// SendRestart sends a restart proxy command to a phone
func (c *Commander) SendRestart(phoneID string) error {
	return c.SendCommand(phoneID, Command{
		Command: CommandRestart,
	})
}

// SendCredentialsUpdate notifies a phone that its credentials have been updated
func (c *Commander) SendCredentialsUpdate(phoneID string, credentials interface{}) error {
	return c.SendCommand(phoneID, Command{
		Command: CommandCredentialsUpdate,
		Data:    credentials,
	})
}

// SendConfigUpdate notifies a phone that its configuration has been updated
func (c *Commander) SendConfigUpdate(phoneID string, config interface{}) error {
	return c.SendCommand(phoneID, Command{
		Command: CommandConfigUpdate,
		Data:    config,
	})
}

// Global convenience functions using the default commander

// SendRotateIP sends a rotate IP command using the default commander
func SendRotateIP(phoneID string) error {
	if defaultCommander == nil {
		return fmt.Errorf("commander not initialized")
	}
	return defaultCommander.SendRotateIP(phoneID)
}

// SendRestart sends a restart command using the default commander
func SendRestart(phoneID string) error {
	if defaultCommander == nil {
		return fmt.Errorf("commander not initialized")
	}
	return defaultCommander.SendRestart(phoneID)
}

// SendCredentialsUpdate sends credentials update using the default commander
func SendCredentialsUpdate(phoneID string, credentials interface{}) error {
	if defaultCommander == nil {
		return fmt.Errorf("commander not initialized")
	}
	return defaultCommander.SendCredentialsUpdate(phoneID, credentials)
}

// SendConfigUpdate sends config update using the default commander
func SendConfigUpdate(phoneID string, config interface{}) error {
	if defaultCommander == nil {
		return fmt.Errorf("commander not initialized")
	}
	return defaultCommander.SendConfigUpdate(phoneID, config)
}
