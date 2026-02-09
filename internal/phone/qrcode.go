package phone

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/skip2/go-qrcode"
)

// QRCodeData is the data encoded in the pairing QR code
type QRCodeData struct {
	APIBaseURL  string `json:"api_url"`
	PhoneID     string `json:"phone_id"`
	PairingCode string `json:"code"`
}

// GenerateQRCode generates a QR code PNG as base64
func GenerateQRCode(apiBaseURL, phoneID, pairingCode string) (string, error) {
	data := QRCodeData{
		APIBaseURL:  apiBaseURL,
		PhoneID:     phoneID,
		PairingCode: pairingCode,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal QR data: %w", err)
	}

	// Generate QR code PNG
	png, err := qrcode.Encode(string(jsonData), qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Convert to base64 data URL
	base64Data := base64.StdEncoding.EncodeToString(png)
	return "data:image/png;base64," + base64Data, nil
}

// GetQRCodeDataString returns the raw JSON string for the QR code
func GetQRCodeDataString(apiBaseURL, phoneID, pairingCode string) (string, error) {
	data := QRCodeData{
		APIBaseURL:  apiBaseURL,
		PhoneID:     phoneID,
		PairingCode: pairingCode,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
