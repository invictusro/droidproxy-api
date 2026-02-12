package phone

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// PairingInfo contains the information needed for phone pairing
type PairingInfo struct {
	PhoneID     string `json:"phone_id"`
	PairingCode string `json:"pairing_code"`
	PairingPIN  string `json:"pairing_pin"`
	QRCodeData  string `json:"qr_code_data"`
}

// PairingResult contains the result of a successful pairing
type PairingResult struct {
	PhoneID         string `json:"phone_id"`
	APIToken        string `json:"api_token"`
	WireGuardConfig string `json:"wireguard_config"`
	CentrifugoURL   string `json:"centrifugo_url"`
	CentrifugoToken string `json:"centrifugo_token"`
	APIBaseURL      string `json:"api_base_url"`
	ServerIP        string `json:"server_ip"`
}

// GeneratePairingCode generates a unique pairing code for QR scanning
func GeneratePairingCode() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GeneratePairingPIN generates a 4-digit PIN for verification
func GeneratePairingPIN() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return fmt.Sprintf("%04d", n.Int64())
}

// GenerateAPIToken generates a secure API token for phone authentication
func GenerateAPIToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// HashDeviceFingerprint creates a hash of the device fingerprint for storage
func HashDeviceFingerprint(fingerprint string) string {
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// GetQRCodeData generates the QR code data string for pairing
func GetQRCodeData(apiBaseURL, phoneID, pairingCode string) string {
	return fmt.Sprintf("droidproxy://%s/pair?phone_id=%s&code=%s", apiBaseURL, phoneID, pairingCode)
}

// ValidatePIN checks if a PIN has the correct format (4 digits)
func ValidatePIN(pin string) bool {
	if len(pin) != 4 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
