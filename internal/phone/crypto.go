package phone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// PBKDF2 parameters
	pbkdf2Iterations = 100000
	pbkdf2KeyLength  = 32 // 256 bits for AES-256

	// Salt for key derivation (should be consistent between client and server)
	derivationSalt = "droidproxy-pairing-v1"
)

// DeriveKeyFromPIN derives an AES-256 key from PIN + pairing code using PBKDF2
func DeriveKeyFromPIN(pin, pairingCode string) []byte {
	password := []byte(pin + pairingCode)
	salt := []byte(derivationSalt + pairingCode)
	return pbkdf2.Key(password, salt, pbkdf2Iterations, pbkdf2KeyLength, sha256.New)
}

// DecryptPublicKey decrypts the phone's public key using AES-GCM
// The encrypted data format: base64(nonce || ciphertext || tag)
// Nonce is 12 bytes, tag is 16 bytes (included in ciphertext by Go's GCM)
func DecryptPublicKey(encryptedBase64, pin, pairingCode string) (string, error) {
	// Decode base64
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// Derive the key
	key := DeriveKeyFromPIN(pin, pairingCode)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce (first 12 bytes)
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong PIN?): %w", err)
	}

	return string(plaintext), nil
}

// ValidatePublicKey checks if the public key is a valid ECDSA public key in PEM format
func ValidatePublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// VerifySignature verifies an ECDSA signature over data using the phone's public key
// Signature format: base64(r || s) where r and s are 32 bytes each for P-256
func VerifySignature(publicKeyPEM, data, signatureBase64 string) (bool, error) {
	// Parse public key
	pubKey, err := ValidatePublicKey(publicKeyPEM)
	if err != nil {
		return false, err
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256([]byte(data))

	// Verify using ASN.1 format (what Android produces)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)

	return valid, nil
}
