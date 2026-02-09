package infra

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// WireGuardKeyPair contains a WireGuard private and public key
type WireGuardKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateWireGuardKeyPair generates a new WireGuard keypair locally (without SSH)
func GenerateWireGuardKeyPair() (*WireGuardKeyPair, error) {
	// Generate 32 random bytes for private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, err
	}

	// Clamp the private key as per WireGuard spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key using Curve25519
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &WireGuardKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}, nil
}
