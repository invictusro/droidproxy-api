package infra

import (
	"fmt"
)

// WireGuardManager manages WireGuard configuration on servers
type WireGuardManager struct {
	client *SSHClient
}

// WireGuardServerConfig holds server WireGuard configuration
type WireGuardServerConfig struct {
	PrivateKey string
	PublicKey  string
	Address    string // e.g., "10.66.66.1/24"
	ListenPort int
}

// WireGuardPeerConfig holds peer (phone) configuration
type WireGuardPeerConfig struct {
	PublicKey  string
	AllowedIPs string // e.g., "10.66.66.2/32"
	IP         string // e.g., "10.66.66.2"
}

// NewWireGuardManager creates a new WireGuard manager
func NewWireGuardManager(client *SSHClient) *WireGuardManager {
	return &WireGuardManager{client: client}
}

// InitializeServer sets up WireGuard server configuration
func (w *WireGuardManager) InitializeServer(listenPort int, networkPrefix string) (*WireGuardServerConfig, error) {
	// Generate server keys
	result, err := w.client.Run("wg genkey")
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey := result.Stdout

	result, err = w.client.Run(fmt.Sprintf("echo '%s' | wg pubkey", privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey := result.Stdout

	// Create WireGuard config with /16 subnet for 65k+ phones
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s.0.1/16
ListenPort = %d
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`, privateKey, networkPrefix, listenPort)

	// Write config
	_, err = w.client.Run(fmt.Sprintf("echo '%s' > /etc/wireguard/wg0.conf", config))
	if err != nil {
		return nil, fmt.Errorf("failed to write WireGuard config: %w", err)
	}

	// Set permissions
	w.client.Run("chmod 600 /etc/wireguard/wg0.conf")

	// Enable and start WireGuard
	commands := []string{
		"systemctl enable wg-quick@wg0",
		"systemctl start wg-quick@wg0",
	}
	w.client.RunMultiple(commands)

	return &WireGuardServerConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    fmt.Sprintf("%s.0.1/16", networkPrefix),
		ListenPort: listenPort,
	}, nil
}

// GetServerPublicKey retrieves the server's WireGuard public key
func (w *WireGuardManager) GetServerPublicKey() (string, error) {
	result, err := w.client.Run("cat /etc/wireguard/wg0.conf | grep PrivateKey | cut -d'=' -f2 | tr -d ' ' | wg pubkey")
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("failed to get public key: %s", result.Stderr)
	}
	return result.Stdout, nil
}

// AddPeer adds a new peer (phone) to the WireGuard server
func (w *WireGuardManager) AddPeer(peerPublicKey, peerIP string) error {
	// Add peer to running interface
	cmd := fmt.Sprintf("wg set wg0 peer %s allowed-ips %s/32", peerPublicKey, peerIP)
	result, err := w.client.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("failed to add peer: %s", result.Stderr)
	}

	// Also add to config file for persistence
	peerConfig := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", peerPublicKey, peerIP)
	_, err = w.client.Run(fmt.Sprintf("echo '%s' >> /etc/wireguard/wg0.conf", peerConfig))
	if err != nil {
		return fmt.Errorf("failed to persist peer config: %w", err)
	}

	return nil
}

// RemovePeer removes a peer from WireGuard
func (w *WireGuardManager) RemovePeer(peerPublicKey string) error {
	// Remove from running interface
	cmd := fmt.Sprintf("wg set wg0 peer %s remove", peerPublicKey)
	result, err := w.client.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("failed to remove peer: %s", result.Stderr)
	}

	// Save config file
	w.client.Run("wg-quick save wg0")

	return nil
}

// GeneratePeerConfig generates a WireGuard config for a phone
func (w *WireGuardManager) GeneratePeerConfig(serverPublicKey, serverIP string, serverPort int, peerPrivateKey, peerIP string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/16

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, peerPrivateKey, peerIP, serverPublicKey, serverIP, serverPort)
}

// GenerateKeyPair generates a new WireGuard key pair
func (w *WireGuardManager) GenerateKeyPair() (privateKey, publicKey string, err error) {
	result, err := w.client.Run("wg genkey")
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey = result.Stdout

	result, err = w.client.Run(fmt.Sprintf("echo '%s' | wg pubkey", privateKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey = result.Stdout

	return privateKey, publicKey, nil
}

