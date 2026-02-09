package infra

import (
	"fmt"
	"strings"
)

// GostManager manages HTTP-to-SOCKS5 proxy instances using gost
type GostManager struct {
	client *SSHClient
}

// GostCredential represents a user credential for HTTP proxy
type GostCredential struct {
	Username string
	Password string
}

// NewGostManager creates a new gost proxy manager
func NewGostManager(client *SSHClient) *GostManager {
	return &GostManager{client: client}
}

// StartSocks5Forwarder sets up a SOCKS5 forwarder from external port to phone's WireGuard IP
// This allows external clients to connect to server:socks5Port and have traffic forwarded to phoneIP:1080
func (m *GostManager) StartSocks5Forwarder(phoneID string, socks5Port int, phoneWireGuardIP string, credentials []GostCredential) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-socks5-%s", phoneID)
	secretsFile := fmt.Sprintf("/etc/gost/socks5-secrets-%s.txt", phoneID)

	// Create secrets directory if it doesn't exist
	m.client.Run("mkdir -p /etc/gost")

	// Create secrets file with all credentials
	var secretsContent strings.Builder
	for _, cred := range credentials {
		secretsContent.WriteString(fmt.Sprintf("%s %s\n", cred.Username, cred.Password))
	}

	// Write secrets file
	if len(credentials) > 0 {
		_, err := m.client.Run(fmt.Sprintf("echo '%s' > %s && chmod 600 %s", secretsContent.String(), secretsFile, secretsFile))
		if err != nil {
			return nil, fmt.Errorf("failed to write secrets file: %w", err)
		}
	}

	// Create systemd service file
	var serviceContent string
	if len(credentials) > 0 {
		// With authentication via secrets file
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost SOCKS5 Forwarder for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "socks5://:%d?secrets=%s" -F "socks5://%s:1080"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, socks5Port, secretsFile, phoneWireGuardIP)
	} else {
		// Without authentication (IP whitelist mode)
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost SOCKS5 Forwarder for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "socks5://:%d" -F "socks5://%s:1080"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, socks5Port, phoneWireGuardIP)
	}

	commands := []string{
		fmt.Sprintf("echo '%s' > /etc/systemd/system/%s.service", serviceContent, serviceName),
		"systemctl daemon-reload",
		fmt.Sprintf("systemctl enable %s", serviceName),
		fmt.Sprintf("systemctl restart %s", serviceName),
	}

	results, err := m.client.RunMultiple(commands)
	if err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, nil
}

// StopSocks5Forwarder stops and removes the SOCKS5 forwarder service
func (m *GostManager) StopSocks5Forwarder(phoneID string) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-socks5-%s", phoneID)
	secretsFile := fmt.Sprintf("/etc/gost/socks5-secrets-%s.txt", phoneID)

	commands := []string{
		fmt.Sprintf("systemctl stop %s 2>/dev/null || true", serviceName),
		fmt.Sprintf("systemctl disable %s 2>/dev/null || true", serviceName),
		fmt.Sprintf("rm -f /etc/systemd/system/%s.service", serviceName),
		fmt.Sprintf("rm -f %s", secretsFile),
		"systemctl daemon-reload",
	}

	results, err := m.client.RunMultiple(commands)
	if err != nil {
		return nil, err
	}
	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, nil
}

// StartProxy starts an HTTP proxy that forwards to a SOCKS5 proxy
// socks5Port is the SOCKS5 port, httpPort is the HTTP proxy port
func (m *GostManager) StartProxy(phoneID string, socks5Port, httpPort int, username, password string) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-http-%s", phoneID)

	var serviceContent string
	if username != "" && password != "" {
		// With authentication - pass auth through to SOCKS5
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost HTTP Proxy for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "http://%s:%s@:%d" -F "socks5://%s:%s@127.0.0.1:%d"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, username, password, httpPort, username, password, socks5Port)
	} else {
		// Without authentication (IP whitelist mode)
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost HTTP Proxy for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "http://:%d" -F "socks5://127.0.0.1:%d"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, httpPort, socks5Port)
	}

	commands := []string{
		fmt.Sprintf("echo '%s' > /etc/systemd/system/%s.service", serviceContent, serviceName),
		"systemctl daemon-reload",
		fmt.Sprintf("systemctl enable %s", serviceName),
		fmt.Sprintf("systemctl start %s", serviceName),
	}

	results, err := m.client.RunMultiple(commands)
	if err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, nil
}

// StartProxyMultiUser starts an HTTP proxy with multiple user support via secrets file
func (m *GostManager) StartProxyMultiUser(phoneID string, socks5Port, httpPort int, credentials []GostCredential) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-http-%s", phoneID)
	secretsFile := fmt.Sprintf("/etc/gost/secrets-%s.txt", phoneID)

	// Create secrets file with all credentials
	var secretsContent strings.Builder
	for _, cred := range credentials {
		secretsContent.WriteString(fmt.Sprintf("%s %s\n", cred.Username, cred.Password))
	}

	// Write secrets file
	_, err := m.client.Run(fmt.Sprintf("echo '%s' > %s && chmod 600 %s", secretsContent.String(), secretsFile, secretsFile))
	if err != nil {
		return nil, fmt.Errorf("failed to write secrets file: %w", err)
	}

	// Create systemd service file with secrets file auth
	var serviceContent string
	if len(credentials) > 0 {
		// With authentication via secrets file
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost HTTP Proxy for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "http://:%d?secrets=%s" -F "socks5://127.0.0.1:%d"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, httpPort, secretsFile, socks5Port)
	} else {
		// Without authentication
		serviceContent = fmt.Sprintf(`[Unit]
Description=Gost HTTP Proxy for %s
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "http://:%d" -F "socks5://127.0.0.1:%d"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, phoneID, httpPort, socks5Port)
	}

	commands := []string{
		fmt.Sprintf("echo '%s' > /etc/systemd/system/%s.service", serviceContent, serviceName),
		"systemctl daemon-reload",
		fmt.Sprintf("systemctl enable %s", serviceName),
		fmt.Sprintf("systemctl restart %s", serviceName),
	}

	results, err := m.client.RunMultiple(commands)
	if err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, nil
}

// UpdateCredentials updates the credentials for an HTTP proxy
func (m *GostManager) UpdateCredentials(phoneID string, credentials []GostCredential) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-http-%s", phoneID)
	secretsFile := fmt.Sprintf("/etc/gost/secrets-%s.txt", phoneID)

	// Update secrets file
	var secretsContent strings.Builder
	for _, cred := range credentials {
		secretsContent.WriteString(fmt.Sprintf("%s %s\n", cred.Username, cred.Password))
	}

	_, err := m.client.Run(fmt.Sprintf("echo '%s' > %s", secretsContent.String(), secretsFile))
	if err != nil {
		return nil, fmt.Errorf("failed to update secrets file: %w", err)
	}

	// Restart the service to pick up new credentials
	return m.client.Run(fmt.Sprintf("systemctl restart %s", serviceName))
}

// StopProxy stops an HTTP proxy service
func (m *GostManager) StopProxy(phoneID string) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-http-%s", phoneID)
	secretsFile := fmt.Sprintf("/etc/gost/secrets-%s.txt", phoneID)

	commands := []string{
		fmt.Sprintf("systemctl stop %s", serviceName),
		fmt.Sprintf("systemctl disable %s", serviceName),
		fmt.Sprintf("rm -f /etc/systemd/system/%s.service", serviceName),
		fmt.Sprintf("rm -f %s", secretsFile),
		"systemctl daemon-reload",
	}

	results, err := m.client.RunMultiple(commands)
	if err != nil {
		return nil, err
	}
	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, nil
}

// GetStatus gets the status of an HTTP proxy service
func (m *GostManager) GetStatus(phoneID string) (*CommandResult, error) {
	serviceName := fmt.Sprintf("gost-http-%s", phoneID)
	return m.client.Run(fmt.Sprintf("systemctl is-active %s", serviceName))
}

// IsRunning checks if the HTTP proxy is running
func (m *GostManager) IsRunning(phoneID string) bool {
	result, err := m.GetStatus(phoneID)
	if err != nil {
		return false
	}
	return result.Stdout == "active"
}
