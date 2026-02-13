package infra

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HubAgentTelemetry represents the telemetry data from hub-agent
type HubAgentTelemetry struct {
	Status           string  `json:"status"`
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryPercent    float64 `json:"memory_percent"`
	DiskPercent      float64 `json:"disk_percent,omitempty"`
	BandwidthInRate  float64 `json:"bandwidth_in_rate,omitempty"`
	BandwidthOutRate float64 `json:"bandwidth_out_rate,omitempty"`
	WireGuardStatus  string  `json:"wireguard_status"`
}

// GetHubAgentTelemetry fetches telemetry from a hub-agent
func GetHubAgentTelemetry(ip string, port int, apiKey string) (*HubAgentTelemetry, error) {
	url := fmt.Sprintf("http://%s:%d/health", ip, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Hub-API-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hub-agent returned %d: %s", resp.StatusCode, string(body))
	}

	var telemetry HubAgentTelemetry
	if err := json.NewDecoder(resp.Body).Decode(&telemetry); err != nil {
		return nil, err
	}

	return &telemetry, nil
}

// GenerateAPIKey generates a secure random API key
func GenerateAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based key (less secure but functional)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// HubAgentProvisioner handles hub-agent installation
type HubAgentProvisioner struct {
	ssh *SSHClient
}

// NewHubAgentProvisioner creates a new provisioner
func NewHubAgentProvisioner(ssh *SSHClient) *HubAgentProvisioner {
	return &HubAgentProvisioner{ssh: ssh}
}

// AddWireGuardPeerV2 adds a WireGuard peer using the V2 wgctrl-based API
func AddWireGuardPeerV2(ip string, port int, apiKey string, publicKey, allowedIPs string) error {
	url := fmt.Sprintf("http://%s:%d/v2/wireguard/peers", ip, port)

	body := map[string]interface{}{
		"public_key": publicKey,
		"allowed_ips": allowedIPs,
		"persistent_keepalive": 25, // For NAT traversal
	}

	return doHubAgentRequest("POST", url, apiKey, body)
}

// RemoveWireGuardPeerV2 removes a WireGuard peer using the V2 wgctrl-based API
func RemoveWireGuardPeerV2(ip string, port int, apiKey string, publicKey string) error {
	url := fmt.Sprintf("http://%s:%d/v2/wireguard/peers/%s", ip, port, publicKey)
	return doHubAgentRequest("DELETE", url, apiKey, nil)
}

// StartProxyV2 starts a proxy using the V2 proxy engine
func StartProxyV2(ip string, port int, apiKey string, proxyConfig map[string]interface{}) error {
	url := fmt.Sprintf("http://%s:%d/v2/proxy/start", ip, port)
	return doHubAgentRequest("POST", url, apiKey, proxyConfig)
}

// StopProxyV2 stops a proxy using the V2 proxy engine
func StopProxyV2(ip string, hubAPIPort int, apiKey string, proxyPort int) error {
	url := fmt.Sprintf("http://%s:%d/v2/proxy/%d", ip, hubAPIPort, proxyPort)
	return doHubAgentRequest("DELETE", url, apiKey, nil)
}

// UpdateProxyCredentialsV2 updates credentials for a proxy
func UpdateProxyCredentialsV2(ip string, hubAPIPort int, apiKey string, proxyPort int, credentials []map[string]interface{}) error {
	url := fmt.Sprintf("http://%s:%d/v2/proxy/%d/credentials", ip, hubAPIPort, proxyPort)
	body := map[string]interface{}{
		"credentials": credentials,
	}
	return doHubAgentRequest("PUT", url, apiKey, body)
}

// doHubAgentRequest performs a request to the hub-agent API
func doHubAgentRequest(method, url, apiKey string, body interface{}) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Hub-API-Key", apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub-agent returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Install downloads and installs hub-agent on the remote server
func (p *HubAgentProvisioner) Install(binaryURL, hubID, apiKey string, port int) error {
	// Create directory
	if _, err := p.ssh.Run("mkdir -p /etc/hub-agent"); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Download binary
	downloadCmd := fmt.Sprintf("curl -L -o /usr/local/bin/hub-agent '%s' && chmod +x /usr/local/bin/hub-agent", binaryURL)
	if _, err := p.ssh.Run(downloadCmd); err != nil {
		return fmt.Errorf("failed to download hub-agent: %w", err)
	}

	// Create config file
	configContent := fmt.Sprintf(`HUB_ID=%s
HUB_API_KEY=%s
MAIN_API_URL=https://api.droidproxy.com
HUB_API_PORT=%d
HEARTBEAT_INTERVAL=10
`, hubID, apiKey, port)

	configCmd := fmt.Sprintf("cat > /etc/hub-agent/config.env << 'EOF'\n%sEOF", configContent)
	if _, err := p.ssh.Run(configCmd); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	// Create systemd service with production settings
	serviceContent := `[Unit]
Description=DroidProxy Hub Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/hub-agent/config.env
ExecStart=/usr/local/bin/hub-agent
Restart=always
RestartSec=5
# CRITICAL: Allow thousands of simultaneous connections
# Default Linux limit is 1024, which is too low for 500+ phones
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`

	serviceCmd := fmt.Sprintf("cat > /etc/systemd/system/hub-agent.service << 'EOF'\n%sEOF", serviceContent)
	if _, err := p.ssh.Run(serviceCmd); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	// Reload systemd and start service
	if _, err := p.ssh.Run("systemctl daemon-reload && systemctl enable hub-agent && systemctl start hub-agent"); err != nil {
		return fmt.Errorf("failed to start hub-agent service: %w", err)
	}

	// Open firewall port
	firewallCmd := fmt.Sprintf("ufw allow %d/tcp 2>/dev/null || true", port)
	p.ssh.Run(firewallCmd) // Ignore errors, firewall might not be enabled

	// Wait a moment for service to start
	time.Sleep(2 * time.Second)

	// Verify service is running
	result, err := p.ssh.Run("systemctl is-active hub-agent")
	if err != nil || result.Stdout != "active\n" {
		// Try to get logs for debugging
		logs, _ := p.ssh.Run("journalctl -u hub-agent -n 20 --no-pager")
		return fmt.Errorf("hub-agent failed to start. Logs: %s", logs.Stdout)
	}

	return nil
}
