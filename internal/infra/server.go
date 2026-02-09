package infra

import (
	"fmt"
	"log"
)

// ServerSetup orchestrates complete server setup
type ServerSetup struct {
	client *SSHClient
}

// NewServerSetup creates a new server setup helper
func NewServerSetup(client *SSHClient) *ServerSetup {
	return &ServerSetup{client: client}
}

// InstallBasics installs basic packages needed for the proxy server
func (s *ServerSetup) InstallBasics() ([]*CommandResult, error) {
	commands := []string{
		"apt-get update",
		"DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget ufw fail2ban",
	}
	return s.client.RunMultiple(commands)
}

// InstallDocker installs Docker and Docker Compose
func (s *ServerSetup) InstallDocker() ([]*CommandResult, error) {
	commands := []string{
		"curl -fsSL https://get.docker.com | sh",
		"systemctl enable docker",
		"systemctl start docker",
	}
	return s.client.RunMultiple(commands)
}

// InstallWireGuard installs WireGuard
func (s *ServerSetup) InstallWireGuard() ([]*CommandResult, error) {
	commands := []string{
		"DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard",
		"echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
		"sysctl -p",
	}
	return s.client.RunMultiple(commands)
}

// InstallGost installs gost for HTTP-to-SOCKS5 conversion
func (s *ServerSetup) InstallGost() ([]*CommandResult, error) {
	commands := []string{
		// Download latest gost binary
		"curl -Lo /usr/local/bin/gost https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz",
		"gunzip -f /usr/local/bin/gost.gz 2>/dev/null || true",
		"chmod +x /usr/local/bin/gost",
		// Create systemd service directory
		"mkdir -p /etc/gost",
	}
	return s.client.RunMultiple(commands)
}

// ConfigureFirewall sets up basic firewall rules
func (s *ServerSetup) ConfigureFirewall(proxyPortStart, proxyPortEnd int) ([]*CommandResult, error) {
	commands := []string{
		"ufw --force reset",
		"ufw default deny incoming",
		"ufw default allow outgoing",
		"ufw allow 22/tcp",                                                           // SSH
		"ufw allow 80/tcp",                                                           // HTTP
		"ufw allow 443/tcp",                                                          // HTTPS
		"ufw allow 51820/udp",                                                        // WireGuard
		fmt.Sprintf("ufw allow %d:%d/tcp", proxyPortStart, proxyPortEnd),             // SOCKS5 proxy ports
		fmt.Sprintf("ufw allow %d:%d/tcp", proxyPortStart+7000, proxyPortEnd+7000),   // HTTP proxy ports
		"ufw --force enable",
	}
	return s.client.RunMultiple(commands)
}

// SetupSystemLimits configures system limits for high connection counts
func (s *ServerSetup) SetupSystemLimits() ([]*CommandResult, error) {
	sysctlConfig := `
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.ip_forward = 1
`
	limitsConfig := `
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
`
	commands := []string{
		fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", sysctlConfig),
		"sysctl -p",
		fmt.Sprintf("echo '%s' >> /etc/security/limits.conf", limitsConfig),
	}
	return s.client.RunMultiple(commands)
}

// FullSetup runs the complete server setup
func (s *ServerSetup) FullSetup(proxyPortStart, proxyPortEnd int) error {
	log.Println("[Infra] Starting full server setup...")

	log.Println("[Infra] Installing basic packages...")
	if _, err := s.InstallBasics(); err != nil {
		return fmt.Errorf("failed to install basics: %w", err)
	}

	log.Println("[Infra] Installing Docker...")
	if _, err := s.InstallDocker(); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	log.Println("[Infra] Installing WireGuard...")
	if _, err := s.InstallWireGuard(); err != nil {
		return fmt.Errorf("failed to install WireGuard: %w", err)
	}

	log.Println("[Infra] Installing gost...")
	if _, err := s.InstallGost(); err != nil {
		return fmt.Errorf("failed to install gost: %w", err)
	}

	log.Println("[Infra] Setting up system limits...")
	if _, err := s.SetupSystemLimits(); err != nil {
		return fmt.Errorf("failed to setup system limits: %w", err)
	}

	log.Println("[Infra] Configuring firewall...")
	if _, err := s.ConfigureFirewall(proxyPortStart, proxyPortEnd); err != nil {
		return fmt.Errorf("failed to configure firewall: %w", err)
	}

	log.Println("[Infra] Server setup complete!")
	return nil
}

// GetSystemInfo retrieves basic system information
func (s *ServerSetup) GetSystemInfo() (map[string]string, error) {
	info := make(map[string]string)

	// Get OS info
	result, err := s.client.Run("cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'")
	if err == nil && result.ExitCode == 0 {
		info["os"] = result.Stdout
	}

	// Get kernel version
	result, err = s.client.Run("uname -r")
	if err == nil && result.ExitCode == 0 {
		info["kernel"] = result.Stdout
	}

	// Get uptime
	result, err = s.client.Run("uptime -p")
	if err == nil && result.ExitCode == 0 {
		info["uptime"] = result.Stdout
	}

	// Get memory info
	result, err = s.client.Run("free -h | awk '/Mem:/ {print $2}'")
	if err == nil && result.ExitCode == 0 {
		info["memory"] = result.Stdout
	}

	// Get disk usage
	result, err = s.client.Run("df -h / | awk 'NR==2 {print $5}'")
	if err == nil && result.ExitCode == 0 {
		info["disk_usage"] = result.Stdout
	}

	return info, nil
}

// CheckServices checks the status of key services
func (s *ServerSetup) CheckServices() (map[string]bool, error) {
	services := map[string]bool{
		"docker":      false,
		"wg-quick@wg0": false,
		"ufw":         false,
	}

	for name := range services {
		result, err := s.client.Run(fmt.Sprintf("systemctl is-active %s", name))
		if err == nil && result.Stdout == "active" {
			services[name] = true
		}
	}

	return services, nil
}
