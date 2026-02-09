package infra

import "fmt"

// FirewallManager manages UFW firewall rules on servers
type FirewallManager struct {
	client *SSHClient
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager(client *SSHClient) *FirewallManager {
	return &FirewallManager{client: client}
}

// AllowPort opens a port in the firewall
func (f *FirewallManager) AllowPort(port int, protocol string) (*CommandResult, error) {
	return f.client.Run(fmt.Sprintf("ufw allow %d/%s", port, protocol))
}

// DenyPort closes a port in the firewall
func (f *FirewallManager) DenyPort(port int, protocol string) (*CommandResult, error) {
	return f.client.Run(fmt.Sprintf("ufw deny %d/%s", port, protocol))
}

// DeleteRule removes a firewall rule
func (f *FirewallManager) DeleteRule(port int, protocol string) (*CommandResult, error) {
	return f.client.Run(fmt.Sprintf("ufw delete allow %d/%s", port, protocol))
}

// GetStatus gets the current firewall status
func (f *FirewallManager) GetStatus() (*CommandResult, error) {
	return f.client.Run("ufw status numbered")
}

// AllowPortRange opens a range of ports in the firewall
func (f *FirewallManager) AllowPortRange(startPort, endPort int, protocol string) (*CommandResult, error) {
	return f.client.Run(fmt.Sprintf("ufw allow %d:%d/%s", startPort, endPort, protocol))
}

// Enable enables the firewall
func (f *FirewallManager) Enable() (*CommandResult, error) {
	return f.client.Run("ufw --force enable")
}

// Disable disables the firewall
func (f *FirewallManager) Disable() (*CommandResult, error) {
	return f.client.Run("ufw disable")
}

// Reset resets all firewall rules
func (f *FirewallManager) Reset() (*CommandResult, error) {
	return f.client.Run("ufw --force reset")
}

// SetDefaults sets default policies (deny incoming, allow outgoing)
func (f *FirewallManager) SetDefaults() ([]*CommandResult, error) {
	commands := []string{
		"ufw default deny incoming",
		"ufw default allow outgoing",
	}
	return f.client.RunMultiple(commands)
}
