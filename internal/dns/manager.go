package dns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Manager handles DNS operations for proxy routing
type Manager struct {
	client      *Rage4Client
	domainID    int64  // Rage4 domain ID (e.g., ID for yalx.in)
	domainName  string // Base domain (e.g., "yalx.in")
	cnamePrefix string // Prefix for CNAME records (e.g., "cn" for *.cn.yalx.in)
	mu          sync.Mutex
}

// ManagerConfig contains configuration for the DNS Manager
type ManagerConfig struct {
	Email       string // Rage4 account email
	APIKey      string // Rage4 API key
	DomainID    int64  // Rage4 domain ID
	DomainName  string // Base domain name (e.g., "yalx.in")
	CNAMEPrefix string // Prefix for CNAME subdomain (e.g., "cn")
}

// ProxyDNSRecord represents a proxy's DNS configuration
type ProxyDNSRecord struct {
	Subdomain   string // Unique subdomain ID (e.g., "abc123def")
	FullDomain  string // Full domain (e.g., "abc123def.cn.yalx.in")
	TargetHost  string // CNAME target (e.g., "x1.yalx.in")
	RecordID    int64  // Rage4 record ID for updates/deletion
}

// ServerDNSRecord represents a server's DNS configuration
type ServerDNSRecord struct {
	Subdomain  string // Server subdomain (e.g., "x1" for x1.yalx.in)
	FullDomain string // Full domain (e.g., "x1.yalx.in")
	IP         string // Server IP address
	RecordID   int64  // Rage4 record ID
}

var instance *Manager
var once sync.Once

// NewManager creates a new DNS Manager
func NewManager(cfg ManagerConfig) *Manager {
	client := NewRage4Client(cfg.Email, cfg.APIKey)

	cnamePrefix := cfg.CNAMEPrefix
	if cnamePrefix == "" {
		cnamePrefix = "cn"
	}

	return &Manager{
		client:      client,
		domainID:    cfg.DomainID,
		domainName:  cfg.DomainName,
		cnamePrefix: cnamePrefix,
	}
}

// InitGlobal initializes the global DNS Manager instance
func InitGlobal(cfg ManagerConfig) *Manager {
	once.Do(func() {
		instance = NewManager(cfg)
		log.Printf("[DNS] Manager initialized for domain: %s (ID: %d)", cfg.DomainName, cfg.DomainID)
	})
	return instance
}

// GetManager returns the global DNS Manager instance
func GetManager() *Manager {
	return instance
}

// GenerateProxySubdomain generates a unique subdomain ID for a proxy
// Format: 10-character lowercase alphanumeric string
func GenerateProxySubdomain() string {
	bytes := make([]byte, 5)
	rand.Read(bytes)
	return strings.ToLower(hex.EncodeToString(bytes))
}

// CreateProxyRecord creates a CNAME record for a new proxy
// subdomain: unique ID (e.g., "abc123def")
// serverSubdomain: server's subdomain (e.g., "x1")
// Returns the full domain name and record ID
func (m *Manager) CreateProxyRecord(subdomain, serverSubdomain string) (*ProxyDNSRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build the full record name: abc123def.cn.yalx.in
	// Rage4 API requires the full domain name, not just the subdomain
	recordName := fmt.Sprintf("%s.%s.%s", subdomain, m.cnamePrefix, m.domainName)

	// CNAME target: x1.yalx.in
	targetHost := fmt.Sprintf("%s.%s", serverSubdomain, m.domainName)

	req := CreateRecordRequest{
		DomainID: m.domainID,
		Name:     recordName,
		Content:  targetHost,
		Type:     RecordTypeCNAME,
		TTL:      300, // 5 minute TTL for fast failover
		Active:   true,
	}

	resp, err := m.client.CreateRecord(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy DNS record: %w", err)
	}

	fullDomain := fmt.Sprintf("%s.%s.%s", subdomain, m.cnamePrefix, m.domainName)

	log.Printf("[DNS] Created proxy record: %s -> %s (ID: %d)", fullDomain, targetHost, resp.ID)

	return &ProxyDNSRecord{
		Subdomain:   subdomain,
		FullDomain:  fullDomain,
		TargetHost:  targetHost,
		RecordID:    resp.ID,
	}, nil
}

// UpdateProxyRecord updates a proxy's CNAME to point to a different server (failover)
func (m *Manager) UpdateProxyRecord(recordID int64, subdomain, newServerSubdomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Full domain name required by Rage4 API
	recordName := fmt.Sprintf("%s.%s.%s", subdomain, m.cnamePrefix, m.domainName)
	newTarget := fmt.Sprintf("%s.%s", newServerSubdomain, m.domainName)

	req := UpdateRecordRequest{
		RecordID: recordID,
		Name:     recordName,
		Content:  newTarget,
		TTL:      300,
		Active:   true,
	}

	_, err := m.client.UpdateRecord(req)
	if err != nil {
		return fmt.Errorf("failed to update proxy DNS record: %w", err)
	}

	fullDomain := fmt.Sprintf("%s.%s.%s", subdomain, m.cnamePrefix, m.domainName)
	log.Printf("[DNS] Updated proxy record: %s -> %s", fullDomain, newTarget)

	return nil
}

// DeleteProxyRecord deletes a proxy's CNAME record
func (m *Manager) DeleteProxyRecord(recordID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.client.DeleteRecord(recordID)
	if err != nil {
		return fmt.Errorf("failed to delete proxy DNS record: %w", err)
	}

	log.Printf("[DNS] Deleted proxy record ID: %d", recordID)
	return nil
}

// CreateServerRecord creates an A record for a server
// subdomain: server subdomain (e.g., "x1" for x1.yalx.in)
// ip: server IP address
func (m *Manager) CreateServerRecord(subdomain, ip string) (*ServerDNSRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Full domain name required by Rage4 API
	fullDomain := fmt.Sprintf("%s.%s", subdomain, m.domainName)

	req := CreateRecordRequest{
		DomainID: m.domainID,
		Name:     fullDomain,
		Content:  ip,
		Type:     RecordTypeA,
		TTL:      3600, // 1 hour TTL for servers
		Active:   true,
	}

	resp, err := m.client.CreateRecord(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create server DNS record: %w", err)
	}

	log.Printf("[DNS] Created server record: %s -> %s (ID: %d)", fullDomain, ip, resp.ID)

	return &ServerDNSRecord{
		Subdomain:  subdomain,
		FullDomain: fullDomain,
		IP:         ip,
		RecordID:   resp.ID,
	}, nil
}

// UpdateServerRecord updates a server's A record (IP change)
func (m *Manager) UpdateServerRecord(recordID int64, subdomain, newIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Full domain name required by Rage4 API
	fullDomain := fmt.Sprintf("%s.%s", subdomain, m.domainName)

	req := UpdateRecordRequest{
		RecordID: recordID,
		Name:     fullDomain,
		Content:  newIP,
		TTL:      3600,
		Active:   true,
	}

	_, err := m.client.UpdateRecord(req)
	if err != nil {
		return fmt.Errorf("failed to update server DNS record: %w", err)
	}

	log.Printf("[DNS] Updated server record: %s -> %s", fullDomain, newIP)

	return nil
}

// DeleteServerRecord deletes a server's A record
func (m *Manager) DeleteServerRecord(recordID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.client.DeleteRecord(recordID)
	if err != nil {
		return fmt.Errorf("failed to delete server DNS record: %w", err)
	}

	log.Printf("[DNS] Deleted server record ID: %d", recordID)
	return nil
}

// BulkFailover updates all proxies pointing to oldServerSubdomain to point to newServerSubdomain
// This is useful when a server goes down and all its proxies need to be redirected
func (m *Manager) BulkFailover(records []ProxyDNSRecord, newServerSubdomain string) (succeeded, failed int) {
	for _, record := range records {
		err := m.UpdateProxyRecord(record.RecordID, record.Subdomain, newServerSubdomain)
		if err != nil {
			log.Printf("[DNS] Failover failed for %s: %v", record.FullDomain, err)
			failed++
		} else {
			succeeded++
		}
	}
	return
}

// GetFullProxyDomain returns the full domain for a proxy subdomain
func (m *Manager) GetFullProxyDomain(subdomain string) string {
	return fmt.Sprintf("%s.%s.%s", subdomain, m.cnamePrefix, m.domainName)
}

// GetFullServerDomain returns the full domain for a server subdomain
func (m *Manager) GetFullServerDomain(subdomain string) string {
	return fmt.Sprintf("%s.%s", subdomain, m.domainName)
}

// VerifyConfiguration tests the Rage4 API connection
func (m *Manager) VerifyConfiguration() error {
	domains, err := m.client.GetDomains()
	if err != nil {
		return fmt.Errorf("failed to connect to Rage4 API: %w", err)
	}

	// Verify the configured domain exists
	found := false
	for _, d := range domains {
		if d.ID == m.domainID {
			found = true
			log.Printf("[DNS] Verified domain: %s (ID: %d)", d.Name, d.ID)
			break
		}
	}

	if !found {
		return fmt.Errorf("domain ID %d not found in account", m.domainID)
	}

	return nil
}

// GetDomainRecords retrieves all DNS records for the configured domain
func (m *Manager) GetDomainRecords() ([]Record, error) {
	return m.client.GetRecords(m.domainID)
}
