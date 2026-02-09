package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	Rage4BaseURL = "https://rage4.com/rapi"
)

// Rage4Client handles communication with the Rage4 DNS API
type Rage4Client struct {
	email   string
	apiKey  string
	client  *http.Client
}

// NewRage4Client creates a new Rage4 API client
func NewRage4Client(email, apiKey string) *Rage4Client {
	return &Rage4Client{
		email:  email,
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CommonResponse is the standard Rage4 API response
type CommonResponse struct {
	Status bool   `json:"status"`
	ID     int64  `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Domain represents a Rage4 DNS domain
type Domain struct {
	ID           int64       `json:"id"`
	Name         string      `json:"name"`
	OwnerEmail   string      `json:"owner_email"`
	Type         interface{} `json:"type"` // Can be int or string depending on Rage4 API version
	SubnetMask   int         `json:"subnet_mask"`
	DefaultNS1   string      `json:"default_ns1"`
	DefaultNS2   string      `json:"default_ns2"`
}

// Record represents a Rage4 DNS record
type Record struct {
	ID              int64   `json:"id"`
	DomainID        int64   `json:"domain_id"`
	Name            string  `json:"name"`
	Content         string  `json:"content"`
	Type            string  `json:"type"`
	TTL             int     `json:"ttl"`
	Priority        int     `json:"priority"`
	Weight          int     `json:"weight"`
	Active          bool    `json:"active"`
	Failover        bool    `json:"failover"`
	FailoverContent string  `json:"failover_content"`
	GeoZone         int64   `json:"geozone"`
	GeoLat          float64 `json:"geolat"`
	GeoLong         float64 `json:"geolong"`
}

// RecordType defines DNS record types
type RecordType string

const (
	RecordTypeA     RecordType = "A"
	RecordTypeAAAA  RecordType = "AAAA"
	RecordTypeCNAME RecordType = "CNAME"
	RecordTypeMX    RecordType = "MX"
	RecordTypeTXT   RecordType = "TXT"
	RecordTypeNS    RecordType = "NS"
)

// CreateRecordRequest contains parameters for creating a DNS record
type CreateRecordRequest struct {
	DomainID        int64
	Name            string     // e.g., "abc123.cn" for abc123.cn.yalx.in
	Content         string     // e.g., "x1.yalx.in" for CNAME
	Type            RecordType // A, AAAA, CNAME, etc.
	TTL             int        // Time to live in seconds (default 3600)
	Priority        int        // For MX records
	Active          bool       // Whether record is active
	Failover        bool       // Enable failover
	FailoverContent string     // Failover value
}

// UpdateRecordRequest contains parameters for updating a DNS record
type UpdateRecordRequest struct {
	RecordID        int64
	Name            string
	Content         string
	TTL             int
	Priority        int
	Active          bool
	Failover        bool
	FailoverContent string
}

// doRequest performs an HTTP request to the Rage4 API with Basic Auth
func (c *Rage4Client) doRequest(method, endpoint string, params url.Values) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", Rage4BaseURL, endpoint)
	if len(params) > 0 {
		reqURL = fmt.Sprintf("%s?%s", reqURL, params.Encode())
	}

	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Basic Auth with email:apiKey
	req.SetBasicAuth(c.email, c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetDomains retrieves all domains for the account
func (c *Rage4Client) GetDomains() ([]Domain, error) {
	body, err := c.doRequest("GET", "GetDomains", nil)
	if err != nil {
		return nil, err
	}

	var domains []Domain
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	return domains, nil
}

// GetDomainByName retrieves a domain by its name
func (c *Rage4Client) GetDomainByName(name string) (*Domain, error) {
	params := url.Values{}
	params.Set("name", name)

	body, err := c.doRequest("GET", "GetDomainByName", params)
	if err != nil {
		return nil, err
	}

	var domain Domain
	if err := json.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf("failed to parse domain: %w", err)
	}

	return &domain, nil
}

// GetRecords retrieves all records for a domain
func (c *Rage4Client) GetRecords(domainID int64) ([]Record, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(domainID, 10))

	body, err := c.doRequest("GET", "GetRecords", params)
	if err != nil {
		return nil, err
	}

	var records []Record
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	return records, nil
}

// GetRecord retrieves a specific record by ID
func (c *Rage4Client) GetRecord(recordID int64) (*Record, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(recordID, 10))

	body, err := c.doRequest("GET", "GetRecord", params)
	if err != nil {
		return nil, err
	}

	var record Record
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("failed to parse record: %w", err)
	}

	return &record, nil
}

// CreateRecord creates a new DNS record
func (c *Rage4Client) CreateRecord(req CreateRecordRequest) (*CommonResponse, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(req.DomainID, 10))
	params.Set("name", req.Name)
	params.Set("content", req.Content)
	params.Set("type", string(req.Type))

	if req.TTL > 0 {
		params.Set("ttl", strconv.Itoa(req.TTL))
	} else {
		params.Set("ttl", "300") // Low TTL for fast updates
	}

	if req.Priority > 0 {
		params.Set("priority", strconv.Itoa(req.Priority))
	}

	params.Set("active", strconv.FormatBool(req.Active))

	if req.Failover {
		params.Set("failover", "true")
		if req.FailoverContent != "" {
			params.Set("failovercontent", req.FailoverContent)
		}
	}

	body, err := c.doRequest("GET", "CreateRecord", params)
	if err != nil {
		return nil, err
	}

	var resp CommonResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Status {
		return nil, fmt.Errorf("failed to create record: %s", resp.Error)
	}

	return &resp, nil
}

// UpdateRecord updates an existing DNS record
func (c *Rage4Client) UpdateRecord(req UpdateRecordRequest) (*CommonResponse, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(req.RecordID, 10))
	params.Set("name", req.Name)
	params.Set("content", req.Content)

	if req.TTL > 0 {
		params.Set("ttl", strconv.Itoa(req.TTL))
	}

	if req.Priority > 0 {
		params.Set("priority", strconv.Itoa(req.Priority))
	}

	params.Set("active", strconv.FormatBool(req.Active))

	if req.Failover {
		params.Set("failover", "true")
		if req.FailoverContent != "" {
			params.Set("failovercontent", req.FailoverContent)
		}
	}

	body, err := c.doRequest("GET", "UpdateRecord", params)
	if err != nil {
		return nil, err
	}

	var resp CommonResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Status {
		return nil, fmt.Errorf("failed to update record: %s", resp.Error)
	}

	return &resp, nil
}

// DeleteRecord deletes a DNS record
func (c *Rage4Client) DeleteRecord(recordID int64) (*CommonResponse, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(recordID, 10))

	body, err := c.doRequest("GET", "DeleteRecord", params)
	if err != nil {
		return nil, err
	}

	var resp CommonResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Status {
		return nil, fmt.Errorf("failed to delete record: %s", resp.Error)
	}

	return &resp, nil
}

// ToggleRecord enables or disables a DNS record
func (c *Rage4Client) ToggleRecord(recordID int64) (*CommonResponse, error) {
	params := url.Values{}
	params.Set("id", strconv.FormatInt(recordID, 10))

	body, err := c.doRequest("GET", "ToggleRecord", params)
	if err != nil {
		return nil, err
	}

	var resp CommonResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Status {
		return nil, fmt.Errorf("failed to toggle record: %s", resp.Error)
	}

	return &resp, nil
}
