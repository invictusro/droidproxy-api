package infra

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient manages SSH connections to servers
type SSHClient struct {
	Host     string
	Port     int
	User     string
	Password string
	client   *ssh.Client
}

// CommandResult holds the result of an SSH command execution
type CommandResult struct {
	Command  string `json:"command"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Duration int64  `json:"duration_ms"`
}

// NewSSHClient creates a new SSH client
func NewSSHClient(host string, port int, user, password string) *SSHClient {
	return &SSHClient{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
	}
}

// Connect establishes an SSH connection
func (c *SSHClient) Connect() error {
	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Use known_hosts in production
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	c.client = client
	return nil
}

// Close closes the SSH connection
func (c *SSHClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Run executes a command and returns the result
func (c *SSHClient) Run(command string) (*CommandResult, error) {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	exitCode := 0
	if err := session.Run(command); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return nil, fmt.Errorf("failed to run command: %w", err)
		}
	}
	duration := time.Since(start).Milliseconds()

	return &CommandResult{
		Command:  command,
		Stdout:   strings.TrimSpace(stdout.String()),
		Stderr:   strings.TrimSpace(stderr.String()),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// RunMultiple executes multiple commands in sequence
func (c *SSHClient) RunMultiple(commands []string) ([]*CommandResult, error) {
	results := make([]*CommandResult, 0, len(commands))
	for _, cmd := range commands {
		result, err := c.Run(cmd)
		if err != nil {
			return results, err
		}
		results = append(results, result)
		// Stop on first failure
		if result.ExitCode != 0 {
			break
		}
	}
	return results, nil
}

// TestConnection tests if the SSH connection works
func (c *SSHClient) TestConnection() error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	result, err := c.Run("echo 'connection test'")
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("test command failed: %s", result.Stderr)
	}
	return nil
}
