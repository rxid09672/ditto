package core

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	require.NotNil(t, cfg)
	assert.True(t, cfg.Authorized)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8443, cfg.Server.Port)
	assert.True(t, cfg.Server.TLSEnabled)
	assert.Equal(t, "aes256", cfg.Encryption.Algorithm)
	assert.Equal(t, 32, cfg.Encryption.KeySize)
	assert.Equal(t, "https", cfg.Communication.Protocol)
	assert.Equal(t, 0.3, cfg.Communication.Jitter)
	assert.NotEmpty(t, cfg.Session.SessionID)
	assert.NotEmpty(t, cfg.Session.Key)
	assert.Len(t, cfg.Session.Key, 32)
}

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Len(t, id1, 32) // 16 bytes = 32 hex chars
}

func TestLoadConfig_EmptyPath(t *testing.T) {
	cfg, err := LoadConfig("")
	
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Authorized)
}

func TestLoadConfig_ValidFile(t *testing.T) {
	// Create temporary config file
	tmpFile, err := os.CreateTemp("", "ditto_test_config_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	testConfig := &Config{
		Authorized: true,
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
	}
	
	data, err := json.Marshal(testConfig)
	require.NoError(t, err)
	
	err = os.WriteFile(tmpFile.Name(), data, 0644)
	require.NoError(t, err)
	
	cfg, err := LoadConfig(tmpFile.Name())
	
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.json")
	
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "ditto_test_config_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	err = os.WriteFile(tmpFile.Name(), []byte("invalid json"), 0644)
	require.NoError(t, err)
	
	cfg, err := LoadConfig(tmpFile.Name())
	
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfig_Unauthorized(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "ditto_test_config_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	testConfig := &Config{
		Authorized: false,
	}
	
	data, err := json.Marshal(testConfig)
	require.NoError(t, err)
	
	err = os.WriteFile(tmpFile.Name(), data, 0644)
	require.NoError(t, err)
	
	cfg, err := LoadConfig(tmpFile.Name())
	
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestSaveConfig(t *testing.T) {
	cfg := DefaultConfig()
	tmpFile, err := os.CreateTemp("", "ditto_test_save_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	err = SaveConfig(cfg, tmpFile.Name())
	
	require.NoError(t, err)
	
	// Verify file was created
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	assert.NotZero(t, info.Size())
	
	// Verify we can load it back
	loaded, err := LoadConfig(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, cfg.Server.Host, loaded.Server.Host)
	assert.Equal(t, cfg.Server.Port, loaded.Server.Port)
}

func TestSaveConfig_InvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	err := SaveConfig(cfg, "/invalid/path/config.json")
	
	assert.Error(t, err)
}

func TestConfig_ServerConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
	assert.Equal(t, 100, cfg.Server.MaxConnections)
	assert.Equal(t, 60*time.Second, cfg.Server.KeepAlive)
}

func TestConfig_EncryptionConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, 16, cfg.Encryption.IVSize)
	assert.Equal(t, "ecdh", cfg.Encryption.KeyExchange)
	assert.True(t, cfg.Encryption.Compression)
	assert.Equal(t, 6, cfg.Encryption.CompressLevel)
}

func TestConfig_CommConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, 3, cfg.Communication.Retries)
	assert.Equal(t, 5*time.Second, cfg.Communication.RetryDelay)
	assert.NotEmpty(t, cfg.Communication.UserAgent)
	assert.NotEmpty(t, cfg.Communication.Headers)
}

func TestConfig_EvasionConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.True(t, cfg.Evasion.EnableSandboxDetection)
	assert.True(t, cfg.Evasion.EnableDebuggerCheck)
	assert.False(t, cfg.Evasion.EnableVMDetection)
	assert.False(t, cfg.Evasion.EnableETWPatches)
	assert.False(t, cfg.Evasion.EnableAMSI)
	assert.True(t, cfg.Evasion.SleepMask)
	assert.False(t, cfg.Evasion.DirectSyscalls)
}

func TestConfig_LoggingConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.True(t, cfg.Logging.Console)
	assert.Equal(t, int64(10*1024*1024), cfg.Logging.MaxSize)
	assert.Equal(t, 5, cfg.Logging.MaxBackups)
}

func TestConfig_SessionConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, 30*time.Second, cfg.Session.Heartbeat)
	assert.Equal(t, 300*time.Second, cfg.Session.Timeout)
	assert.Equal(t, 100, cfg.Session.MaxCommands)
	assert.Equal(t, 60*time.Second, cfg.Session.CommandTimeout)
}

func TestConfig_JSONRoundTrip(t *testing.T) {
	cfg1 := DefaultConfig()
	
	data, err := json.Marshal(cfg1)
	require.NoError(t, err)
	
	var cfg2 Config
	err = json.Unmarshal(data, &cfg2)
	require.NoError(t, err)
	
	assert.Equal(t, cfg1.Server.Host, cfg2.Server.Host)
	assert.Equal(t, cfg1.Server.Port, cfg2.Server.Port)
	assert.Equal(t, cfg1.Encryption.Algorithm, cfg2.Encryption.Algorithm)
	assert.Equal(t, cfg1.Communication.Protocol, cfg2.Communication.Protocol)
}

