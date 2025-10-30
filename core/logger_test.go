package core

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(false)
	
	require.NotNil(t, logger)
	assert.False(t, logger.debug)
	assert.NotNil(t, logger.logger)
}

func TestNewLogger_Debug(t *testing.T) {
	logger := NewLogger(true)
	
	assert.True(t, logger.debug)
}

func TestLogger_Debug(t *testing.T) {
	logger := NewLogger(true)
	
	// Should log when debug is enabled
	logger.Debug("test debug message")
	
	loggerNoDebug := NewLogger(false)
	// Should not log when debug is disabled
	loggerNoDebug.Debug("should not appear")
}

func TestLogger_Info(t *testing.T) {
	logger := NewLogger(false)
	
	// Should always log
	logger.Info("test info message")
}

func TestLogger_Warn(t *testing.T) {
	logger := NewLogger(false)
	
	logger.Warn("test warning message")
}

func TestLogger_Error(t *testing.T) {
	logger := NewLogger(false)
	
	logger.Error("test error message")
}

func TestLogger_SetFile(t *testing.T) {
	logger := NewLogger(false)
	tmpFile, err := os.CreateTemp("", "ditto_test_log_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	err = logger.SetFile(tmpFile.Name())
	
	require.NoError(t, err)
	assert.NotNil(t, logger.file)
	
	logger.Info("test message")
	
	// Verify file was written
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	assert.NotZero(t, info.Size())
}

func TestLogger_SetFile_InvalidPath(t *testing.T) {
	logger := NewLogger(false)
	
	err := logger.SetFile("/invalid/path/log.log")
	
	assert.Error(t, err)
}

func TestLogger_SetFile_Replace(t *testing.T) {
	logger := NewLogger(false)
	tmpFile1, err := os.CreateTemp("", "ditto_test_log1_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile1.Name())
	
	tmpFile2, err := os.CreateTemp("", "ditto_test_log2_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile2.Name())
	
	err = logger.SetFile(tmpFile1.Name())
	require.NoError(t, err)
	
	err = logger.SetFile(tmpFile2.Name())
	require.NoError(t, err)
	
	// First file should be closed
	assert.NotNil(t, logger.file)
}

func TestLogger_Close(t *testing.T) {
	logger := NewLogger(false)
	
	err := logger.Close()
	assert.NoError(t, err)
	
	tmpFile, err := os.CreateTemp("", "ditto_test_log_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	err = logger.SetFile(tmpFile.Name())
	require.NoError(t, err)
	
	err = logger.Close()
	assert.NoError(t, err)
}

func TestLogger_Concurrent(t *testing.T) {
	logger := NewLogger(true)
	
	// Test concurrent logging
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				logger.Info("concurrent test %d-%d", id, j)
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestLogger_LogFormat(t *testing.T) {
	logger := NewLogger(false)
	
	logger.Info("test %s", "message")
	logger.Warn("test %d", 123)
	logger.Error("test %v", time.Now())
}

func TestLogger_ThreadSafety(t *testing.T) {
	logger := NewLogger(false)
	tmpFile, err := os.CreateTemp("", "ditto_test_log_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	err = logger.SetFile(tmpFile.Name())
	require.NoError(t, err)
	
	// Concurrent writes
	for i := 0; i < 100; i++ {
		go func(id int) {
			logger.Info("thread %d", id)
		}(i)
	}
	
	// Give time for writes
	time.Sleep(100 * time.Millisecond)
	
	err = logger.Close()
	assert.NoError(t, err)
}

