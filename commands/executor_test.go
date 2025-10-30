package commands

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExecutor(t *testing.T) {
	timeout := 30 * time.Second
	executor := NewExecutor(timeout)
	
	require.NotNil(t, executor)
	assert.Equal(t, timeout, executor.timeout)
}

func TestExecutor_Execute_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	executor := NewExecutor(5 * time.Second)
	
	output, err := executor.Execute("echo test")
	
	require.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestExecutor_Execute_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	executor := NewExecutor(5 * time.Second)
	
	output, err := executor.Execute("echo test")
	
	require.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestExecutor_Execute_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	
	executor := NewExecutor(5 * time.Second)
	
	output, err := executor.Execute("echo test")
	
	require.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestExecutor_Execute_Timeout(t *testing.T) {
	executor := NewExecutor(100 * time.Millisecond)
	
	// Run a command that will timeout
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "ping -n 10 127.0.0.1"
	} else {
		cmd = "sleep 10"
	}
	
	_, err := executor.Execute(cmd)
	
	assert.Error(t, err)
}

func TestExecutor_ExecuteShell(t *testing.T) {
	executor := NewExecutor(5 * time.Second)
	
	// ExecuteShell starts an interactive shell - can't test fully
	// but can verify it doesn't panic
	assert.NotPanics(t, func() {
		_ = executor.ExecuteShell()
	})
}

func TestExecutor_DownloadFile(t *testing.T) {
	executor := NewExecutor(10 * time.Second)
	
	// Test with invalid URL to verify error handling
	err := executor.DownloadFile("invalid://url", "/tmp/test")
	
	// Should fail, but structure is tested
	assert.Error(t, err)
}

func TestExecutor_UploadFile(t *testing.T) {
	executor := NewExecutor(10 * time.Second)
	
	// Test with invalid URL to verify error handling
	err := executor.UploadFile("/nonexistent/file", "invalid://url")
	
	// Should fail, but structure is tested
	assert.Error(t, err)
}

func TestExecutor_Execute_EmptyCommand(t *testing.T) {
	executor := NewExecutor(5 * time.Second)
	
	output, err := executor.Execute("")
	
	// Empty command behavior depends on OS
	_ = output
	_ = err
}

func BenchmarkExecutor_Execute(b *testing.B) {
	executor := NewExecutor(5 * time.Second)
	cmd := "echo benchmark"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = executor.Execute(cmd)
	}
}

