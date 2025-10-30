package platform

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	
	assert.NotEmpty(t, hostname)
	assert.NotEqual(t, "unknown", hostname)
}

func TestGetUsername(t *testing.T) {
	username := GetUsername()
	
	assert.NotEmpty(t, username)
	assert.NotEqual(t, "unknown", username)
}

func TestGetOS(t *testing.T) {
	os := GetOS()
	
	assert.NotEmpty(t, os)
	assert.Contains(t, []string{"windows", "linux", "darwin", "freebsd", "openbsd"}, os)
}

func TestGetArch(t *testing.T) {
	arch := GetArch()
	
	assert.NotEmpty(t, arch)
	assert.Contains(t, []string{"amd64", "386", "arm", "arm64"}, arch)
}

func TestGetProcessID(t *testing.T) {
	pid := GetProcessID()
	
	assert.Greater(t, pid, 0)
	assert.Equal(t, os.Getpid(), pid)
}

func TestGetParentProcessID(t *testing.T) {
	ppid := GetParentProcessID()
	
	assert.GreaterOrEqual(t, ppid, 0)
	assert.Equal(t, os.Getppid(), ppid)
}

func TestIsAdmin(t *testing.T) {
	isAdmin := IsAdmin()
	
	assert.IsType(t, false, isAdmin)
}

func TestGetSystemInfo(t *testing.T) {
	info := GetSystemInfo()
	
	require.NotNil(t, info)
	assert.NotEmpty(t, info["hostname"])
	assert.NotEmpty(t, info["username"])
	assert.NotEmpty(t, info["os"])
	assert.NotEmpty(t, info["arch"])
	assert.Greater(t, info["process_id"].(int), 0)
	assert.GreaterOrEqual(t, info["parent_pid"].(int), 0)
	assert.Greater(t, info["num_cpu"].(int), 0)
	assert.NotEmpty(t, info["go_version"])
}

func TestGetHomeDir(t *testing.T) {
	homeDir := GetHomeDir()
	
	assert.NotEmpty(t, homeDir)
}

func TestGetTempDir(t *testing.T) {
	tempDir := GetTempDir()
	
	assert.NotEmpty(t, tempDir)
	assert.Equal(t, os.TempDir(), tempDir)
}

func TestGetWorkingDir(t *testing.T) {
	wd := GetWorkingDir()
	
	assert.NotEmpty(t, wd)
	assert.NotEqual(t, "unknown", wd)
}

func TestIsAdmin_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	isAdmin := IsAdmin()
	
	assert.IsType(t, false, isAdmin)
}

func TestIsAdmin_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	
	isAdmin := IsAdmin()
	
	assert.IsType(t, false, isAdmin)
}

func TestIsAdmin_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	isAdmin := IsAdmin()
	
	assert.IsType(t, false, isAdmin)
}

func BenchmarkGetSystemInfo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetSystemInfo()
	}
}

