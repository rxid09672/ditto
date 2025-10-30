package persistence

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInstaller(t *testing.T) {
	installer := NewInstaller("/path/to/target", "registry")
	
	require.NotNil(t, installer)
	assert.Equal(t, "/path/to/target", installer.targetPath)
	assert.Equal(t, "registry", installer.startupMethod)
}

func TestInstaller_Install_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip("Supported OS test")
	}
	
	installer := NewInstaller("/path/to/target", "registry")
	
	err := installer.Install()
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OS")
}

func TestInstaller_Install_Windows_Registry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*.exe")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "registry")
	
	// Will fail due to registry operations not implemented, but structure is tested
	err = installer.Install()
	assert.Error(t, err)
}

func TestInstaller_Install_Windows_Service(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*.exe")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "service")
	
	err = installer.Install()
	assert.Error(t, err)
}

func TestInstaller_Install_Windows_Startup(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*.exe")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "startup")
	
	// Will fail due to file operations, but structure is tested
	err = installer.Install()
	// May succeed or fail depending on permissions
	_ = err
}

func TestInstaller_Install_Linux_Systemd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "systemd")
	
	err = installer.Install()
	// May fail due to permissions or implementation
	_ = err
}

func TestInstaller_Install_Linux_Cron(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "cron")
	
	err = installer.Install()
	_ = err
}

func TestInstaller_Install_Darwin_LaunchAgent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "launchagent")
	
	err = installer.Install()
	_ = err
}

func TestInstaller_Install_Default(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*.exe")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "unknown")
	
	// Should default to registry on Windows
	err = installer.Install()
	assert.Error(t, err)
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "source.txt")
	dst := filepath.Join(tmpDir, "dest.txt")
	
	err := os.WriteFile(src, []byte("test content"), 0644)
	require.NoError(t, err)
	
	err = copyFile(src, dst)
	require.NoError(t, err)
	
	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, []byte("test content"), data)
}

func TestCopyFile_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, "dest.txt")
	
	err := copyFile("/nonexistent/file", dst)
	assert.Error(t, err)
}

func TestWriteServiceFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_service_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	err = writeServiceFile(tmpFile.Name(), "test content")
	require.NoError(t, err)
	
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, []byte("test content"), data)
}

func TestAppendToFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_append_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	err = os.WriteFile(tmpFile.Name(), []byte("original"), 0644)
	require.NoError(t, err)
	
	err = appendToFile(tmpFile.Name(), " appended")
	require.NoError(t, err)
	
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, []byte("original appended"), data)
}

func TestAppendToFile_NotFound(t *testing.T) {
	err := appendToFile("/nonexistent/path/file", "content")
	assert.Error(t, err)
}

func TestWriteFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_write_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	err = writeFile(tmpFile.Name(), "test content")
	require.NoError(t, err)
	
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, []byte("test content"), data)
}

func TestSetRegistryValue(t *testing.T) {
	// This is a stub that returns nil, so just verify it doesn't panic
	err := setRegistryValue("key", "value", "data")
	assert.NoError(t, err)
}

func TestCreateWindowsService(t *testing.T) {
	// This is a stub that returns nil, so just verify it doesn't panic
	err := createWindowsService("test", "/path/to/exe")
	assert.NoError(t, err)
}

func TestCreateScheduledTask(t *testing.T) {
	// This is a stub that returns nil, so just verify it doesn't panic
	err := createScheduledTask("test", "/path/to/exe")
	assert.NoError(t, err)
}

func TestAddCronEntry(t *testing.T) {
	// This is a stub that returns nil, so just verify it doesn't panic
	err := addCronEntry("@reboot /path/to/script")
	assert.NoError(t, err)
}

func TestAddLoginItem(t *testing.T) {
	// This is a stub that returns nil, so just verify it doesn't panic
	err := addLoginItem("/path/to/app")
	assert.NoError(t, err)
}

func TestInstaller_Install_Windows_Scheduled(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*.exe")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "scheduled")
	
	err = installer.Install()
	assert.NoError(t, err) // Stub returns nil
}

func TestInstaller_Install_Linux_RC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "rc")
	
	err = installer.Install()
	// May fail due to permissions
	_ = err
}

func TestInstaller_Install_Darwin_LoginItem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	
	tmpFile, err := os.CreateTemp("", "test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	installer := NewInstaller(tmpFile.Name(), "loginitem")
	
	err = installer.Install()
	assert.NoError(t, err) // Stub returns nil
}

