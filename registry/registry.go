package registry

import (
	"fmt"
	"runtime"
)

// RegistryOps provides Windows registry operations
type RegistryOps struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewRegistryOps creates new registry operations
func NewRegistryOps(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *RegistryOps {
	return &RegistryOps{logger: logger}
}

// ReadKey reads a registry key value
func (ro *RegistryOps) ReadKey(keyPath, valueName string) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("registry operations only supported on Windows")
	}
	return ro.readKeyWindows(keyPath, valueName)
}

// WriteKey writes a registry key value
func (ro *RegistryOps) WriteKey(keyPath, valueName string, value interface{}, valueType string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only supported on Windows")
	}
	return ro.writeKeyWindows(keyPath, valueName, value, valueType)
}

// EnumKeys enumerates subkeys
func (ro *RegistryOps) EnumKeys(keyPath string) ([]string, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("registry operations only supported on Windows")
	}
	return ro.enumKeysWindows(keyPath)
}

// Platform-specific implementations are in registry_windows.go (Windows) and registry_nonwindows.go (others)
// These functions are declared but implemented in platform-specific files via build tags

// GetValue reads a registry value
func (ro *RegistryOps) GetValue(keyPath, valueName string) (interface{}, error) {
	return ro.ReadKey(keyPath, valueName)
}

// SetValue writes a registry value
func (ro *RegistryOps) SetValue(keyPath, valueName string, value interface{}, valueType string) error {
	return ro.WriteKey(keyPath, valueName, value, valueType)
}

// DeleteKey deletes a registry key or value
func (ro *RegistryOps) DeleteKey(keyPath string, valueName string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only supported on Windows")
	}
	return ro.deleteKeyWindows(keyPath, valueName)
}

