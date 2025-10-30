// +build !windows

package registry

import "fmt"

// Stub implementations for non-Windows platforms
func (ro *RegistryOps) readKeyWindows(keyPath, valueName string) (interface{}, error) {
	return nil, fmt.Errorf("registry operations only supported on Windows")
}

func (ro *RegistryOps) writeKeyWindows(keyPath, valueName string, value interface{}, valueType string) error {
	return fmt.Errorf("registry operations only supported on Windows")
}

func (ro *RegistryOps) enumKeysWindows(keyPath string) ([]string, error) {
	return nil, fmt.Errorf("registry operations only supported on Windows")
}

func (ro *RegistryOps) deleteKeyWindows(keyPath, valueName string) error {
	return fmt.Errorf("registry operations only supported on Windows")
}

