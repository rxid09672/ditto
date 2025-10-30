// +build windows

package registry

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// parseKeyPath parses registry key path into hive and subkey
func parseKeyPath(keyPath string) (registry.Key, string, error) {
	var hive registry.Key
	var path string
	
	parts := strings.SplitN(keyPath, "\\", 2)
	if len(parts) == 0 {
		return 0, "", fmt.Errorf("invalid registry path")
	}
	
	hiveStr := strings.ToUpper(parts[0])
	switch hiveStr {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return 0, "", fmt.Errorf("unknown registry hive: %s", hiveStr)
	}
	
	if len(parts) > 1 {
		path = parts[1]
	} else {
		path = ""
	}
	
	return hive, path, nil
}

func (ro *RegistryOps) readKeyWindows(keyPath, valueName string) (interface{}, error) {
	ro.logger.Info("Reading registry key: %s\\%s", keyPath, valueName)
	
	hive, path, err := parseKeyPath(keyPath)
	if err != nil {
		return nil, err
	}
	
	key, err := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()
	
	// Get value type first
	_, valType, err := key.GetValue(valueName, make([]byte, 0))
	if err != nil {
		return nil, fmt.Errorf("failed to read value: %w", err)
	}
	
	// Read value based on type
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err := key.GetStringValue(valueName)
		return val, err
	case registry.DWORD, registry.QWORD:
		val, _, err := key.GetIntegerValue(valueName)
		return val, err
	case registry.BINARY:
		val, _, err := key.GetBinaryValue(valueName)
		return val, err
	case registry.MULTI_SZ:
		val, _, err := key.GetStringsValue(valueName)
		return strings.Join(val, "\n"), err
	default:
		return nil, fmt.Errorf("unsupported value type: %d", valType)
	}
}

func (ro *RegistryOps) writeKeyWindows(keyPath, valueName string, value interface{}, valueType string) error {
	ro.logger.Info("Writing registry key: %s\\%s", keyPath, valueName)
	
	hive, path, err := parseKeyPath(keyPath)
	if err != nil {
		return err
	}
	
	key, _, err := registry.CreateKey(hive, path, registry.SET_VALUE|registry.WRITE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()
	
	// Write value based on type
	switch strings.ToUpper(valueType) {
	case "STRING", "SZ":
		val, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid string value")
		}
		return key.SetStringValue(valueName, val)
	case "DWORD":
		var val uint32
		switch v := value.(type) {
		case uint32:
			val = v
		case int:
			val = uint32(v)
		default:
			return fmt.Errorf("invalid DWORD value")
		}
		return key.SetDWordValue(valueName, val)
	case "QWORD":
		var val uint64
		switch v := value.(type) {
		case uint64:
			val = v
		case int:
			val = uint64(v)
		default:
			return fmt.Errorf("invalid QWORD value")
		}
		return key.SetQWordValue(valueName, val)
	case "BINARY":
		val, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("invalid binary value")
		}
		return key.SetBinaryValue(valueName, val)
	case "MULTI_SZ":
		val, ok := value.([]string)
		if !ok {
			if str, ok := value.(string); ok {
				val = strings.Split(str, "\n")
			} else {
				return fmt.Errorf("invalid MULTI_SZ value")
			}
		}
		return key.SetStringsValue(valueName, val)
	default:
		return fmt.Errorf("unsupported value type: %s", valueType)
	}
}

func (ro *RegistryOps) enumKeysWindows(keyPath string) ([]string, error) {
	ro.logger.Info("Enumerating registry keys: %s", keyPath)
	
	hive, path, err := parseKeyPath(keyPath)
	if err != nil {
		return nil, err
	}
	
	key, err := registry.OpenKey(hive, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()
	
	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate keys: %w", err)
	}
	
	return names, nil
}

func (ro *RegistryOps) deleteKeyWindows(keyPath, valueName string) error {
	hive, path, err := parseKeyPath(keyPath)
	if err != nil {
		return err
	}
	
	key, err := registry.OpenKey(hive, path, registry.SET_VALUE|registry.WRITE)
	if err != nil {
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()
	
	if valueName != "" {
		// Delete a value
		return key.DeleteValue(valueName)
	} else {
		// Delete a subkey - need to enumerate and delete recursively
		subkeys, err := key.ReadSubKeyNames(0)
		if err != nil {
			return fmt.Errorf("failed to enumerate subkeys: %w", err)
		}
		
		for _, subkey := range subkeys {
			fullPath := path + "\\" + subkey
			if err := ro.deleteKeyWindows(keyPath+"\\"+subkey, ""); err != nil {
				return err
			}
		}
		
		// Delete the key itself
		return registry.DeleteKey(hive, path)
	}
}

