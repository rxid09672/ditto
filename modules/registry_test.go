package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewModuleRegistry(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	require.NotNil(t, registry)
	assert.NotNil(t, registry.modules)
	assert.Equal(t, logger, registry.logger)
}

func TestModuleRegistry_LoadModule_ValidYAML(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	// Create temporary YAML file
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test_module.yaml")
	
	yamlContent := `
id: test_module
name: Test Module
description: A test module
language: powershell
category: code_execution
authors:
  - name: Test Author
`
	
	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	require.NoError(t, err)
	
	module, err := registry.LoadModule(yamlFile)
	
	require.NoError(t, err)
	assert.Equal(t, "Test Module", module.Name)
	assert.Equal(t, LanguagePowerShell, module.Language)
	assert.Equal(t, CategoryCodeExecution, module.Category)
}

func TestModuleRegistry_LoadModule_InvalidYAML(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	tmpFile, err := os.CreateTemp("", "invalid_*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	_, err = tmpFile.WriteString("invalid: yaml: content: [")
	require.NoError(t, err)
	tmpFile.Close()
	
	_, err = registry.LoadModule(tmpFile.Name())
	
	assert.Error(t, err)
}

func TestModuleRegistry_LoadModule_Nonexistent(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	_, err := registry.LoadModule("/nonexistent/path/module.yaml")
	
	assert.Error(t, err)
}

func TestModuleRegistry_GetModule_Exists(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	// Manually add a module
	module := &EmpireModule{
		ID:   "test-id",
		Name: "Test Module",
	}
	registry.modules["test-id"] = module
	
	retrieved, ok := registry.GetModule("test-id")
	
	assert.True(t, ok)
	assert.Equal(t, module, retrieved)
}

func TestModuleRegistry_GetModule_NotExists(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	_, ok := registry.GetModule("nonexistent")
	
	assert.False(t, ok)
}

func TestModuleRegistry_ListAllModules(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	module1 := &EmpireModule{ID: "1", Name: "Module 1"}
	module2 := &EmpireModule{ID: "2", Name: "Module 2"}
	
	registry.modules["1"] = module1
	registry.modules["2"] = module2
	
	modules := registry.ListAllModules()
	
	assert.Len(t, modules, 2)
}

func TestModuleRegistry_SearchModules(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	module1 := &EmpireModule{ID: "test1", Name: "Test Module 1", Description: "First test"}
	module2 := &EmpireModule{ID: "test2", Name: "Test Module 2", Description: "Second test"}
	module3 := &EmpireModule{ID: "other", Name: "Other Module", Description: "Different"}
	
	registry.modules["test1"] = module1
	registry.modules["test2"] = module2
	registry.modules["other"] = module3
	
	results := registry.SearchModules("test")
	
	assert.Len(t, results, 2)
}

func TestModuleRegistry_ListModulesByCategory(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	module1 := &EmpireModule{ID: "1", Category: CategoryCodeExecution}
	module2 := &EmpireModule{ID: "2", Category: CategoryCollection}
	module3 := &EmpireModule{ID: "3", Category: CategoryCodeExecution}
	
	registry.modules["1"] = module1
	registry.modules["2"] = module2
	registry.modules["3"] = module3
	
	results := registry.ListModulesByCategory(CategoryCodeExecution)
	
	assert.Len(t, results, 2)
}

func TestModuleRegistry_ListModulesByLanguage(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	module1 := &EmpireModule{ID: "1", Language: LanguagePowerShell}
	module2 := &EmpireModule{ID: "2", Language: LanguagePython}
	module3 := &EmpireModule{ID: "3", Language: LanguagePowerShell}
	
	registry.modules["1"] = module1
	registry.modules["2"] = module2
	registry.modules["3"] = module3
	
	results := registry.ListModulesByLanguage(LanguagePowerShell)
	
	assert.Len(t, results, 2)
}

func TestModuleRegistry_GetModuleCount(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	assert.Equal(t, 0, registry.GetModuleCount())
	
	registry.modules["1"] = &EmpireModule{ID: "1"}
	registry.modules["2"] = &EmpireModule{ID: "2"}
	
	assert.Equal(t, 2, registry.GetModuleCount())
}

func TestModuleRegistry_LoadModulesFromDirectory(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	tmpDir := t.TempDir()
	
	// Create test module files
	module1 := filepath.Join(tmpDir, "module1.yaml")
	module2 := filepath.Join(tmpDir, "module2.yaml")
	
	os.WriteFile(module1, []byte(`
id: module1
name: Module 1
language: powershell
category: code_execution
`), 0644)
	
	os.WriteFile(module2, []byte(`
id: module2
name: Module 2
language: python
category: collection
`), 0644)
	
	err := registry.LoadModulesFromDirectory(tmpDir)
	
	require.NoError(t, err)
	assert.Equal(t, 2, registry.GetModuleCount())
}

func TestEmpireModule_ToJSON(t *testing.T) {
	module := &EmpireModule{
		ID:   "test-id",
		Name: "Test Module",
	}
	
	jsonData, err := module.ToJSON()
	
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), "test-id")
	assert.Contains(t, string(jsonData), "Test Module")
}

func TestProcessModule(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test",
		Script: `
function Invoke-Ditto {
    param($Param1)
    Write-Host "Param1: {{ Param1 }}"
}
`,
	}
	
	params := map[string]string{
		"Param1": "test-value",
	}
	
	result, err := ProcessModule(module, params)
	
	require.NoError(t, err)
	assert.Contains(t, result, "test-value")
}

func TestProcessModule_NoScript(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test",
		Script: "{{ Param1 }}",
	}
	
	params := map[string]string{
		"Param1": "value",
	}
	
	result, err := ProcessModule(module, params)
	
	require.NoError(t, err)
	assert.Contains(t, result, "value")
}

func TestValidateModuleParams(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test",
		Options: []ModuleOption{
			{Name: "RequiredParam", Required: true},
			{Name: "OptionalParam", Required: false},
		},
	}
	
	tests := []struct {
		name    string
		params  map[string]string
		wantErr bool
	}{
		{"valid", map[string]string{"RequiredParam": "value"}, false},
		{"missing required", map[string]string{}, true},
		{"optional missing", map[string]string{"RequiredParam": "value"}, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateModuleParams(module, tt.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestModuleRegistry_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	registry := NewModuleRegistry(logger)
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			module := &EmpireModule{
				ID:   string(rune(id)),
				Name: "Test",
			}
			registry.modules[string(rune(id))] = module
			registry.GetModule(string(rune(id)))
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, registry.modules)
}

