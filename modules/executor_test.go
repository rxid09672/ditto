package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewPowerShellExecutor(t *testing.T) {
	logger := &mockLogger{}
	pe := NewPowerShellExecutor(logger)
	
	require.NotNil(t, pe)
	assert.Equal(t, logger, pe.logger)
}

func TestPowerShellExecutor_Supports(t *testing.T) {
	logger := &mockLogger{}
	pe := NewPowerShellExecutor(logger)
	
	assert.True(t, pe.Supports(LanguagePowerShell))
	assert.False(t, pe.Supports(LanguagePython))
}

func TestPowerShellExecutor_Execute(t *testing.T) {
	logger := &mockLogger{}
	pe := NewPowerShellExecutor(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Name:     "Test Module",
		Language: LanguagePowerShell,
		Script:   "Write-Host '{{ Param1 }}'",
	}
	
	ctx := context.Background()
	script, err := pe.Execute(ctx, module, map[string]string{"Param1": "value"}, "session-1")
	
	require.NoError(t, err)
	assert.Contains(t, script, "value")
}

func TestNewPythonExecutor(t *testing.T) {
	logger := &mockLogger{}
	py := NewPythonExecutor(logger)
	
	require.NotNil(t, py)
}

func TestPythonExecutor_Supports(t *testing.T) {
	logger := &mockLogger{}
	py := NewPythonExecutor(logger)
	
	assert.True(t, py.Supports(LanguagePython))
	assert.False(t, py.Supports(LanguagePowerShell))
}

func TestPythonExecutor_Execute(t *testing.T) {
	logger := &mockLogger{}
	py := NewPythonExecutor(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Name:     "Test",
		Language: LanguagePython,
		Script:   "print('{{ Param1 }}')",
	}
	
	ctx := context.Background()
	script, err := py.Execute(ctx, module, map[string]string{"Param1": "value"}, "session-1")
	
	require.NoError(t, err)
	assert.Contains(t, script, "value")
}

func TestNewCSharpExecutor(t *testing.T) {
	logger := &mockLogger{}
	cs := NewCSharpExecutor(logger)
	
	require.NotNil(t, cs)
}

func TestCSharpExecutor_Supports(t *testing.T) {
	logger := &mockLogger{}
	cs := NewCSharpExecutor(logger)
	
	assert.True(t, cs.Supports(LanguageCSharp))
	assert.False(t, cs.Supports(LanguagePowerShell))
}

func TestCSharpExecutor_Execute_NoCSharp(t *testing.T) {
	logger := &mockLogger{}
	cs := NewCSharpExecutor(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguageCSharp,
		CSharp:   nil,
	}
	
	ctx := context.Background()
	_, err := cs.Execute(ctx, module, map[string]string{}, "session-1")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing csharp section")
}

func TestCSharpExecutor_Execute_WithCSharp(t *testing.T) {
	logger := &mockLogger{}
	cs := NewCSharpExecutor(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguageCSharp,
		CSharp: &CSharpOption{
			Code: "System.Console.WriteLine(\"{{ Param1 }}\");",
		},
	}
	
	ctx := context.Background()
	code, err := cs.Execute(ctx, module, map[string]string{"Param1": "value"}, "session-1")
	
	require.NoError(t, err)
	assert.Contains(t, code, "value")
}

func TestNewBOFExecutor(t *testing.T) {
	logger := &mockLogger{}
	bf := NewBOFExecutor(logger)
	
	require.NotNil(t, bf)
}

func TestBOFExecutor_Supports(t *testing.T) {
	logger := &mockLogger{}
	bf := NewBOFExecutor(logger)
	
	assert.True(t, bf.Supports(LanguageBOF))
	assert.False(t, bf.Supports(LanguagePowerShell))
}

func TestBOFExecutor_Execute_NoBOF(t *testing.T) {
	logger := &mockLogger{}
	bf := NewBOFExecutor(logger)
	
	module := &EmpireModule{
		ID:  "test",
		BOF: nil,
	}
	
	ctx := context.Background()
	_, err := bf.Execute(ctx, module, map[string]string{}, "session-1")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing bof section")
}

func TestBOFExecutor_Execute_WithBOF(t *testing.T) {
	logger := &mockLogger{}
	bf := NewBOFExecutor(logger)
	
	module := &EmpireModule{
		ID:  "test",
		BOF: &BOFOption{EntryPoint: "go"},
	}
	
	ctx := context.Background()
	result, err := bf.Execute(ctx, module, map[string]string{}, "session-1")
	
	require.NoError(t, err)
	assert.Contains(t, result, "BOF execution prepared")
}

func TestNewModuleExecutionManager(t *testing.T) {
	logger := &mockLogger{}
	mem := NewModuleExecutionManager(logger)
	
	require.NotNil(t, mem)
	assert.NotNil(t, mem.executors)
	assert.Len(t, mem.executors, 4) // PowerShell, Python, C#, BOF
}

func TestModuleExecutionManager_RegisterExecutor(t *testing.T) {
	logger := &mockLogger{}
	mem := NewModuleExecutionManager(logger)
	
	initialLen := len(mem.executors)
	customExec := NewPowerShellExecutor(logger)
	mem.RegisterExecutor(customExec)
	
	assert.Len(t, mem.executors, initialLen+1)
}

func TestModuleExecutionManager_ExecuteModule(t *testing.T) {
	logger := &mockLogger{}
	mem := NewModuleExecutionManager(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Name:     "Test",
		Language: LanguagePowerShell,
		Script:   "Write-Host 'test'",
	}
	
	ctx := context.Background()
	script, err := mem.ExecuteModule(ctx, module, map[string]string{}, "session-1")
	
	require.NoError(t, err)
	assert.NotEmpty(t, script)
}

func TestModuleExecutionManager_ExecuteModule_Unsupported(t *testing.T) {
	logger := &mockLogger{}
	mem := NewModuleExecutionManager(logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguageIronPython, // Not supported
	}
	
	ctx := context.Background()
	_, err := mem.ExecuteModule(ctx, module, map[string]string{}, "session-1")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no executor found")
}

func TestNewModuleSourceLoader(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("/test/path", logger)
	
	require.NotNil(t, msl)
	assert.Equal(t, "/test/path", msl.basePath)
	assert.Equal(t, logger, msl.logger)
}

func TestModuleSourceLoader_LoadModuleSource_Exists(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("test script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	data, err := msl.LoadModuleSource("test.ps1")
	
	require.NoError(t, err)
	assert.Equal(t, []byte("test script"), data)
}

func TestModuleSourceLoader_LoadModuleSource_NotExists(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	_, err := msl.LoadModuleSource("nonexistent.ps1")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "script not found")
}

func TestModuleSourceLoader_GetModuleSource(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("test script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	script, err := msl.GetModuleSource("test.ps1", false, "")
	
	require.NoError(t, err)
	assert.Equal(t, "test script", script)
}

func TestModuleSourceLoader_FinalizeModule(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	script := "main script"
	scriptEnd := "end script"
	
	final, err := msl.FinalizeModule(script, scriptEnd, false, "")
	
	require.NoError(t, err)
	assert.Contains(t, final, "main script")
	assert.Contains(t, final, "end script")
}

func TestProcessModuleWithSource_ScriptPath(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("Write-Host '{{ Param1 }}'"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		Language:   LanguagePowerShell,
		ScriptPath: "test.ps1",
	}
	
	script, err := ProcessModuleWithSource(module, map[string]string{"Param1": "value"}, msl)
	
	require.NoError(t, err)
	assert.Contains(t, script, "value")
}

func TestProcessModuleWithSource_Script(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguagePowerShell,
		Script:   "Write-Host '{{ Param1 }}'",
	}
	
	script, err := ProcessModuleWithSource(module, map[string]string{"Param1": "value"}, msl)
	
	require.NoError(t, err)
	assert.Contains(t, script, "value")
}

func TestProcessModuleWithSource_ScriptEnd(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	module := &EmpireModule{
		ID:         "test",
		Language:   LanguagePowerShell,
		Script:     "main",
		ScriptEnd:  "end",
	}
	
	script, err := ProcessModuleWithSource(module, map[string]string{}, msl)
	
	require.NoError(t, err)
	assert.Contains(t, script, "main")
	assert.Contains(t, script, "end")
}

func TestProcessModuleWithSource_NoScript(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguagePython,
	}
	
	_, err := ProcessModuleWithSource(module, map[string]string{}, msl)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no script")
}

func TestNewCustomGenerateRegistry(t *testing.T) {
	logger := &mockLogger{}
	registry := NewCustomGenerateRegistry(logger)
	
	require.NotNil(t, registry)
	assert.NotNil(t, registry.handlers)
	assert.Greater(t, len(registry.handlers), 0)
}

func TestCustomGenerateRegistry_GetHandler_Exists(t *testing.T) {
	logger := &mockLogger{}
	registry := NewCustomGenerateRegistry(logger)
	
	handler, ok := registry.GetHandler("powershell/credentials/mimikatz/golden_ticket")
	
	assert.True(t, ok)
	assert.NotNil(t, handler)
}

func TestCustomGenerateRegistry_GetHandler_NotExists(t *testing.T) {
	logger := &mockLogger{}
	registry := NewCustomGenerateRegistry(logger)
	
	_, ok := registry.GetHandler("nonexistent/module")
	
	assert.False(t, ok)
}

func TestBuildModuleTask(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test Module",
		Options: []ModuleOption{
			{Name: "RequiredParam", Required: true},
		},
	}
	
	params := map[string]string{
		"RequiredParam": "value",
	}
	
	task, err := BuildModuleTask(module, params)
	
	require.NoError(t, err)
	assert.Equal(t, "module", task["type"])
	assert.Equal(t, "test", task["module_id"])
}

func TestBuildModuleTask_ValidationError(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test",
		Options: []ModuleOption{
			{Name: "RequiredParam", Required: true},
		},
	}
	
	params := map[string]string{}
	
	_, err := BuildModuleTask(module, params)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter")
}

func TestValidateModuleParams_Strict(t *testing.T) {
	module := &EmpireModule{
		ID:   "test",
		Name: "Test",
		Options: []ModuleOption{
			{
				Name:            "Param",
				Strict:          true,
				SuggestedValues: []string{"value1", "value2"},
			},
		},
	}
	
	tests := []struct {
		name    string
		params  map[string]string
		wantErr bool
	}{
		{"valid", map[string]string{"Param": "value1"}, false},
		{"invalid", map[string]string{"Param": "invalid"}, true},
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

func TestModuleSourceLoader_LoadModuleSource_WithExtension(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("test script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	data, err := msl.LoadModuleSource("test")
	
	require.NoError(t, err)
	assert.Equal(t, []byte("test script"), data)
}

func TestModuleSourceLoader_GetModuleSource_Obfuscate(t *testing.T) {
	logger := &mockLogger{}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("test script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	script, err := msl.GetModuleSource("test.ps1", true, "obfuscate-command")
	
	require.NoError(t, err)
	assert.Equal(t, "test script", script)
}

func TestModuleSourceLoader_FinalizeModule_Obfuscate(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	script := "main script"
	scriptEnd := "end script"
	
	final, err := msl.FinalizeModule(script, scriptEnd, true, "obfuscate-command")
	
	require.NoError(t, err)
	assert.Contains(t, final, "main script")
	assert.Contains(t, final, "end script")
}

func TestProcessModuleWithSource_CSharp(t *testing.T) {
	logger := &mockLogger{}
	msl := NewModuleSourceLoader("", logger)
	
	module := &EmpireModule{
		ID:       "test",
		Language: LanguageCSharp,
		CSharp: &CSharpOption{
			Code: "System.Console.WriteLine(\"{{ Param1 }}\");",
		},
	}
	
	script, err := ProcessModuleWithSource(module, map[string]string{"Param1": "value"}, msl)
	
	require.NoError(t, err)
	assert.Contains(t, script, "value")
}

func TestCustomGenerateRegistry_Register(t *testing.T) {
	logger := &mockLogger{}
	registry := NewCustomGenerateRegistry(logger)
	
	initialCount := len(registry.handlers)
	
	// Test that registerAllHandlers was called
	assert.Greater(t, len(registry.handlers), 0)
	
	// Test GetHandler with different formats
	handler1, ok1 := registry.GetHandler("golden_ticket")
	handler2, ok2 := registry.GetHandler("powershell/credentials/mimikatz/golden_ticket")
	
	// At least one should work
	assert.True(t, ok1 || ok2)
	if ok1 || ok2 {
		var handler CustomGenerateHandler
		if ok1 {
			handler = handler1
		} else {
			handler = handler2
		}
		assert.NotNil(t, handler)
	}
	
	_ = initialCount
}

func TestDCSyncHashdumpHandler_Generate(t *testing.T) {
	logger := &mockLogger{}
	handler := &DCSyncHashdumpHandler{logger: logger}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("base script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		ScriptPath: "test.ps1",
	}
	
	params := map[string]string{
		"Domain":        "test.domain",
		"Forest":        "True",
		"Computers":     "True",
		"OutputFunction": "Out-String",
	}
	
	script, err := handler.Generate(module, params, msl, nil)
	
	require.NoError(t, err)
	assert.Contains(t, script, "base script")
	assert.Contains(t, script, "Invoke-DCSync")
	assert.Contains(t, script, "test.domain")
}

func TestMimikatzGoldenTicketHandler_Generate_WithCredID(t *testing.T) {
	logger := &mockLogger{}
	handler := &MimikatzGoldenTicketHandler{logger: logger}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("base script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		ScriptPath: "test.ps1",
	}
	
	mockCredStore := &mockCredentialStore{
		cred: &Credential{
			ID:       "test-id",
			Username: "krbtgt",
			Password: "test-hash",
			Domain:   "test.domain",
			SID:      "S-1-5-21-123",
		},
	}
	
	params := map[string]string{
		"CredID": "test-id",
	}
	
	script, err := handler.Generate(module, params, msl, mockCredStore)
	
	require.NoError(t, err)
	assert.Contains(t, script, "base script")
	assert.Contains(t, script, "kerberos::golden")
}

func TestMimikatzGoldenTicketHandler_Generate_NoKrbtgt(t *testing.T) {
	logger := &mockLogger{}
	handler := &MimikatzGoldenTicketHandler{logger: logger}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("base script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		ScriptPath: "test.ps1",
	}
	
	params := map[string]string{}
	
	_, err := handler.Generate(module, params, msl, nil)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "krbtgt hash not specified")
}

func TestMimikatzPTHHandler_Generate_WithCredID(t *testing.T) {
	logger := &mockLogger{}
	handler := &MimikatzPTHHandler{logger: logger}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("base script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		ScriptPath: "test.ps1",
	}
	
	mockCredStore := &mockCredentialStore{
		cred: &Credential{
			ID:       "test-id",
			Username: "testuser",
			Password: "ntlm-hash",
			Domain:   "test.domain",
			CredType: "hash",
		},
	}
	
	params := map[string]string{
		"CredID": "test-id",
	}
	
	script, err := handler.Generate(module, params, msl, mockCredStore)
	
	require.NoError(t, err)
	assert.Contains(t, script, "base script")
	assert.Contains(t, script, "sekurlsa::pth")
}

func TestMimikatzPTHHandler_Generate_NoNTLM(t *testing.T) {
	logger := &mockLogger{}
	handler := &MimikatzPTHHandler{logger: logger}
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ps1")
	os.WriteFile(testFile, []byte("base script"), 0644)
	
	msl := NewModuleSourceLoader(tmpDir, logger)
	
	module := &EmpireModule{
		ID:         "test",
		ScriptPath: "test.ps1",
	}
	
	params := map[string]string{}
	
	_, err := handler.Generate(module, params, msl, nil)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ntlm hash not specified")
}

type mockCredentialStore struct {
	cred *Credential
}

func (m *mockCredentialStore) GetCredentialByID(id string) (*Credential, error) {
	if m.cred != nil && m.cred.ID == id {
		return m.cred, nil
	}
	return nil, fmt.Errorf("credential not found")
}
