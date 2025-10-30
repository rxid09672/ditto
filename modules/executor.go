package modules

import (
	"context"
	"fmt"
	
	"github.com/ditto/ditto/credentials"
)

// ModuleExecutor executes modules
type ModuleExecutor interface {
	Execute(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error)
	Supports(language ModuleLanguage) bool
	SetCredentialStore(store credentials.CredentialStore)
}

// PowerShellExecutor executes PowerShell modules
type PowerShellExecutor struct {
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	credStore credentials.CredentialStore
}

// NewPowerShellExecutor creates a new PowerShell executor
func NewPowerShellExecutor(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *PowerShellExecutor {
	return &PowerShellExecutor{logger: logger}
}

// SetCredentialStore sets the credential store for the executor
func (pe *PowerShellExecutor) SetCredentialStore(store credentials.CredentialStore) {
	pe.credStore = store
}

func (pe *PowerShellExecutor) Supports(language ModuleLanguage) bool {
	return language == LanguagePowerShell
}

func (pe *PowerShellExecutor) Execute(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error) {
	pe.logger.Info("Executing PowerShell module: %s", module.Name)

	// Create source loader (would be passed in production)
	sourceLoader := NewModuleSourceLoader("./modules/module_source", pe.logger)

	// Check for custom generate handler
	customRegistry := NewCustomGenerateRegistry(pe.logger)
	if handler, ok := customRegistry.GetHandler(module.ID); ok {
		// Use credential store if available - create adapter
		var credStore CredentialStore
		if pe.credStore != nil {
			credStore = &credentialStoreAdapter{store: pe.credStore}
		}
		script, err := handler.Generate(module, params, sourceLoader, credStore)
		if err != nil {
			return "", fmt.Errorf("custom generate failed: %w", err)
		}
		pe.logger.Debug("Generated PowerShell script (custom): %d bytes", len(script))
		return script, nil
	}

	// Standard processing
	script, err := ProcessModuleWithSource(module, params, sourceLoader)
	if err != nil {
		return "", fmt.Errorf("failed to process module: %w", err)
	}

	pe.logger.Debug("Generated PowerShell script: %d bytes", len(script))
	return script, nil
}

// PythonExecutor executes Python modules
type PythonExecutor struct {
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	credStore credentials.CredentialStore
}

// NewPythonExecutor creates a new Python executor
func NewPythonExecutor(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *PythonExecutor {
	return &PythonExecutor{logger: logger}
}

// SetCredentialStore sets the credential store for the executor
func (py *PythonExecutor) SetCredentialStore(store credentials.CredentialStore) {
	py.credStore = store
}

func (py *PythonExecutor) Supports(language ModuleLanguage) bool {
	return language == LanguagePython
}

func (py *PythonExecutor) Execute(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error) {
	py.logger.Info("Executing Python module: %s", module.Name)

	script, err := ProcessModule(module, params)
	if err != nil {
		return "", fmt.Errorf("failed to process module: %w", err)
	}

	py.logger.Debug("Generated Python script: %d bytes", len(script))

	return script, nil
}

// CSharpExecutor executes C# modules
type CSharpExecutor struct {
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	credStore credentials.CredentialStore
}

// NewCSharpExecutor creates a new C# executor
func NewCSharpExecutor(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *CSharpExecutor {
	return &CSharpExecutor{logger: logger}
}

// SetCredentialStore sets the credential store for the executor
func (cs *CSharpExecutor) SetCredentialStore(store credentials.CredentialStore) {
	cs.credStore = store
}

func (cs *CSharpExecutor) Supports(language ModuleLanguage) bool {
	return language == LanguageCSharp
}

func (cs *CSharpExecutor) Execute(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error) {
	cs.logger.Info("Executing C# module: %s", module.Name)

	if module.CSharp == nil {
		return "", fmt.Errorf("C# module missing csharp section")
	}

	// Compile C# code
	// In production, would use Roslyn compiler or similar
	code := module.CSharp.Code

	// Template substitution
	code = substituteTemplate(code, params)

	cs.logger.Debug("Generated C# code: %d bytes", len(code))

	// Compile and execute
	return code, nil
}

// BOFExecutor executes BOF modules
type BOFExecutor struct {
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	credStore credentials.CredentialStore
}

// NewBOFExecutor creates a new BOF executor
func NewBOFExecutor(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *BOFExecutor {
	return &BOFExecutor{logger: logger}
}

// SetCredentialStore sets the credential store for the executor
func (bf *BOFExecutor) SetCredentialStore(store credentials.CredentialStore) {
	bf.credStore = store
}

func (bf *BOFExecutor) Supports(language ModuleLanguage) bool {
	return language == LanguageBOF
}

func (bf *BOFExecutor) Execute(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error) {
	bf.logger.Info("Executing BOF module: %s", module.Name)

	if module.BOF == nil {
		return "", fmt.Errorf("BOF module missing bof section")
	}

	// Load and execute BOF
	// In production, would load BOF file and execute via beacon API

	bf.logger.Debug("BOF module prepared for execution")

	return "BOF execution prepared", nil
}

// ModuleExecutionManager manages module execution
type ModuleExecutionManager struct {
	executors []ModuleExecutor
	logger    interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// credentialStoreAdapter adapts credentials.CredentialStore to modules.CredentialStore
type credentialStoreAdapter struct {
	store credentials.CredentialStore
}

func (a *credentialStoreAdapter) GetCredentialByID(id string) (*Credential, error) {
	ctx := context.Background()
	cred, err := a.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	
	return &Credential{
		ID:       cred.ID,
		Username: cred.Username,
		Password: cred.Password,
		Domain:   cred.Domain,
		CredType: cred.Type,
	}, nil
}

// NewModuleExecutionManager creates a new execution manager
func NewModuleExecutionManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ModuleExecutionManager {
	manager := &ModuleExecutionManager{
		executors: []ModuleExecutor{},
		logger:    logger,
	}

	// Register executors
	manager.RegisterExecutor(NewPowerShellExecutor(logger))
	manager.RegisterExecutor(NewPythonExecutor(logger))
	manager.RegisterExecutor(NewCSharpExecutor(logger))
	manager.RegisterExecutor(NewBOFExecutor(logger))

	return manager
}

// RegisterExecutor registers an executor
func (mem *ModuleExecutionManager) RegisterExecutor(executor ModuleExecutor) {
	mem.executors = append(mem.executors, executor)
}

// ExecuteModule executes a module
func (mem *ModuleExecutionManager) ExecuteModule(ctx context.Context, module *EmpireModule, params map[string]string, sessionID string) (string, error) {
	// Find appropriate executor
	for _, executor := range mem.executors {
		if executor.Supports(module.Language) {
			return executor.Execute(ctx, module, params, sessionID)
		}
	}

	return "", fmt.Errorf("no executor found for language: %s", module.Language)
}

// ValidateModuleParams validates module parameters
func ValidateModuleParams(module *EmpireModule, params map[string]string) error {
	// Check required parameters
	for _, option := range module.Options {
		if option.Required {
			if value, ok := params[option.Name]; !ok || value == "" {
				return fmt.Errorf("required parameter missing: %s", option.Name)
			}
		}

		// Check strict values
		if option.Strict && len(option.SuggestedValues) > 0 {
			value := params[option.Name]
			valid := false
			for _, suggested := range option.SuggestedValues {
				if value == suggested {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid value for parameter %s: %s (must be one of: %v)", option.Name, value, option.SuggestedValues)
			}
		}
	}

	return nil
}

// BuildModuleTask builds a task for module execution
func BuildModuleTask(module *EmpireModule, params map[string]string) (map[string]interface{}, error) {
	if err := ValidateModuleParams(module, params); err != nil {
		return nil, err
	}

	task := map[string]interface{}{
		"type":        "module",
		"module_id":   module.ID,
		"module_name": module.Name,
		"language":    string(module.Language),
		"params":      params,
		"background":  module.Background,
		"needs_admin": module.NeedsAdmin,
	}

	return task, nil
}
