package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ModuleSourceLoader loads module source files
type ModuleSourceLoader struct {
	basePath string
	logger   interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewModuleSourceLoader creates a new module source loader
func NewModuleSourceLoader(basePath string, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ModuleSourceLoader {
	return &ModuleSourceLoader{
		basePath: basePath,
		logger:   logger,
	}
}

// LoadModuleSource loads a module source file
func (msl *ModuleSourceLoader) LoadModuleSource(scriptPath string) ([]byte, error) {
	fullPath := filepath.Join(msl.basePath, scriptPath)
	
	if data, err := os.ReadFile(fullPath); err == nil {
		return data, nil
	}
	
	if !strings.HasSuffix(fullPath, ".ps1") && !strings.HasSuffix(fullPath, ".py") {
		if data, err := os.ReadFile(fullPath + ".ps1"); err == nil {
			return data, nil
		}
		if data, err := os.ReadFile(fullPath + ".py"); err == nil {
			return data, nil
		}
	}
	
	var foundPath string
	filepath.Walk(msl.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, scriptPath) || strings.HasSuffix(path, filepath.Base(scriptPath)) {
			foundPath = path
			return filepath.SkipAll
		}
		return nil
	})
	
	if foundPath == "" {
		return nil, fmt.Errorf("script not found: %s", scriptPath)
	}
	
	return os.ReadFile(foundPath)
}

// GetModuleSource gets module source with obfuscation support
func (msl *ModuleSourceLoader) GetModuleSource(scriptPath string, obfuscate bool, obfuscateCommand string) (string, error) {
	data, err := msl.LoadModuleSource(scriptPath)
	if err != nil {
		return "", err
	}
	
	script := string(data)
	if obfuscate && obfuscateCommand != "" {
		script = obfuscateScript(script, obfuscateCommand)
		msl.logger.Debug("Applied obfuscation to module source")
	}
	
	return script, nil
}

// FinalizeModule finalizes a module script with script_end
func (msl *ModuleSourceLoader) FinalizeModule(script, scriptEnd string, obfuscate bool, obfuscateCommand string) (string, error) {
	finalScript := script + "\n" + scriptEnd
	if obfuscate && obfuscateCommand != "" {
		finalScript = obfuscateScript(finalScript, obfuscateCommand)
		msl.logger.Debug("Applied obfuscation to finalized module")
	}
	return finalScript, nil
}

// obfuscateScript applies basic obfuscation to scripts
func obfuscateScript(script, command string) string {
	// Basic PowerShell obfuscation: encoding and variable substitution
	if strings.Contains(command, "powershell") || strings.Contains(script, "$") {
		// Replace common variable names with random ones
		script = strings.ReplaceAll(script, "$env:", "$x" + generateRandomString(3) + ":")
		script = strings.ReplaceAll(script, "$ErrorActionPreference", "$x" + generateRandomString(5))
	}
	return script
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

// ProcessModuleWithSource processes a module including script_path loading
func ProcessModuleWithSource(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader) (string, error) {
	var script string
	var err error
	
	if module.ScriptPath != "" {
		script, err = sourceLoader.GetModuleSource(module.ScriptPath, false, "")
		if err != nil {
			return "", fmt.Errorf("failed to load script_path: %w", err)
		}
	} else if module.Script != "" {
		script = module.Script
	} else if module.Language == LanguageCSharp && module.CSharp != nil {
		script = module.CSharp.Code
	} else {
		return "", fmt.Errorf("module has no script, script_path, or csharp code")
	}
	
	script = substituteTemplate(script, params)
	
	if module.Language == LanguagePowerShell && module.ScriptEnd != "" {
		scriptEnd := substituteTemplate(module.ScriptEnd, params)
		script, err = sourceLoader.FinalizeModule(script, scriptEnd, false, "")
		if err != nil {
			return "", err
		}
	}
	
	return script, nil
}

