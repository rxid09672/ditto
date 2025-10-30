package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ModuleLanguage represents supported module languages
type ModuleLanguage string

const (
	LanguagePowerShell ModuleLanguage = "powershell"
	LanguagePython     ModuleLanguage = "python"
	LanguageCSharp     ModuleLanguage = "csharp"
	LanguageBOF        ModuleLanguage = "bof"
	LanguageIronPython ModuleLanguage = "ironpython"
)

// ModuleCategory represents module categories
type ModuleCategory string

const (
	CategoryCodeExecution      ModuleCategory = "code_execution"
	CategoryCollection         ModuleCategory = "collection"
	CategoryCredentials        ModuleCategory = "credentials"
	CategoryLateralMovement    ModuleCategory = "lateral_movement"
	CategoryPersistence        ModuleCategory = "persistence"
	CategoryPrivilegeEscalation ModuleCategory = "privesc"
	CategorySituationalAwareness ModuleCategory = "situational_awareness"
	CategoryManagement         ModuleCategory = "management"
	CategoryRecon              ModuleCategory = "recon"
	CategoryExfiltration       ModuleCategory = "exfiltration"
	CategoryExploitation       ModuleCategory = "exploitation"
	CategoryTrollsploit        ModuleCategory = "trollsploit"
)

// Author represents module author
type Author struct {
	Name   string `yaml:"name" json:"name"`
	Handle string `yaml:"handle" json:"handle"`
	Link   string `yaml:"link" json:"link"`
}

// ModuleOption represents a module option
type ModuleOption struct {
	Name           string   `yaml:"name" json:"name"`
	NameInCode     string   `yaml:"name_in_code" json:"name_in_code"`
	Description    string   `yaml:"description" json:"description"`
	Required       bool     `yaml:"required" json:"required"`
	Value          string   `yaml:"value" json:"value"`
	SuggestedValues []string `yaml:"suggested_values" json:"suggested_values"`
	Strict         bool     `yaml:"strict" json:"strict"`
	Type           string   `yaml:"type" json:"type"`
	Internal       bool     `yaml:"internal" json:"internal"`
	DependsOn      []map[string]interface{} `yaml:"depends_on" json:"depends_on"`
}

// ModuleAdvanced represents advanced module options
type ModuleAdvanced struct {
	OptionFormatString        string `yaml:"option_format_string" json:"option_format_string"`
	OptionFormatStringBoolean string `yaml:"option_format_string_boolean" json:"option_format_string_boolean"`
	CustomGenerate            bool   `yaml:"custom_generate" json:"custom_generate"`
}

// BOFOption represents BOF module options
type BOFOption struct {
	X86         string `yaml:"x86" json:"x86"`
	X64         string `yaml:"x64" json:"x64"`
	EntryPoint  string `yaml:"entry_point" json:"entry_point"`
	FormatString string `yaml:"format_string" json:"format_string"`
}

// CSharpOption represents C# module options
type CSharpOption struct {
	UnsafeCompile            bool                   `yaml:"UnsafeCompile" json:"UnsafeCompile"`
	CompatibleDotNetVersions []string               `yaml:"CompatibleDotNetVersions" json:"CompatibleDotNetVersions"`
	Code                     string                 `yaml:"Code" json:"Code"`
	ReferenceSourceLibraries []map[string]interface{} `yaml:"ReferenceSourceLibraries" json:"ReferenceSourceLibraries"`
	ReferenceAssemblies      []map[string]interface{} `yaml:"ReferenceAssemblies" json:"ReferenceAssemblies"`
	EmbeddedResources        []map[string]interface{} `yaml:"EmbeddedResources" json:"EmbeddedResources"`
}

// EmpireModule represents an Empire module
type EmpireModule struct {
	ID               string          `yaml:"id" json:"id"`
	Name             string          `yaml:"name" json:"name"`
	Authors          []Author        `yaml:"authors" json:"authors"`
	Description      string          `yaml:"description" json:"description"`
	Software         string          `yaml:"software" json:"software"`
	Techniques       []string        `yaml:"techniques" json:"techniques"`
	Tactics          []string        `yaml:"tactics" json:"tactics"`
	Background       bool            `yaml:"background" json:"background"`
	OutputExtension  string          `yaml:"output_extension" json:"output_extension"`
	NeedsAdmin       bool            `yaml:"needs_admin" json:"needs_admin"`
	OpsecSafe        bool            `yaml:"opsec_safe" json:"opsec_safe"`
	Language         ModuleLanguage  `yaml:"language" json:"language"`
	MinLanguageVersion string        `yaml:"min_language_version" json:"min_language_version"`
	Comments         []string        `yaml:"comments" json:"comments"`
	Options          []ModuleOption  `yaml:"options" json:"options"`
	Script           string          `yaml:"script" json:"script"`
	ScriptPath       string          `yaml:"script_path" json:"script_path"`
	ScriptEnd        string          `yaml:"script_end" json:"script_end"`
	BOF              *BOFOption      `yaml:"bof" json:"bof"`
	CSharp           *CSharpOption    `yaml:"csharp" json:"csharp"`
	Advanced         ModuleAdvanced  `yaml:"advanced" json:"advanced"`
	Enabled          bool            `yaml:"enabled" json:"enabled"`
	
	// Internal fields
	Category ModuleCategory `json:"category"`
	Path     string         `json:"path"`
	FilePath string         `json:"file_path"`
}

// ModuleRegistry manages Empire modules
type ModuleRegistry struct {
	modules map[string]*EmpireModule
	mu      sync.RWMutex
	logger  interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]*EmpireModule),
		logger:  logger,
	}
}

// LoadModule loads a module from YAML file
func (mr *ModuleRegistry) LoadModule(filePath string) (*EmpireModule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module file: %w", err)
	}
	
	var module EmpireModule
	if err := yaml.Unmarshal(data, &module); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	
	// Generate ID if not present
	if module.ID == "" {
		// Use full path-based ID (e.g., powershell/privesc/getsystem)
		module.ID = mr.extractModulePath(filePath)
		// Remove "empire/" prefix if present
		if strings.HasPrefix(module.ID, "empire/") {
			module.ID = strings.TrimPrefix(module.ID, "empire/")
		}
	}
	
	// Determine category from path
	module.Category = mr.determineCategory(filePath)
	module.FilePath = filePath
	module.Path = mr.extractModulePath(filePath)
	
	// Register module
	mr.mu.Lock()
	mr.modules[module.ID] = &module
	mr.mu.Unlock()
	
	mr.logger.Debug("Loaded module: %s (%s)", module.Name, module.ID)
	
	return &module, nil
}

// LoadModulesFromDirectory loads all modules from a directory
func (mr *ModuleRegistry) LoadModulesFromDirectory(dirPath string) error {
	mr.logger.Info("Loading modules from directory: %s", dirPath)
	
	var loadCount int
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			_, err := mr.LoadModule(path)
			if err != nil {
				mr.logger.Error("Failed to load module %s: %v", path, err)
				return nil // Continue loading other modules
			}
			loadCount++
		}
		
		return nil
	})
	
	mr.logger.Info("Loaded %d modules", loadCount)
	return err
}

// GetModuleByPath retrieves a module by path (e.g., powershell/privesc/getsystem)
func (mr *ModuleRegistry) GetModuleByPath(path string) (*EmpireModule, bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	// Try exact path match first
	for _, module := range mr.modules {
		if module.Path == path || module.ID == path {
			return module, true
		}
	}
	
	// Try with "empire/" prefix
	pathWithEmpire := "empire/" + path
	for _, module := range mr.modules {
		if module.Path == pathWithEmpire || module.ID == pathWithEmpire {
			return module, true
		}
	}
	
	return nil, false
}

// GetModule retrieves a module by ID
func (mr *ModuleRegistry) GetModule(id string) (*EmpireModule, bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	module, ok := mr.modules[id]
	return module, ok
}

// SearchModules searches modules by criteria
func (mr *ModuleRegistry) SearchModules(query string) []*EmpireModule {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	results := []*EmpireModule{}
	queryLower := strings.ToLower(query)
	
	for _, module := range mr.modules {
		if strings.Contains(strings.ToLower(module.Name), queryLower) ||
			strings.Contains(strings.ToLower(module.Description), queryLower) {
			results = append(results, module)
		}
	}
	
	return results
}

// ListModulesByCategory lists modules by category
func (mr *ModuleRegistry) ListModulesByCategory(category ModuleCategory) []*EmpireModule {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	results := []*EmpireModule{}
	for _, module := range mr.modules {
		if module.Category == category {
			results = append(results, module)
		}
	}
	
	return results
}

// ListModulesByLanguage lists modules by language
func (mr *ModuleRegistry) ListModulesByLanguage(language ModuleLanguage) []*EmpireModule {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	results := []*EmpireModule{}
	for _, module := range mr.modules {
		if module.Language == language {
			results = append(results, module)
		}
	}
	
	return results
}

// ListAllModules returns all modules
func (mr *ModuleRegistry) ListAllModules() []*EmpireModule {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	modules := make([]*EmpireModule, 0, len(mr.modules))
	for _, module := range mr.modules {
		modules = append(modules, module)
	}
	
	return modules
}

// GetModuleCount returns total module count
func (mr *ModuleRegistry) GetModuleCount() int {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return len(mr.modules)
}

// Helper functions
func (mr *ModuleRegistry) generateModuleID(filePath string) string {
	base := filepath.Base(filePath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return strings.ToLower(strings.ReplaceAll(name, "_", "/"))
}

func (mr *ModuleRegistry) determineCategory(filePath string) ModuleCategory {
	pathLower := strings.ToLower(filePath)
	
	categories := map[string]ModuleCategory{
		"code_execution":      CategoryCodeExecution,
		"collection":          CategoryCollection,
		"credentials":         CategoryCredentials,
		"lateral_movement":    CategoryLateralMovement,
		"persistence":         CategoryPersistence,
		"privesc":             CategoryPrivilegeEscalation,
		"situational_awareness": CategorySituationalAwareness,
		"management":          CategoryManagement,
		"recon":               CategoryRecon,
		"exfiltration":        CategoryExfiltration,
		"exploitation":        CategoryExploitation,
		"trollsploit":         CategoryTrollsploit,
	}
	
	for key, category := range categories {
		if strings.Contains(pathLower, key) {
			return category
		}
	}
	
	return CategoryCodeExecution // Default
}

func (mr *ModuleRegistry) extractModulePath(filePath string) string {
	parts := strings.Split(filePath, string(filepath.Separator))
	modulesIdx := -1
	for i, part := range parts {
		if part == "modules" {
			modulesIdx = i
			break
		}
	}
	
	if modulesIdx == -1 {
		return filepath.Base(filePath)
	}
	
	pathParts := parts[modulesIdx+1:]
	ext := filepath.Ext(pathParts[len(pathParts)-1])
	pathParts[len(pathParts)-1] = strings.TrimSuffix(pathParts[len(pathParts)-1], ext)
	
	return strings.Join(pathParts, "/")
}

// ProcessModule processes a module with parameters
func ProcessModule(module *EmpireModule, params map[string]string) (string, error) {
	var script string
	
	if module.ScriptPath != "" {
		// Load script from file path
		// Try common module source paths
		possiblePaths := []string{
			module.ScriptPath,
			"modules/module_source/" + module.ScriptPath,
			"module_source/" + module.ScriptPath,
		}
		
		for _, path := range possiblePaths {
			if data, readErr := os.ReadFile(path); readErr == nil {
				script = string(data)
				break
			}
		}
		
		if script == "" {
			return "", fmt.Errorf("failed to load script_path: %s", module.ScriptPath)
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
		script += "\n" + substituteTemplate(module.ScriptEnd, params)
	}
	
	return script, nil
}

// substituteTemplate substitutes {{ PARAM }} placeholders
func substituteTemplate(template string, params map[string]string) string {
	result := template
	
	// Handle {{ OUTPUT_FUNCTION }} - default to Out-String if not specified
	if strings.Contains(result, "{{ OUTPUT_FUNCTION }}") {
		outputFunc := params["OUTPUT_FUNCTION"]
		if outputFunc == "" {
			outputFunc = "Out-String" // Default output function for PowerShell modules
		}
		result = strings.ReplaceAll(result, "{{ OUTPUT_FUNCTION }}", outputFunc)
	}
	
	// Handle {{ PARAMS }} - build parameter string
	if strings.Contains(result, "{{ PARAMS }}") {
		paramsStr := buildParamsString(params)
		result = strings.ReplaceAll(result, "{{ PARAMS }}", paramsStr)
	}
	
	// Handle other {{ PARAM }} placeholders
	re := regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`)
	result = re.ReplaceAllStringFunc(result, func(match string) string {
		paramName := strings.TrimSpace(strings.Trim(match, "{}"))
		if value, ok := params[paramName]; ok {
			return value
		}
		return match
	})
	
	return result
}

// buildParamsString builds parameter string for PowerShell modules
func buildParamsString(params map[string]string) string {
	var parts []string
	
	for key, value := range params {
		if key == "Agent" || value == "" {
			continue
		}
		
		if value == "True" || value == "False" {
			parts = append(parts, fmt.Sprintf("-%s", key))
		} else {
			parts = append(parts, fmt.Sprintf("-%s \"%s\"", key, value))
		}
	}
	
	return strings.Join(parts, " ")
}

// ToJSON converts module to JSON
func (m *EmpireModule) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

