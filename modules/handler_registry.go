package modules

import (
	"fmt"
	"strings"
)

// CustomGenerateRegistry maps module names/paths to custom handlers
type CustomGenerateRegistry struct {
	handlers map[string]CustomGenerateHandler
	logger   interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewCustomGenerateRegistry creates a new custom generate registry
func NewCustomGenerateRegistry(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *CustomGenerateRegistry {
	registry := &CustomGenerateRegistry{
		handlers: make(map[string]CustomGenerateHandler),
		logger:   logger,
	}
	registry.registerAllHandlers()
	return registry
}

// GetHandler retrieves a handler for a module
func (r *CustomGenerateRegistry) GetHandler(moduleID string) (CustomGenerateHandler, bool) {
	handler, ok := r.handlers[moduleID]
	return handler, ok
}

// registerAllHandlers registers all custom handlers
func (r *CustomGenerateRegistry) registerAllHandlers() {
	// Mimikatz handlers
	r.register("powershell/credentials/mimikatz/golden_ticket", &MimikatzGoldenTicketHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/dcsync", &MimikatzDCSyncHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/dcsync_hashdump", &DCSyncHashdumpHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/pth", &MimikatzPTHHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/silver_ticket", &MimikatzSilverTicketHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/lsadump", &MimikatzLSADumpHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/tokens", &MimikatzTokensHandler{logger: r.logger})
	r.register("powershell/credentials/mimikatz/keys", &MimikatzTrustKeysHandler{logger: r.logger})
	
	// Management handlers
	r.register("powershell/management/spawn", &SpawnHandler{logger: r.logger})
	r.register("powershell/management/spawnas", &SpawnAsHandler{logger: r.logger})
	r.register("powershell/management/runas", &RunAsHandler{logger: r.logger})
	r.register("powershell/management/shinject", &ShellInjectHandler{logger: r.logger})
	r.register("powershell/management/psinject", &PSInjectHandler{logger: r.logger})
	r.register("powershell/management/reflective_inject", &ReflectiveInjectHandler{logger: r.logger})
	r.register("powershell/management/switch_listener", &SwitchListenerHandler{logger: r.logger})
	r.register("powershell/management/logoff", &LogoffHandler{logger: r.logger})
	r.register("powershell/management/invoke_bypass", &InvokeBypassHandler{logger: r.logger})
	r.register("powershell/management/user_to_sid", &UserToSIDHandler{logger: r.logger})
	
	// Lateral movement handlers
	r.register("powershell/lateral_movement/invoke_wmi", &InvokeWMIHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_psexec", &InvokePsExecHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_dcom", &InvokeDCOMHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_smbexec", &InvokeSMBExecHandler{logger: r.logger})
	r.register("powershell/lateral_movement/new_gpo_immediate_task", &NewGPOImmediateTaskHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_psremoting", &InvokePSRemotingHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_wmi_debugger", &InvokeWMIDebuggerHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_sqloscmd", &InvokeSQLOSCmdHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_sshcommand", &InvokeSSHCommandHandler{logger: r.logger})
	r.register("powershell/lateral_movement/invoke_executemsbuild", &InvokeExecuteMSBuildHandler{logger: r.logger})
	r.register("powershell/lateral_movement/jenkins_script_console", &JenkinsScriptConsoleHandler{logger: r.logger})
	r.register("powershell/lateral_movement/inveigh_relay", &InveighRelayHandler{logger: r.logger})
	
	// Persistence handlers
	r.register("powershell/persistence/elevated/wmi", &WMIPersistenceHandler{logger: r.logger})
	r.register("powershell/persistence/elevated/schtasks", &ScheduledTaskHandler{logger: r.logger})
	r.register("powershell/persistence/elevated/wmi_updater", &WMIUpdaterHandler{logger: r.logger})
	r.register("powershell/persistence/elevated/registry", &RegistryPersistenceHandler{logger: r.logger})
	r.register("powershell/persistence/userland/registry", &RegistryUserlandHandler{logger: r.logger})
	r.register("powershell/persistence/userland/backdoor_lnk", &BackdoorLNKHandler{logger: r.logger})
	r.register("powershell/persistence/userland/schtasks", &ScheduledTaskUserlandHandler{logger: r.logger})
	r.register("powershell/persistence/misc/debugger", &DebuggerHandler{logger: r.logger})
	r.register("powershell/persistence/misc/add_sid_history", &AddSIDHistoryHandler{logger: r.logger})
	r.register("powershell/persistence/powerbreach/deaduser", &DeadUserHandler{logger: r.logger})
	r.register("powershell/persistence/powerbreach/eventlog", &EventLogHandler{logger: r.logger})
	r.register("powershell/persistence/powerbreach/resolver", &ResolverHandler{logger: r.logger})
	
	// Privilege escalation handlers
	r.register("powershell/privesc/bypassuac", &BypassUACHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_eventvwr", &BypassUACEventVWRHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_fodhelper", &BypassUACFodHelperHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_tokenmanipulation", &BypassUACTokenManipulationHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_sdctlbypass", &BypassUACSDCTLHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_wscript", &BypassUACWScriptHandler{logger: r.logger})
	r.register("powershell/privesc/bypassuac_env", &BypassUACEnvHandler{logger: r.logger})
	r.register("powershell/privesc/ms16-032", &MS16032Handler{logger: r.logger})
	r.register("powershell/privesc/ms16-135", &MS16135Handler{logger: r.logger})
	r.register("powershell/privesc/ask", &AskHandler{logger: r.logger})
	r.register("powershell/privesc/powerup/write_dllhijacker", &WriteDLLHijackerHandler{logger: r.logger})
	r.register("powershell/privesc/powerup/service_stager", &ServiceStagerHandler{logger: r.logger})
	r.register("powershell/privesc/powerup/service_exe_stager", &ServiceExeStagerHandler{logger: r.logger})
	
	// Code execution handlers
	r.register("powershell/code_execution/invoke_shellcode", &InvokeShellcodeHandler{logger: r.logger})
	r.register("powershell/code_execution/invoke_shellcodemsil", &InvokeShellcodeMSILHandler{logger: r.logger})
	r.register("powershell/code_execution/invoke_reflectivepeinjection", &InvokeReflectivePEInjectionHandler{logger: r.logger})
	r.register("powershell/code_execution/invoke_ntsd", &InvokeNTSDHandler{logger: r.logger})
	r.register("powershell/code_execution/invoke_script", &InvokeScriptHandler{logger: r.logger})
	
	// Credential handlers
	r.register("powershell/credentials/credential_injection", &CredentialInjectionHandler{logger: r.logger})
	r.register("powershell/credentials/tokens", &TokensHandler{logger: r.logger})
	r.register("powershell/credentials/invoke_kerberoast", &InvokeKerberoastHandler{logger: r.logger})
	r.register("powershell/credentials/vault_credential", &VaultCredentialHandler{logger: r.logger})
	r.register("powershell/credentials/DomainPasswordSpray", &DomainPasswordSprayHandler{logger: r.logger})
	r.register("powershell/credentials/sessiongopher", &SessionGopherHandler{logger: r.logger})
	r.register("powershell/credentials/powerdump", &PowerDumpHandler{logger: r.logger})
	r.register("powershell/credentials/sharpsecdump", &SharpSecDumpHandler{logger: r.logger})
	r.register("powershell/credentials/VeeamGetCreds", &VeeamGetCredsHandler{logger: r.logger})
	r.register("powershell/credentials/enum_cred_store", &EnumCredStoreHandler{logger: r.logger})
	r.register("powershell/credentials/get_lapspasswords", &GetLAPSPasswordsHandler{logger: r.logger})
	r.register("powershell/credentials/invoke_ntlmextract", &InvokeNTLMExtractHandler{logger: r.logger})
	r.register("powershell/credentials/invoke_internal_monologue", &InvokeInternalMonologueHandler{logger: r.logger})
	
	// Collection handlers
	r.register("powershell/collection/screenshot", &ScreenshotHandler{logger: r.logger})
	r.register("powershell/collection/minidump", &MinidumpHandler{logger: r.logger})
	r.register("powershell/collection/packet_capture", &PacketCaptureHandler{logger: r.logger})
	r.register("powershell/collection/WireTap", &WireTapHandler{logger: r.logger})
	r.register("powershell/collection/SharpChromium", &SharpChromiumHandler{logger: r.logger})
	r.register("powershell/collection/get_sql_column_sample_data", &GetSQLColumnSampleDataHandler{logger: r.logger})
	
	// Recon handlers
	r.register("powershell/recon/find_fruit", &FindFruitHandler{logger: r.logger})
	r.register("powershell/recon/get_sql_server_login_default_pw", &SQLServerDefaultPWHandler{logger: r.logger})
	r.register("powershell/recon/fetch_brute_local", &FetchBruteLocalHandler{logger: r.logger})
	
	// Situational awareness handlers
	r.register("powershell/situational_awareness/host/computerdetails", &ComputerDetailsHandler{logger: r.logger})
	r.register("powershell/situational_awareness/network/powerview/get_subnet_ranges", &GetSubnetRangesHandler{logger: r.logger})
	r.register("powershell/situational_awareness/network/powerview/get_gpo_computer", &GetGPOComputerHandler{logger: r.logger})
	r.register("powershell/situational_awareness/network/get_sql_server_info", &GetSQLServerInfoHandler{logger: r.logger})
	
	// Management handlers
	r.register("powershell/management/mailraider/get_emailitems", &GetEmailItemsHandler{logger: r.logger})
	r.register("powershell/management/mailraider/disable_security", &DisableSecurityHandler{logger: r.logger})
	
	// Exploitation handlers
	r.register("powershell/exploitation/exploit_eternalblue", &ExploitEternalBlueHandler{logger: r.logger})
	
	// Exfiltration handlers
	r.register("powershell/exfiltration/PSRansom", &PSRansomHandler{logger: r.logger})
	
	// Python handlers
	r.register("python/management/multi/spawn", &PythonSpawnHandler{logger: r.logger})
	r.register("python/collection/osx/hashdump", &OSXHashdumpHandler{logger: r.logger})
	r.register("python/collection/osx/keychaindump", &OSXKeychainDumpHandler{logger: r.logger})
	r.register("python/collection/osx/search_email", &SearchEmailHandler{logger: r.logger})
	r.register("python/collection/osx/prompt", &PromptHandler{logger: r.logger})
	r.register("python/collection/osx/native_screenshot_mss", &NativeScreenshotMSSHandler{logger: r.logger})
	r.register("python/collection/osx/imessage_dump", &IMessageDumpHandler{logger: r.logger})
	r.register("python/collection/osx/sniffer", &SnifferHandler{logger: r.logger})
	r.register("python/privesc/osx/dyld_print_to_file", &DyldPrintToFileHandler{logger: r.logger})
	r.register("python/privesc/multi/sudo_spawn", &SudoSpawnHandler{logger: r.logger})
	r.register("python/privesc/multi/CVE-2021-4034", &CVE20214034Handler{logger: r.logger})
	r.register("python/privesc/multi/CVE-2021-3560", &CVE20213560Handler{logger: r.logger})
	r.register("python/privesc/multi/bashdoor", &BashdoorHandler{logger: r.logger})
	r.register("python/privesc/osx/piggyback", &OSXPiggybackHandler{logger: r.logger})
	r.register("python/persistence/osx/LaunchAgent", &OSXLaunchAgentHandler{logger: r.logger})
	r.register("python/persistence/osx/LaunchAgentUserLandPersistence", &OSXLaunchAgentUserlandHandler{logger: r.logger})
	r.register("python/persistence/osx/loginhook", &LoginHookHandler{logger: r.logger})
	r.register("python/persistence/osx/mail", &MailPersistenceHandler{logger: r.logger})
	r.register("python/persistence/osx/CreateHijacker", &CreateHijackerHandler{logger: r.logger})
	r.register("python/persistence/multi/desktopfile", &DesktopFileHandler{logger: r.logger})
	r.register("python/management/osx/shellcodeinject64", &ShellcodeInject64Handler{logger: r.logger})
	r.register("python/situational_awareness/host/osx/situational_awareness", &OSXSituationalAwarenessHandler{logger: r.logger})
	r.register("python/lateral_movement/multi/ssh_launcher", &SSHLauncherHandler{logger: r.logger})
	
	// BOF handlers
	r.register("bof/tgtdelegation", &TGTDelegationHandler{logger: r.logger})
	r.register("bof/secinject", &SecInjectHandler{logger: r.logger})
	r.register("bof/nanodump", &NanoDumpHandler{logger: r.logger})
	r.register("bof/clipboard_window_inject", &ClipboardWindowInjectHandler{logger: r.logger})
	r.register("bof/situational_awareness/wmi_query", &WMIQueryHandler{logger: r.logger})
	r.register("bof/situational_awareness/windowlist", &WindowListHandler{logger: r.logger})
	r.register("bof/situational_awareness/netshares", &NetSharesHandler{logger: r.logger})
	r.register("bof/situational_awareness/netloggedon", &NetLoggedOnHandler{logger: r.logger})
	r.register("bof/situational_awareness/netLocalGroupList", &NetLocalGroupListHandler{logger: r.logger})
	r.register("bof/situational_awareness/netLocalGroupListMembers", &NetLocalGroupListMembersHandler{logger: r.logger})
	r.register("bof/situational_awareness/netGroupList", &NetGroupListHandler{logger: r.logger})
	r.register("bof/situational_awareness/netGroupListMembers", &NetGroupListMembersHandler{logger: r.logger})
	
	// C# handlers
	r.register("csharp/management/ThreadlessInject", &ThreadlessInjectHandler{logger: r.logger})
	r.register("csharp/management/ProcessInjection", &ProcessInjectionHandler{logger: r.logger})
	r.register("csharp/code_execution/RunCoff", &RunCoffHandler{logger: r.logger})
}

// register adds a handler for a module path
func (r *CustomGenerateRegistry) register(modulePath string, handler CustomGenerateHandler) {
	// Normalize path (remove .yaml extension, handle different formats)
	normalized := strings.TrimSuffix(modulePath, ".yaml")
	normalized = strings.TrimSuffix(normalized, ".yml")
	
	// Register with multiple keys for flexibility
	r.handlers[normalized] = handler
	r.handlers[fmt.Sprintf("modules/%s", normalized)] = handler
	r.handlers[fmt.Sprintf("empire/%s", normalized)] = handler
	
	// Also register by module name (last component)
	parts := strings.Split(normalized, "/")
	if len(parts) > 0 {
		moduleName := parts[len(parts)-1]
		r.handlers[moduleName] = handler
	}
}

