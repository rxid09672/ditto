# Empire Framework Module Analysis & Porting Plan

## Executive Summary

Empire framework contains **433 YAML module definitions** across multiple languages and categories. This document provides a comprehensive analysis and implementation plan for porting all Empire modules into the Ditto.

---

## Module Statistics

- **Total Modules**: 433 YAML files
- **Languages**: PowerShell, Python, C#, BOF (Beacon Object Files)
- **Categories**: 12+ major categories with subcategories

---

## Module Categories Breakdown

### 1. **Code Execution** (Execution/Scripting)
- PowerShell: 13 modules
- Python: 3 modules  
- C#: 5 modules
- **Total**: ~21 modules

**Examples**:
- `invoke_shellcode` - Shellcode execution
- `invoke_script` - Generic script execution
- `invoke_dllinjection` - DLL injection
- `invoke_reflectivepeinjection` - Reflective PE injection
- `Assembly` - .NET assembly execution
- `RunCoff` - COFF/BOF execution

### 2. **Collection** (Data Collection)
- PowerShell: 30+ modules
- Python: 30+ modules (Windows, Linux, OSX)
- C#: 3 modules
- **Total**: ~63 modules

**Subcategories**:
- Host collection (files, registry, memory)
- Network collection (credentials, tokens)
- Browser dumps
- Keyloggers
- Screenshots
- Email collection
- Vault credential extraction

**Examples**:
- `mimipenguin` - Linux credential extraction
- `keychaindump` - macOS keychain extraction
- `browser_dump` - Browser credential extraction
- `hashdump` - Password hash extraction
- `screenshot` - Screen capture
- `keylogger` - Keystroke logging

### 3. **Credentials** (Credential Access)
- PowerShell: 40+ modules
- C#: 6 modules
- **Total**: ~46 modules

**Notable Tools**:
- **Mimikatz** (24 modules): Full Mimikatz integration
  - DCSync
  - LSASS dumping
  - Token manipulation
  - Golden ticket attacks
  - Pass-the-hash
- **SharpSploit Credentials** (5 modules)
- Kerberoasting
- Password spraying
- Credential injection

**Examples**:
- `dcsync` - Domain password sync
- `sekurlsa::logonpasswords` - LSASS credential extraction
- `invoke_kerberoast` - Kerberos ticket extraction
- `DomainPasswordSpray` - Password spraying
- `credential_injection` - Credential injection

### 4. **Lateral Movement** (Movement)
- PowerShell: 25 modules
- Python: 3 modules
- **Total**: ~28 modules

**Techniques**:
- WMI execution
- DCOM execution
- PowerShell remoting
- SSH command execution
- SMB execution
- WinRM execution
- GPO immediate tasks
- Scheduled tasks

**Examples**:
- `invoke_wmi` - WMI lateral movement
- `invoke_dcom` - DCOM lateral movement
- `invoke_psexec` - PsExec-like execution
- `ssh_command` - SSH command execution
- `new_gpo_immediate_task` - GPO-based movement

### 5. **Persistence** (Persistence)
- PowerShell: 32+ modules
- Python: 14 modules
- C#: 4 modules
- **Total**: ~50 modules

**Subcategories**:
- **Elevated Persistence**:
  - WMI event subscriptions
  - Scheduled tasks (elevated)
  - Registry (elevated)
  - Service installation
- **Userland Persistence**:
  - Startup folder
  - Registry (user)
  - Scheduled tasks (user)
  - LNK backdoors
- **PowerBreach** modules:
  - Event log persistence
  - Dead user persistence
  - Resolver persistence

**Examples**:
- `schtasks` - Scheduled task persistence
- `registry` - Registry persistence
- `wmi` - WMI event subscription
- `backdoor_lnk` - LNK file backdoor
- `LaunchAgent` - macOS launch agent

### 6. **Privilege Escalation** (PrivEsc)
- PowerShell: 44 modules
- Python: 15 modules
- C#: 3 modules
- **Total**: ~62 modules

**Techniques**:
- UAC bypasses (multiple methods)
- Token manipulation
- Service abuse
- DLL hijacking
- Exploit modules (MS16-032, MS16-135, CVE-2021-4034, etc.)
- Sudo abuse
- PowerUp modules

**UAC Bypass Methods**:
- `bypassuac_eventvwr` - Event Viewer
- `bypassuac_fodhelper` - FOD Helper
- `bypassuac_sdctlbypass` - SDCTL bypass
- `bypassuac_tokenmanipulation` - Token manipulation
- `bypassuac_wscript` - WScript
- `bypassuac_env` - Environment variable

**Examples**:
- `ask` - Admin prompt
- `powerup` modules - Service abuse
- `write_dllhijacker` - DLL hijacking
- `CVE-2021-4034` - Pkexec exploit
- `dyld_print_to_file` - macOS privilege escalation

### 7. **Situational Awareness** (Discovery/Recon)
- PowerShell: 64+ modules
- Python: 29 modules
- C#: 15 modules
- BOF: 40+ modules
- **Total**: ~148 modules

**Subcategories**:
- **Host Discovery**:
  - System information
  - Process enumeration
  - Service enumeration
  - File system enumeration
  - Registry enumeration
- **Network Discovery**:
  - Active Directory enumeration
  - Network scanning
  - Share enumeration
  - WMI queries
  - DNS enumeration
- **PowerView Integration** (37 modules):
  - AD object enumeration
  - GPO enumeration
  - User/group enumeration
  - Computer enumeration
  - Trust enumeration

**Notable Tools**:
- **Seatbelt** (C#) - System enumeration
- **SharpSC** (C#) - Service enumeration
- **SharpWMI** (C#) - WMI enumeration
- **PowerView** (PowerShell) - AD enumeration

**Examples**:
- `computerdetails` - Comprehensive system info
- `get_domaincontroller` - DC enumeration
- `get_users` - User enumeration
- `get_groups` - Group enumeration
- `get_gpo` - GPO enumeration
- `port_scan` - Network scanning

### 8. **Management** (Execution/Management)
- PowerShell: 48 modules
- Python: 7 modules
- C#: 8 modules
- **Total**: ~63 modules

**Functionality**:
- Process management
- Process injection
- Shellcode injection
- Token manipulation
- User impersonation
- Listener switching
- Obfuscation bypass
- MailRaider integration

**Examples**:
- `spawn` - Spawn new process
- `spawnas` - Spawn as user
- `shinject` - Shellcode injection
- `psinject` - PowerShell injection
- `reflective_inject` - Reflective injection
- `runas` - Run as user
- `logoff` - User logoff

### 9. **Recon** (Reconnaissance)
- PowerShell: 7 modules
- **Total**: ~7 modules

**Examples**:
- `find_fruit` - Service enumeration
- `get_sql_server_info` - SQL server discovery
- `fetch_brute_local` - Local brute force
- `get_sql_server_login_default_pw` - Default password checks

### 10. **Exfiltration** (Exfiltration)
- PowerShell: 5 modules
- **Total**: ~5 modules

**Examples**:
- Data exfiltration methods
- File transfer
- Email exfiltration

### 11. **Exploitation** (Exploitation)
- PowerShell: 5 modules
- Python: 2 modules
- **Total**: ~7 modules

**Examples**:
- Exploit modules
- Web exploitation

### 12. **Trollsploit** (Harassment)
- PowerShell: 10 modules
- Python: 4 modules
- **Total**: ~14 modules

**Examples**:
- Prank/harassment modules
- OSX-specific trollsploits

### 13. **BOF Modules** (Beacon Object Files)
- **Total**: ~40+ modules

**Categories**:
- Injection BOFs
- Situational awareness BOFs

**Examples**:
- `nanodump` - LSASS dumping
- `secinject` - Secure injection
- `clipboard_window_inject` - Clipboard injection
- AD enumeration BOFs
- Network enumeration BOFs

---

## Module Language Support

### PowerShell Modules
- **Count**: ~250+ modules
- **Features**:
  - Template substitution (`{{ PARAMS }}`)
  - Obfuscation support (Invoke-Obfuscation)
  - Script path referencing
  - Advanced option formatting

### Python Modules
- **Count**: ~70+ modules
- **Platforms**: Windows, Linux, macOS
- **Features**:
  - Cross-platform support
  - Background job support
  - Template substitution

### C# Modules
- **Count**: ~40+ modules
- **Features**:
  - In-memory compilation (Roslyn)
  - .NET Framework version support
  - SharpSploit integration
  - Reference assemblies
  - Embedded resources

### BOF Modules
- **Count**: ~40+ modules
- **Features**:
  - Beacon Object File format
  - x86/x64 support
  - Entry point specification

---

## Implementation Requirements

### 1. Module Registry System
- YAML parsing and validation
- Module metadata storage
- Module categorization
- Search and filtering

### 2. Module Execution Engine
- PowerShell execution (via PowerShell/.NET)
- Python execution (embedded interpreter)
- C# compilation and execution (Roslyn compiler)
- BOF loading and execution

### 3. Template System
- Parameter substitution (`{{ PARAMS }}`)
- Option formatting
- Dynamic option dependencies
- Script path resolution

### 4. Module Categories
- Code execution
- Collection
- Credentials
- Lateral movement
- Persistence
- Privilege escalation
- Situational awareness
- Management
- Recon
- Exfiltration
- Exploitation
- Trollsploit
- BOF

### 5. Integration Points
- Session management
- Task queue
- Result handling
- Background jobs
- File upload/download

---

## Porting Strategy

### Phase 1: Core Module System
1. YAML parser and validator
2. Module registry
3. Module metadata models
4. Template engine

### Phase 2: Language Support
1. PowerShell execution engine
2. Python execution engine
3. C# compilation engine
4. BOF loader

### Phase 3: Module Categories
1. Port all PowerShell modules
2. Port all Python modules
3. Port all C# modules
4. Port all BOF modules

### Phase 4: Advanced Features
1. Obfuscation integration
2. Advanced option handling
3. Custom module generation
4. Module dependencies

---

## Estimated Module Count by Category

| Category | Estimated Count |
|----------|----------------|
| Code Execution | 21 |
| Collection | 63 |
| Credentials | 46 |
| Lateral Movement | 28 |
| Persistence | 50 |
| Privilege Escalation | 62 |
| Situational Awareness | 148 |
| Management | 63 |
| Recon | 7 |
| Exfiltration | 5 |
| Exploitation | 7 |
| Trollsploit | 14 |
| BOF | 40+ |
| **TOTAL** | **433+** |

---

## Next Steps

1. Create module system architecture
2. Implement YAML parser
3. Implement language execution engines
4. Port modules systematically by category
5. Test and validate each module category

