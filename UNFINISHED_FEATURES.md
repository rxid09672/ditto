# Unfinished Features and Placeholders

## CRITICAL ISSUES - Core Functionality

### 1. **Module Embedding NOT Implemented** ❌
- **Location**: `payload/generator.go` line 625
- **Issue**: `Modules []string` field exists in `Options` and `TemplateData`, but modules are **NEVER embedded** into generated code
- **Impact**: The `--modules` flag accepts module IDs but they're not compiled into implants
- **Status**: Modules only stored in database metadata, zero code generation

### 2. **Evasion Functions are Placeholders** ⚠️
- **Location**: `payload/generator.go` lines 565-583
- **Issues**:
  - `checkDebugger()` - Returns `false` with comment "Debugger detection would go here"
  - `checkVM()` - Returns `false` with comment "VM detection would go here"  
  - `sleepMask()` - Just calls regular `time.Sleep()`, not actual sleep masking evasion
  - `checkSandbox()` - Only checks CPU count (minimal implementation)
- **Impact**: Evasion flags compile but don't provide real protection

### 3. **Command Processing Not Implemented** ❌
- **Location**: `payload/generator.go` lines 604-607, 472-474
- **Issues**:
  - Beacon: "In a real implementation, this would process commands"
  - Stager: "In a real implementation, this would download and execute second stage"
- **Impact**: Generated implants can't execute commands or stage properly

### 4. **Listener Creation Doesn't Start Servers** ❌
- **Location**: `interactive_server.go` lines 205-229
- **Issue**: `handleListen()` creates a job entry but **doesn't start actual HTTP/HTTPS/mTLS listeners**
- **Impact**: `listen http 0.0.0.0:8080` creates database entry but no network listener

### 5. **Session Interaction Not Implemented** ❌
- **Location**: `interactive_server.go` line 539
- **Issue**: `handleUse()` displays "Session interaction coming soon..."
- **Impact**: Can't execute commands on sessions, no interactive shell

## MODERATE ISSUES - Feature Completeness

### 6. **Script Path Loading**
- **Location**: `modules/registry.go` line 343
- **Issue**: "script_path loading not yet implemented"
- **Impact**: Can't load modules from external files, only inline script

### 7. **Obfuscation Not Implemented**
- **Location**: `modules/source_loader.go` lines 77, 87
- **Issue**: "Obfuscation requested but not yet implemented" (appears twice)
- **Impact**: No PowerShell/Python obfuscation support

## LOW PRIORITY - Platform-Specific Features

### 8. **Linux/macOS Injection**
- **Location**: `injection/process.go` lines 362, 367
- **Issue**: "Linux injection not yet implemented", "macOS injection not yet implemented"

### 9. **Windows Registry Operations**
- **Location**: `registry/registry.go` lines 53, 58, 63
- **Issue**: Multiple "not yet implemented" errors

### 10. **Screenshot Capture**
- **Location**: `screenshot/capture.go` line 39
- **Issue**: "not yet implemented"

### 11. **Other Platform Features**
- Various reconnaissance, process management, filesystem features return "not yet implemented"

## Summary

**CRITICAL**: 5 major unimplemented features  
**MODERATE**: 2 feature gaps  
**LOW**: Multiple platform-specific features

The framework has the infrastructure (database, CLI, module registry) but core execution logic is missing.
