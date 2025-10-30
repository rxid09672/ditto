package payload

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ditto/ditto/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, args ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, args ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, args ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestGenerateWindowsExecutable_Compiles(t *testing.T) {
	// Skip if Go is not available
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("Go compiler not found in PATH")
	}

	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	opts := Options{
		Type:        "full",
		Arch:        "amd64",
		OS:          "windows",
		Encrypt:     false,
		Obfuscate:   false,
		Config:      cfg,
		CallbackURL: "http://localhost:8443",
		Delay:       30,
		Jitter:      0.0,
	}

	// Generate the executable
	data, err := gen.Generate(opts)
	require.NoError(t, err, "Generation should succeed")
	require.NotEmpty(t, data, "Generated data should not be empty")
	assert.Greater(t, len(data), 100000, "Windows executable should be at least 100KB")

	// Verify it's a PE executable
	if len(data) >= 64 {
		// Check DOS header signature (MZ)
		assert.Equal(t, []byte{0x4D, 0x5A}, data[0:2], "Should start with MZ header")
		
		// Check PE signature offset (stored at offset 0x3C)
		peOffset := uint32(data[0x3C]) | uint32(data[0x3D])<<8 | uint32(data[0x3E])<<16 | uint32(data[0x3F])<<24
		if int(peOffset) < len(data)-4 {
			// Check PE signature (PE\0\0)
			assert.Equal(t, []byte{0x50, 0x45, 0x00, 0x00}, data[peOffset:peOffset+4], "Should contain PE signature")
		}
	}
}

func TestGenerateWindowsExecutable_Stager(t *testing.T) {
	// Skip if Go is not available
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("Go compiler not found in PATH")
	}

	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	opts := Options{
		Type:      "stager",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}

	// Generate the executable
	data, err := gen.Generate(opts)
	require.NoError(t, err, "Stager generation should succeed")
	require.NotEmpty(t, data, "Generated stager should not be empty")
	assert.Greater(t, len(data), 100000, "Windows stager executable should be at least 100KB")

	// Verify PE header
	if len(data) >= 64 {
		assert.Equal(t, []byte{0x4D, 0x5A}, data[0:2], "Should start with MZ header")
	}
}

func TestGenerateWindowsSource_NoUnusedImports(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	// Test full payload source
	opts := Options{
		Type:      "full",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   false,
		Obfuscate: false,
		Config:    cfg,
	}

	source, err := gen.generateWindowsSource(opts)
	require.NoError(t, err)
	require.NotEmpty(t, source)

	// Validate source code compiles
	err = validateGoSourceCompiles(source, "windows", "amd64")
	assert.NoError(t, err, "Generated source should compile without unused import errors")

	// Test stager source
	opts.Type = "stager"
	source, err = gen.generateWindowsSource(opts)
	require.NoError(t, err)
	require.NotEmpty(t, source)

	err = validateGoSourceCompiles(source, "windows", "amd64")
	assert.NoError(t, err, "Generated stager source should compile without unused import errors")
}

func TestGenerateWindowsSource_Architectures(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	architectures := []string{"amd64", "386"}
	
	for _, arch := range architectures {
		t.Run("arch_"+arch, func(t *testing.T) {
			opts := Options{
				Type:      "full",
				Arch:      arch,
				OS:        "windows",
				Encrypt:   false,
				Obfuscate: false,
				Config:    cfg,
			}

			// Generate executable
			data, err := gen.Generate(opts)
			require.NoError(t, err, "Generation should succeed for %s", arch)
			require.NotEmpty(t, data, "Generated data should not be empty for %s", arch)

			// Verify PE header
			if len(data) >= 64 {
				assert.Equal(t, []byte{0x4D, 0x5A}, data[0:2], "Should start with MZ header")
			}
		})
	}
}

// validateGoSourceCompiles validates that Go source code compiles without errors
func validateGoSourceCompiles(source []byte, goos, goarch string) error {
	// Skip if Go is not available
	if _, err := exec.LookPath("go"); err != nil {
		// Can't validate without Go compiler
		return nil
	}

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "ditto_test_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Write main.go
	mainGoPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainGoPath, source, 0644); err != nil {
		return err
	}

	// Write go.mod
	goModContent := `module ditto-implant-test

go 1.21
`
	goModPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		return err
	}

	// Build command
	cmd := exec.Command("go", "build", "-o", filepath.Join(tmpDir, "test.exe"), ".")
	cmd.Dir = tmpDir

	// Set cross-compilation environment
	env := os.Environ()
	env = append(env, "GOOS="+goos)
	env = append(env, "GOARCH="+goarch)
	env = append(env, "CGO_ENABLED=0")
	cmd.Env = env

	// Capture output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run build
	if err := cmd.Run(); err != nil {
		return &CompilationError{
			Err:    err,
			Stderr: stderr.String(),
			Source: string(source),
		}
	}

	return nil
}

// CompilationError represents a Go compilation error
type CompilationError struct {
	Err    error
	Stderr string
	Source string
}

func (e *CompilationError) Error() string {
	return "Go compilation failed: " + e.Err.Error() + "\n" + e.Stderr
}

func TestGenerateWindowsSource_ValidSyntax(t *testing.T) {
	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	testCases := []struct {
		name     string
		payloadType string
		arch     string
	}{
		{"full_amd64", "full", "amd64"},
		{"full_386", "full", "386"},
		{"stager_amd64", "stager", "amd64"},
		{"stager_386", "stager", "386"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				Type:      tc.payloadType,
				Arch:      tc.arch,
				OS:        "windows",
				Encrypt:   false,
				Obfuscate: false,
				Config:    cfg,
			}

			source, err := gen.generateWindowsSource(opts)
			require.NoError(t, err)
			require.NotEmpty(t, source)

			// Check for common issues
			sourceStr := string(source)
			
			// Must have package declaration
			assert.Contains(t, sourceStr, "package main")
			
			// Must have main function
			assert.Contains(t, sourceStr, "func main()")
			
			// Check that imports are properly closed
			importCount := strings.Count(sourceStr, "import (")
			if importCount > 0 {
				closeCount := strings.Count(sourceStr, ")")
				assert.Greater(t, closeCount, importCount, "Imports should be properly closed")
			}

			// Validate compilation
			if _, err := exec.LookPath("go"); err == nil {
				err := validateGoSourceCompiles(source, "windows", tc.arch)
				assert.NoError(t, err, "Generated source should compile for %s/%s", "windows", tc.arch)
			}
		})
	}
}

func TestGenerateWindowsExecutable_WithEncryption(t *testing.T) {
	// Skip if Go is not available
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("Go compiler not found in PATH")
	}

	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	opts := Options{
		Type:      "full",
		Arch:      "amd64",
		OS:        "windows",
		Encrypt:   true,
		Obfuscate: false,
		Config:    cfg,
	}

	// Should still generate a valid PE executable (encryption happens after compilation)
	data, err := gen.Generate(opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	
	// When encrypted, the PE header might be modified, so we just check it's not empty
	assert.Greater(t, len(data), 1000, "Encrypted payload should still be substantial")
}

// Test that generated code doesn't have unused imports
func TestGenerateWindowsSource_NoUnusedImports_AllTypes(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("Go compiler not found in PATH")
	}

	logger := &mockLogger{}
	gen := NewGenerator(logger)

	cfg := core.DefaultConfig()
	cfg.Communication.Protocol = "http://localhost:8443"

	types := []string{"full", "stager"}
	archs := []string{"amd64", "386"}

	for _, payloadType := range types {
		for _, arch := range archs {
			t.Run(payloadType+"_"+arch, func(t *testing.T) {
				opts := Options{
					Type:      payloadType,
					Arch:      arch,
					OS:        "windows",
					Encrypt:   false,
					Obfuscate: false,
					Config:    cfg,
				}

				// Generate source
				source, err := gen.generateWindowsSource(opts)
				require.NoError(t, err)

				// Validate compilation
				err = validateGoSourceCompiles(source, "windows", arch)
				if err != nil {
					// Check if it's an unused import error
					if strings.Contains(err.Error(), "imported and not used") {
						t.Errorf("Generated source has unused imports for %s/%s:\n%s", payloadType, arch, err.Error())
					} else {
						t.Errorf("Generated source compilation failed for %s/%s: %v", payloadType, arch, err)
					}
				}
			})
		}
	}
}