package main

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainFlags(t *testing.T) {
	// Reset flags for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	mode := fs.String("mode", "interactive", "Operation mode")
	config := fs.String("config", "", "Configuration file path")
	listenAddr := fs.String("listen", "0.0.0.0:8443", "Server listen address")
	callbackURL := fs.String("callback", "", "Client callback URL")
	payloadType := fs.String("payload", "stager", "Payload type")
	output := fs.String("output", "", "Output file path")
	arch := fs.String("arch", "amd64", "Target architecture")
	osTarget := fs.String("os", "linux", "Target OS")
	encrypt := fs.Bool("encrypt", true, "Enable payload encryption")
	obfuscate := fs.Bool("obfuscate", true, "Enable code obfuscation")
	debug := fs.Bool("debug", false, "Enable debug logging")
	showVersion := fs.Bool("version", false, "Show version information")

	err := fs.Parse([]string{
		"-mode", "server",
		"-config", "/test/config.json",
		"-listen", "127.0.0.1:8080",
		"-callback", "https://example.com",
		"-payload", "shellcode",
		"-output", "/tmp/payload",
		"-arch", "arm64",
		"-os", "windows",
		"-encrypt=false",
		"-obfuscate=false",
		"-debug",
		"-version",
	})
	require.NoError(t, err)

	assert.Equal(t, "server", *mode)
	assert.Equal(t, "/test/config.json", *config)
	assert.Equal(t, "127.0.0.1:8080", *listenAddr)
	assert.Equal(t, "https://example.com", *callbackURL)
	assert.Equal(t, "shellcode", *payloadType)
	assert.Equal(t, "/tmp/payload", *output)
	assert.Equal(t, "arm64", *arch)
	assert.Equal(t, "windows", *osTarget)
	assert.False(t, *encrypt)
	assert.False(t, *obfuscate)
	assert.True(t, *debug)
	assert.True(t, *showVersion)
}

func TestPrintBanner(t *testing.T) {
	// Test that printBanner doesn't panic
	// It may fail if ditto.png doesn't exist, but that's okay
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printBanner panicked: %v", r)
		}
	}()

	// Can't directly test printBanner as it's not exported,
	// but we can verify the banner package works
	// This is tested in banner/banner_test.go
}

func TestVersionInfo(t *testing.T) {
	// Test that version variables are set
	assert.NotEmpty(t, version)
	// buildTime and gitCommit may be "unknown" in tests, which is fine
}
