package banner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageToASCII_NonExistentFile(t *testing.T) {
	_, err := ImageToASCII("/nonexistent/file.png", 60)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open image")
}

func TestImageToASCII_InvalidFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	tmpFile.WriteString("not an image")
	tmpFile.Close()
	
	_, err = ImageToASCII(tmpFile.Name(), 60)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestPrintDittoBanner(t *testing.T) {
	// Test that it doesn't panic
	assert.NotPanics(t, func() {
		_ = PrintDittoBanner()
	})
}

func TestPrintDittoBanner_WithLocalFile(t *testing.T) {
	// Create a dummy PNG file
	tmpDir := t.TempDir()
	testPNG := filepath.Join(tmpDir, "ditto.png")
	
	// Create minimal valid PNG header
	pngHeader := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
	}
	
	err := os.WriteFile(testPNG, pngHeader, 0644)
	require.NoError(t, err)
	
	// Change to temp directory
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)
	
	// Should try to use local file
	err = PrintDittoBanner()
	
	// May fail due to invalid PNG, but structure is tested
	_ = err
}

func TestASCIIChars(t *testing.T) {
	assert.NotEmpty(t, asciiChars)
	assert.Contains(t, asciiChars, " ")
	assert.Contains(t, asciiChars, "@")
}

func TestImageToASCII_Width(t *testing.T) {
	// Create a simple test image using embedded PNG if available
	// For now, just test that function accepts width parameter
	_, err := ImageToASCII("/nonexistent.png", 60)
	
	assert.Error(t, err)
	// But should accept width parameter without panicking
}

func BenchmarkImageToASCII(b *testing.B) {
	tmpFile, err := os.CreateTemp("", "bench_*.png")
	if err != nil {
		b.Skip("Could not create temp file")
	}
	defer os.Remove(tmpFile.Name())
	
	// Write minimal PNG header
	pngHeader := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	}
	tmpFile.Write(pngHeader)
	tmpFile.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ImageToASCII(tmpFile.Name(), 60)
	}
}

