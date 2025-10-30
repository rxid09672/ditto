package screenshot

import (
	"fmt"
	"image"
	"runtime"
)

// Screenshot captures screenshots
type Screenshot struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewScreenshot creates a new screenshot handler
func NewScreenshot(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *Screenshot {
	return &Screenshot{logger: logger}
}

// Capture captures a screenshot
func (s *Screenshot) Capture() (image.Image, error) {
	switch runtime.GOOS {
	case "windows":
		return s.captureWindows()
	default:
		return nil, fmt.Errorf("screenshot not supported on %s", runtime.GOOS)
	}
}

// Platform-specific implementations are in capture_windows.go
// This stub will be overridden by build tags

