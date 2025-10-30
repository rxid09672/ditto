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

func (s *Screenshot) captureWindows() (image.Image, error) {
	s.logger.Info("Capturing Windows screenshot")
	return nil, fmt.Errorf("not yet implemented")
}

