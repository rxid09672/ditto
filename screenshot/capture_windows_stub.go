// +build !windows

package screenshot

import (
	"fmt"
	"image"
)

func (s *Screenshot) captureWindows() (image.Image, error) {
	return nil, fmt.Errorf("screenshot capture only supported on Windows")
}

