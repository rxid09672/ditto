//go:build !windows && !linux
// +build !windows,!linux

package processes

import (
	"fmt"
)

func (pm *ProcessManager) listProcessesWindows() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("Windows process listing only supported on Windows")
}

