// +build !darwin

package injection

import (
	"fmt"
)

func (pi *ProcessInjection) injectDarwin(pid int, shellcode []byte, method string) error {
	return fmt.Errorf("macOS injection only supported on macOS")
}

