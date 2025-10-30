// +build !linux

package injection

import (
	"fmt"
)

func (pi *ProcessInjection) injectLinux(pid int, shellcode []byte, method string) error {
	return fmt.Errorf("Linux injection only supported on Linux")
}

