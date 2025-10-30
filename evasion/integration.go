// +build windows

package evasion

import (
	"github.com/ditto/ditto/injection"
)

// NewProcessInjectionWithEvasion creates a process injection handler with direct syscalls enabled
// This is a convenience function that wires everything together
func NewProcessInjectionWithEvasion(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) (*injection.ProcessInjection, *DirectSyscall, error) {
	// Create direct syscall handler
	ds := NewDirectSyscall(logger)
	
	// Create injection handler
	pi := injection.NewProcessInjection(logger)
	
	// Wire them together
	pi.SetDirectSyscall(ds)
	
	return pi, ds, nil
}

