// +build linux

package processes

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func (pm *ProcessManager) killProcess(pid int) error {
	pm.logger.Info("Killing process: %d", pid)
	
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}
	
	return proc.Kill()
}

func (pm *ProcessManager) listProcessesWindows() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("Windows process listing only supported on Windows")
}

func (pm *ProcessManager) listProcessesLinux() ([]ProcessInfo, error) {
	procDir := "/proc"
	d, err := os.Open(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	defer d.Close()
	
	processes := make([]ProcessInfo, 0, 50)
	
	for {
		entries, err := d.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			
			name := entry.Name()
			if name[0] < '0' || name[0] > '9' {
				continue
			}
			
			pid, err := strconv.Atoi(name)
			if err != nil {
				continue
			}
			
			procInfo := ProcessInfo{
				PID: pid,
			}
			
			// Read /proc/[pid]/stat for PPID
			if statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
				fields := strings.Fields(string(statData))
				if len(fields) > 3 {
					if ppid, err := strconv.Atoi(fields[3]); err == nil {
						procInfo.PPID = ppid
					}
				}
				if len(fields) > 1 {
					procInfo.Name = strings.Trim(fields[1], "()")
				}
			}
			
			// Read /proc/[pid]/cmdline for path
			if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				args := strings.Split(string(cmdline), "\x00")
				if len(args) > 0 && args[0] != "" {
					procInfo.Path = args[0]
					if procInfo.Name == "" {
						procInfo.Name = filepath.Base(args[0])
					}
				}
			}
			
			// Get process owner
			if stat, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
				if statSys, ok := stat.Sys().(*syscall.Stat_t); ok {
					if u, err := user.LookupId(fmt.Sprintf("%d", statSys.Uid)); err == nil {
						procInfo.Owner = u.Username
					} else {
						procInfo.Owner = fmt.Sprintf("%d", statSys.Uid)
					}
				}
			}
			
			// Get architecture from /proc/[pid]/exe
			if _, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
				// Try to determine arch from file
				procInfo.Arch = "unknown"
				// Could use file command or read ELF header
			}
			
			processes = append(processes, procInfo)
		}
	}
	
	return processes, nil
}

