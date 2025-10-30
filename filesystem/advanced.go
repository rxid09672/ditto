package filesystem

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// MemoryFile represents a file stored in memory
type MemoryFile struct {
	Name        string
	Content     []byte
	CreatedAt   time.Time
	ModifiedAt  time.Time
	Permissions os.FileMode
}

// MemoryFileSystem manages in-memory files
type MemoryFileSystem struct {
	files map[string]*MemoryFile
	mu    sync.RWMutex
}

// NewMemoryFileSystem creates a new memory file system
func NewMemoryFileSystem() *MemoryFileSystem {
	return &MemoryFileSystem{
		files: make(map[string]*MemoryFile),
	}
}

// AddFile adds a file to memory
func (mfs *MemoryFileSystem) AddFile(name string, content []byte) error {
	mfs.mu.Lock()
	defer mfs.mu.Unlock()
	
	mfs.files[name] = &MemoryFile{
		Name:        name,
		Content:     content,
		CreatedAt:   time.Now(),
		ModifiedAt:  time.Now(),
		Permissions: 0644,
	}
	
	return nil
}

// GetFile retrieves a file from memory
func (mfs *MemoryFileSystem) GetFile(name string) (*MemoryFile, error) {
	mfs.mu.RLock()
	defer mfs.mu.RUnlock()
	
	file, ok := mfs.files[name]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", name)
	}
	
	return file, nil
}

// RemoveFile removes a file from memory
func (mfs *MemoryFileSystem) RemoveFile(name string) error {
	mfs.mu.Lock()
	defer mfs.mu.Unlock()
	
	delete(mfs.files, name)
	return nil
}

// ListFiles lists all files in memory
func (mfs *MemoryFileSystem) ListFiles() []string {
	mfs.mu.RLock()
	defer mfs.mu.RUnlock()
	
	names := make([]string, 0, len(mfs.files))
	for name := range mfs.files {
		names = append(names, name)
	}
	return names
}

// FilesystemOps provides advanced filesystem operations
type FilesystemOps struct {
	memFS *MemoryFileSystem
}

// NewFilesystemOps creates new filesystem operations
func NewFilesystemOps() *FilesystemOps {
	return &FilesystemOps{
		memFS: NewMemoryFileSystem(),
	}
}

// Grep searches for patterns in files
func (fso *FilesystemOps) Grep(pattern string, path string, recursive bool) ([]string, error) {
	results := []string{}
	
	var walkFn filepath.WalkFunc
	walkFn = func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() && !recursive {
			return filepath.SkipDir
		}
		
		if !info.IsDir() {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			
			// Simple pattern matching
			if containsPattern(content, pattern) {
				results = append(results, path)
			}
		}
		
		return nil
	}
	
	err := filepath.Walk(path, walkFn)
	return results, err
}

func containsPattern(content []byte, pattern string) bool {
	return bytes.Contains(content, []byte(pattern))
}

// Chmod changes file permissions
func (fso *FilesystemOps) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// Chown changes file ownership
func (fso *FilesystemOps) Chown(path string, uid, gid int) error {
	switch runtime.GOOS {
	case "linux", "darwin":
		return os.Chown(path, uid, gid)
	default:
		return fmt.Errorf("Chown not supported on %s", runtime.GOOS)
	}
}

// Chtimes changes file timestamps
func (fso *FilesystemOps) Chtimes(path string, atime, mtime time.Time) error {
	return os.Chtimes(path, atime, mtime)
}

// Head returns first N lines of a file
func (fso *FilesystemOps) Head(path string, lines int) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	fileLines := strings.Split(string(content), "\n")
	if lines > len(fileLines) {
		lines = len(fileLines)
	}
	
	return fileLines[:lines], nil
}

// Tail returns last N lines of a file
func (fso *FilesystemOps) Tail(path string, lines int) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	fileLines := strings.Split(string(content), "\n")
	if lines > len(fileLines) {
		lines = len(fileLines)
	}
	
	return fileLines[len(fileLines)-lines:], nil
}

// Cat returns file contents
func (fso *FilesystemOps) Cat(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// MountInfo provides mount information
func (fso *FilesystemOps) MountInfo() ([]MountInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return fso.mountInfoLinux()
	case "darwin":
		return fso.mountInfoDarwin()
	case "windows":
		return fso.mountInfoWindows()
	default:
		return nil, fmt.Errorf("unsupported OS")
	}
}

type MountInfo struct {
	Device     string
	MountPoint string
	FSType     string
	Options    string
}

func (fso *FilesystemOps) mountInfoLinux() ([]MountInfo, error) {
	// Parse /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/mounts: %w", err)
	}
	
	mounts := []MountInfo{}
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			mount := MountInfo{
				Device:     fields[0],
				MountPoint: fields[1],
				FSType:     fields[2],
			}
			if len(fields) >= 4 {
				mount.Options = fields[3]
			}
			mounts = append(mounts, mount)
		}
	}
	
	return mounts, nil
}

func (fso *FilesystemOps) mountInfoDarwin() ([]MountInfo, error) {
	// Parse mount output
	cmd := exec.Command("mount")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run mount: %w", err)
	}
	
	mounts := []MountInfo{}
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse mount output format: "device on mountpoint (type, options)"
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			mount := MountInfo{
				Device:     parts[0],
				MountPoint: parts[2],
			}
			
			// Extract filesystem type and options from parentheses
			for i, part := range parts {
				if strings.HasPrefix(part, "(") {
					optionStr := strings.Join(parts[i:], " ")
					optionStr = strings.Trim(optionStr, "()")
					optionParts := strings.Split(optionStr, ",")
					if len(optionParts) > 0 {
						mount.FSType = strings.TrimSpace(optionParts[0])
					}
					if len(optionParts) > 1 {
						mount.Options = strings.TrimSpace(strings.Join(optionParts[1:], ","))
					}
					break
				}
			}
			
			mounts = append(mounts, mount)
		}
	}
	
	return mounts, nil
}

func (fso *FilesystemOps) mountInfoWindows() ([]MountInfo, error) {
	// Use wmic or PowerShell to get mount info
	cmd := exec.Command("wmic", "logicaldisk", "get", "deviceid,volumename,filesystem,size", "/format:list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run wmic: %w", err)
	}
	
	mounts := []MountInfo{}
	lines := strings.Split(string(output), "\n")
	currentMount := MountInfo{}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if currentMount.Device != "" {
				mounts = append(mounts, currentMount)
				currentMount = MountInfo{}
			}
			continue
		}
		
		if strings.HasPrefix(line, "DeviceID=") {
			currentMount.Device = strings.TrimPrefix(line, "DeviceID=")
		} else if strings.HasPrefix(line, "VolumeName=") {
			currentMount.MountPoint = strings.TrimPrefix(line, "VolumeName=")
		} else if strings.HasPrefix(line, "FileSystem=") {
			currentMount.FSType = strings.TrimPrefix(line, "FileSystem=")
		}
	}
	
	if currentMount.Device != "" {
		mounts = append(mounts, currentMount)
	}
	
	return mounts, nil
}

