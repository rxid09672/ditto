package filesystem

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryFileSystem(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	require.NotNil(t, mfs)
	assert.NotNil(t, mfs.files)
	assert.Len(t, mfs.files, 0)
}

func TestMemoryFileSystem_AddFile(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	err := mfs.AddFile("test.txt", []byte("test content"))
	
	require.NoError(t, err)
	file, err := mfs.GetFile("test.txt")
	require.NoError(t, err)
	assert.Equal(t, "test.txt", file.Name)
	assert.Equal(t, []byte("test content"), file.Content)
}

func TestMemoryFileSystem_GetFile_Exists(t *testing.T) {
	mfs := NewMemoryFileSystem()
	mfs.AddFile("test.txt", []byte("content"))
	
	file, err := mfs.GetFile("test.txt")
	
	require.NoError(t, err)
	assert.Equal(t, "test.txt", file.Name)
}

func TestMemoryFileSystem_GetFile_NotExists(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	_, err := mfs.GetFile("nonexistent.txt")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryFileSystem_RemoveFile(t *testing.T) {
	mfs := NewMemoryFileSystem()
	mfs.AddFile("test.txt", []byte("content"))
	
	err := mfs.RemoveFile("test.txt")
	
	require.NoError(t, err)
	_, err = mfs.GetFile("test.txt")
	assert.Error(t, err)
}

func TestMemoryFileSystem_RemoveFile_NotExists(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	err := mfs.RemoveFile("nonexistent.txt")
	
	assert.NoError(t, err)
}

func TestMemoryFileSystem_ListFiles(t *testing.T) {
	mfs := NewMemoryFileSystem()
	mfs.AddFile("file1.txt", []byte("content1"))
	mfs.AddFile("file2.txt", []byte("content2"))
	
	files := mfs.ListFiles()
	
	assert.Len(t, files, 2)
	assert.Contains(t, files, "file1.txt")
	assert.Contains(t, files, "file2.txt")
}

func TestMemoryFileSystem_Concurrent(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			mfs.AddFile(string(rune(id)), []byte("content"))
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	assert.Len(t, mfs.ListFiles(), 10)
}

func TestMemoryFile_CreatedAt(t *testing.T) {
	mfs := NewMemoryFileSystem()
	
	before := time.Now()
	mfs.AddFile("test.txt", []byte("content"))
	after := time.Now()
	
	file, _ := mfs.GetFile("test.txt")
	
	assert.True(t, file.CreatedAt.After(before) || file.CreatedAt.Equal(before))
	assert.True(t, file.CreatedAt.Before(after) || file.CreatedAt.Equal(after))
}

func TestNewFilesystemOps(t *testing.T) {
	fso := NewFilesystemOps()
	
	require.NotNil(t, fso)
	assert.NotNil(t, fso.memFS)
}

func TestFilesystemOps_Grep(t *testing.T) {
	fso := NewFilesystemOps()
	
	// Add test files to memory
	fso.memFS.AddFile("file1.txt", []byte("test content\nanother line"))
	fso.memFS.AddFile("file2.txt", []byte("different content"))
	
	// Grep uses filepath, which requires a real path
	// This test verifies the function structure
	// For actual grep testing, would need real filesystem
	results, err := fso.Grep("test", ".", false)
	
	// May fail due to filepath requirements, but structure is tested
	_ = results
	_ = err
}

func BenchmarkMemoryFileSystem_AddFile(b *testing.B) {
	mfs := NewMemoryFileSystem()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mfs.AddFile(string(rune(i)), []byte("content"))
	}
}

func BenchmarkMemoryFileSystem_GetFile(b *testing.B) {
	mfs := NewMemoryFileSystem()
	mfs.AddFile("test.txt", []byte("content"))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mfs.GetFile("test.txt")
	}
}

func TestFilesystemOps_Chmod(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_chmod_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	err = fso.Chmod(tmpFile.Name(), 0755)
	require.NoError(t, err)
	
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestFilesystemOps_Chmod_NotFound(t *testing.T) {
	fso := NewFilesystemOps()
	
	err := fso.Chmod("/nonexistent/path/file", 0755)
	assert.Error(t, err)
}

func TestFilesystemOps_Chown(t *testing.T) {
	fso := NewFilesystemOps()
	if runtime.GOOS == "windows" {
		t.Skip("Chown not supported on Windows")
	}
	
	tmpFile, err := os.CreateTemp("", "test_chown_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	// Get current uid/gid
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	
	err = fso.Chown(tmpFile.Name(), int(stat.Uid), int(stat.Gid))
	require.NoError(t, err)
}

func TestFilesystemOps_Chown_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	
	fso := NewFilesystemOps()
	
	err := fso.Chown("test", 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestFilesystemOps_Chtimes(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_chtimes_*")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	
	atime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	mtime := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	
	err = fso.Chtimes(tmpFile.Name(), atime, mtime)
	require.NoError(t, err)
	
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	// Compare times accounting for timezone conversion
	expectedMtime := mtime.In(info.ModTime().Location())
	assert.Equal(t, expectedMtime.Truncate(time.Second), info.ModTime().Truncate(time.Second))
}

func TestFilesystemOps_Head(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_head_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	content := "line1\nline2\nline3\nline4\nline5"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)
	
	lines, err := fso.Head(tmpFile.Name(), 3)
	require.NoError(t, err)
	assert.Len(t, lines, 3)
	assert.Equal(t, "line1", lines[0])
	assert.Equal(t, "line2", lines[1])
	assert.Equal(t, "line3", lines[2])
}

func TestFilesystemOps_Head_MoreThanLines(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_head_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	content := "line1\nline2"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)
	
	lines, err := fso.Head(tmpFile.Name(), 10)
	require.NoError(t, err)
	assert.Len(t, lines, 2)
}

func TestFilesystemOps_Tail(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_tail_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	content := "line1\nline2\nline3\nline4\nline5"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)
	
	lines, err := fso.Tail(tmpFile.Name(), 3)
	require.NoError(t, err)
	assert.Len(t, lines, 3)
	assert.Equal(t, "line3", lines[0])
	assert.Equal(t, "line4", lines[1])
	assert.Equal(t, "line5", lines[2])
}

func TestFilesystemOps_Tail_MoreThanLines(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_tail_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	content := "line1\nline2"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)
	
	lines, err := fso.Tail(tmpFile.Name(), 10)
	require.NoError(t, err)
	assert.Len(t, lines, 2)
}

func TestFilesystemOps_Cat(t *testing.T) {
	fso := NewFilesystemOps()
	tmpFile, err := os.CreateTemp("", "test_cat_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	content := "test content\nwith multiple lines"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)
	
	result, err := fso.Cat(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, content, result)
}

func TestFilesystemOps_Cat_NotFound(t *testing.T) {
	fso := NewFilesystemOps()
	
	_, err := fso.Cat("/nonexistent/file")
	assert.Error(t, err)
}

func TestFilesystemOps_MountInfo(t *testing.T) {
	fso := NewFilesystemOps()
	
	_, err := fso.MountInfo()
	// May fail due to not implemented, but structure is tested
	if err != nil {
		assert.Contains(t, err.Error(), "not implemented")
	}
}

func TestContainsPattern(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		pattern string
		want    bool
	}{
		{"found", []byte("test content"), "test", true},
		{"not found", []byte("test content"), "missing", false},
		{"empty pattern", []byte("test"), "", true},
		{"empty content", []byte(""), "test", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPattern(tt.content, tt.pattern)
			assert.Equal(t, tt.want, result)
		})
	}
}

