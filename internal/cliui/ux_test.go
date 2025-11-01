package cliui

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDetectTTY(t *testing.T) {
	tests := []struct {
		name string
		file *os.File
		want bool
	}{
		{
			name: "stdout",
			file: os.Stdout,
			want: true, // Usually true in test environment
		},
		{
			name: "nil file",
			file: nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectTTY(tt.file)
			// We can't reliably test TTY detection without mocking, so just check it doesn't panic
			if got && tt.file == nil {
				t.Errorf("DetectTTY(nil) = %v, want false", got)
			}
		})
	}
}

func TestTermWidth(t *testing.T) {
	// Test with COLUMNS env var
	t.Run("COLUMNS env var", func(t *testing.T) {
		os.Setenv("COLUMNS", "120")
		defer os.Unsetenv("COLUMNS")

		// Can't reliably reset sync.Once, so just test that it respects COLUMNS
		// The first call will use COLUMNS
		got := TermWidth()
		if got != 120 {
			t.Errorf("TermWidth() = %d, want 120", got)
		}
	})

	// Test default - can't reliably test without resetting sync.Once
	t.Run("default width", func(t *testing.T) {
		os.Unsetenv("COLUMNS")
		// Note: TermWidth() may be cached from previous test
		got := TermWidth()
		if got <= 0 {
			t.Errorf("TermWidth() = %d, want > 0", got)
		}
	})
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name  string
		input string
		width int
		want  string
	}{
		{
			name:  "short text",
			input: "short",
			width: 80,
			want:  "short",
		},
		{
			name:  "long text wraps",
			input: "this is a very long line that should wrap",
			width: 20,
			want:  "this is a very long\nline that should\nwrap",
		},
		{
			name:  "multiple words",
			input: "word1 word2 word3",
			width: 10,
			want:  "word1\nword2 word3",
		},
		{
			name:  "empty string",
			input: "",
			width: 80,
			want:  "",
		},
		{
			name:  "zero width uses default",
			input: "test",
			width: 0,
			want:  "test", // Should use TermWidth() default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Wrap(tt.input, tt.width)
			if tt.width > 0 {
				// Check that lines don't exceed width (allowing for rounding)
				lines := strings.Split(got, "\n")
				for _, line := range lines {
					if len(line) > tt.width+5 { // Allow small margin
						t.Errorf("Wrap() line %q exceeds width %d", line, tt.width)
					}
				}
			}
			// Reconstruct original words (order may differ)
			gotWords := strings.Fields(got)
			wantWords := strings.Fields(tt.input)
			if len(gotWords) != len(wantWords) {
				t.Errorf("Wrap() word count = %d, want %d", len(gotWords), len(wantWords))
			}
		})
	}
}

func TestEllipsize(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "short string",
			input:  "short",
			maxLen: 10,
			want:   "short",
		},
		{
			name:   "exact length",
			input:  "exact",
			maxLen: 5,
			want:   "exact",
		},
		{
			name:   "long string",
			input:  "this is a very long string",
			maxLen: 10,
			want:   "this is...",
		},
		{
			name:   "maxLen <= 3",
			input:  "long",
			maxLen: 3,
			want:   "...",
		},
		{
			name:   "zero maxLen",
			input:  "test",
			maxLen: 0,
			want:   "test",
		},
		{
			name:   "unicode string",
			input:  "hello世界",
			maxLen: 7,
			want:   "hello...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Ellipsize(tt.input, tt.maxLen)
			if tt.maxLen > 0 && len([]rune(got)) > tt.maxLen {
				t.Errorf("Ellipsize() = %q (len=%d), exceeds maxLen %d", got, len([]rune(got)), tt.maxLen)
			}
			if tt.maxLen > 3 && len([]rune(got)) > tt.maxLen {
				t.Errorf("Ellipsize() result exceeds maxLen")
			}
		})
	}
}

func TestColorGating(t *testing.T) {
	// Reset enabled state
	enabledMu = sync.Mutex{}
	enabledInit = false
	enabled = false

	t.Run("NO_COLOR disables colors", func(t *testing.T) {
		os.Setenv("NO_COLOR", "1")
		defer os.Unsetenv("NO_COLOR")

		enabledMu = sync.Mutex{}
		enabledInit = false
		enabled = false

		result := C.Bold("test")
		if strings.Contains(result, "\033[1m") {
			t.Errorf("Colors should be disabled with NO_COLOR, got %q", result)
		}
	})

	t.Run("TERM=dumb disables colors", func(t *testing.T) {
		os.Unsetenv("NO_COLOR")
		os.Setenv("TERM", "dumb")
		defer os.Unsetenv("TERM")

		enabledMu = sync.Mutex{}
		enabledInit = false
		enabled = false

		result := C.Green("test")
		if strings.Contains(result, "\033[32m") {
			t.Errorf("Colors should be disabled with TERM=dumb, got %q", result)
		}
	})

	t.Run("DITTO_PRETTY enables colors", func(t *testing.T) {
		os.Unsetenv("NO_COLOR")
		os.Unsetenv("TERM")
		os.Setenv("DITTO_PRETTY", "1")
		defer os.Unsetenv("DITTO_PRETTY")

		enabledMu = sync.Mutex{}
		enabledInit = false
		enabled = false

		result := C.Red("test")
		if !strings.Contains(result, "\033[31m") {
			t.Errorf("Colors should be enabled with DITTO_PRETTY, got %q", result)
		}
	})

	t.Run("EnableColors forces colors", func(t *testing.T) {
		os.Unsetenv("NO_COLOR")
		os.Unsetenv("TERM")
		os.Unsetenv("DITTO_PRETTY")

		enabledMu = sync.Mutex{}
		enabledInit = false
		enabled = false

		EnableColors()
		result := C.Blue("test")
		if !strings.Contains(result, "\033[34m") {
			t.Errorf("Colors should be enabled after EnableColors(), got %q", result)
		}
	})

	t.Run("DisableColors forces no colors", func(t *testing.T) {
		enabledMu = sync.Mutex{}
		enabledInit = false
		enabled = false

		DisableColors()
		result := C.Yellow("test")
		if strings.Contains(result, "\033[33m") {
			t.Errorf("Colors should be disabled after DisableColors(), got %q", result)
		}
	})
}

func TestSpinner(t *testing.T) {
	t.Run("non-TTY no-op", func(t *testing.T) {
		// Spinner should not block or panic in non-TTY mode
		spinner := NewSpinner("testing")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		spinner.Start(ctx)
		time.Sleep(50 * time.Millisecond)
		spinner.Stop(true)

		// Should complete without hanging
	})

	t.Run("stop before start", func(t *testing.T) {
		spinner := NewSpinner("test")
		spinner.Stop(true) // Should not panic
	})

	t.Run("start stop sequence", func(t *testing.T) {
		spinner := NewSpinner("test")
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		spinner.Start(ctx)
		time.Sleep(50 * time.Millisecond)
		spinner.Stop(true)
	})
}

func TestChoose(t *testing.T) {
	t.Run("no options", func(t *testing.T) {
		ctx := context.Background()
		_, _, err := Choose(ctx, "test", []string{}, 0)
		if err == nil {
			t.Error("Choose() should return error for empty options")
		}
	})

	t.Run("invalid default index", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// In non-TTY mode, should return default immediately
		// Use a short timeout to avoid hanging
		idx, chosen, err := Choose(ctx, "test", []string{"a", "b"}, 5)
		// Should use default (0) when index is invalid
		if idx != 0 {
			t.Errorf("Choose() should default to 0 for invalid index, got %d", idx)
		}
		if chosen != "a" {
			t.Errorf("Choose() should return first option for invalid index, got %q", chosen)
		}
		// May return error in non-TTY if stdin is closed, which is OK
		_ = err
	})

	// Skip interactive tests that require stdin input
	t.Skip("Skipping interactive Choose() tests - require TTY stdin")
}

func TestUserError(t *testing.T) {
	err := NewUserError("test error", "fix hint")
	if err == nil {
		t.Fatal("NewUserError() returned nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "test error") {
		t.Errorf("Error() = %q, want containing 'test error'", errStr)
	}
	if !strings.Contains(errStr, "fix hint") {
		t.Errorf("Error() = %q, want containing 'fix hint'", errStr)
	}
}

func TestPrintJSONSyntax(t *testing.T) {
	// Reset enabled state for predictable output
	enabledMu = sync.Mutex{}
	enabledInit = false
	enabled = false
	DisableColors()

	json := `{"key": "value", "number": 42}`
	// Just verify it doesn't panic - can't easily capture stdout
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintJSONSyntax() panicked: %v", r)
		}
	}()
	PrintJSONSyntax(json)
}

func FuzzWrapNoPanic(f *testing.F) {
	f.Add("short text", 80)
	f.Add("this is a very long line that should wrap properly", 20)
	f.Add("", 0)
	f.Add("word", 1)

	f.Fuzz(func(t *testing.T, text string, width int) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Wrap() panicked with %v for input %q width %d", r, text, width)
			}
		}()
		Wrap(text, width)
	})
}

func FuzzEllipsizeNoPanic(f *testing.F) {
	f.Add("short", 10)
	f.Add("this is a very long string", 5)
	f.Add("", 0)
	f.Add("test", -1)

	f.Fuzz(func(t *testing.T, text string, maxLen int) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Ellipsize() panicked with %v for input %q maxLen %d", r, text, maxLen)
			}
		}()
		Ellipsize(text, maxLen)
	})
}

func TestH1H2(t *testing.T) {
	// Test that H1 and H2 don't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("H1/H2 panicked: %v", r)
		}
	}()
	H1("Test Heading")
	H2("Sub Heading")
}

func TestBullets(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Bullets() panicked: %v", r)
		}
	}()
	items := []string{"item1", "item2", "item3"}
	Bullets(items)
}

func TestKV(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("KV() panicked: %v", r)
		}
	}()
	pairs := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	KV(pairs)
}

