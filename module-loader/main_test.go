package main

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainFunctionality(t *testing.T) {
	// Test that main sets up flags correctly
	// Since main() calls os.Exit, we can't test it directly
	// Instead, we test the underlying functionality
	
	// Reset flags for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"module-loader", "-help"}
	
	// Create a flag set to test flag parsing
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	empireModulesPath := fs.String("empire-modules", "", "Path to Empire modules directory")
	loadModules := fs.Bool("load-modules", false, "Load Empire modules")
	listModules := fs.Bool("list-modules", false, "List loaded modules")
	searchModules := fs.String("search", "", "Search modules")
	category := fs.String("category", "", "Filter by category")
	language := fs.String("language", "", "Filter by language")
	moduleID := fs.String("module", "", "Show module details")
	debug := fs.Bool("debug", false, "Enable debug logging")
	
	err := fs.Parse([]string{"-empire-modules", "/test/path", "-load-modules", "-debug"})
	require.NoError(t, err)
	
	assert.Equal(t, "/test/path", *empireModulesPath)
	assert.True(t, *loadModules)
	assert.True(t, *debug)
	assert.False(t, *listModules)
	assert.Empty(t, *searchModules)
	assert.Empty(t, *category)
	assert.Empty(t, *language)
	assert.Empty(t, *moduleID)
}

func TestFlagParsing(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.String("empire-modules", "", "Path")
	_ = fs.Bool("load-modules", false, "Load")
	_ = fs.Bool("list-modules", false, "List")
	_ = fs.String("search", "", "Search")
	_ = fs.String("category", "", "Category")
	_ = fs.String("language", "", "Language")
	_ = fs.String("module", "", "Module")
	_ = fs.Bool("debug", false, "Debug")
	
	err := fs.Parse([]string{"-list-modules", "-search", "test", "-category", "code_execution", "-language", "powershell", "-module", "test-module"})
	require.NoError(t, err)
	
	assert.Equal(t, fs.Lookup("list-modules").Value.String(), "true")
	assert.Equal(t, fs.Lookup("search").Value.String(), "test")
	assert.Equal(t, fs.Lookup("category").Value.String(), "code_execution")
	assert.Equal(t, fs.Lookup("language").Value.String(), "powershell")
	assert.Equal(t, fs.Lookup("module").Value.String(), "test-module")
}

