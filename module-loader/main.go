package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/modules"
)

func main() {
	var (
		empireModulesPath = flag.String("empire-modules", "", "Path to Empire modules directory")
		loadModules       = flag.Bool("load-modules", false, "Load Empire modules")
		listModules       = flag.Bool("list-modules", false, "List loaded modules")
		searchModules     = flag.String("search", "", "Search modules")
		category          = flag.String("category", "", "Filter by category")
		language          = flag.String("language", "", "Filter by language")
		moduleID          = flag.String("module", "", "Show module details")
		debug             = flag.Bool("debug", false, "Enable debug logging")
	)
	
	flag.Parse()
	
	logger := core.NewLogger(*debug)
	
	// Create module registry
	registry := modules.NewModuleRegistry(logger)
	
	// Load modules if requested
	if *loadModules && *empireModulesPath != "" {
		logger.Info("Loading Empire modules from: %s", *empireModulesPath)
		if err := registry.LoadModulesFromDirectory(*empireModulesPath); err != nil {
			log.Fatalf("Failed to load modules: %v", err)
		}
		logger.Info("Loaded %d modules", registry.GetModuleCount())
	}
	
	// List modules
	if *listModules {
		allModules := registry.ListAllModules()
		fmt.Printf("Total modules: %d\n\n", len(allModules))
		
		for _, module := range allModules {
			fmt.Printf("ID: %s\n", module.ID)
			fmt.Printf("Name: %s\n", module.Name)
			fmt.Printf("Language: %s\n", module.Language)
			fmt.Printf("Category: %s\n", module.Category)
			fmt.Printf("Description: %s\n", module.Description)
			fmt.Println("---")
		}
		return
	}
	
	// Search modules
	if *searchModules != "" {
		results := registry.SearchModules(*searchModules)
		fmt.Printf("Found %d modules matching '%s'\n\n", len(results), *searchModules)
		for _, module := range results {
			fmt.Printf("%s: %s (%s)\n", module.ID, module.Name, module.Language)
		}
		return
	}
	
	// Filter by category
	if *category != "" {
		categoryEnum := modules.ModuleCategory(*category)
		results := registry.ListModulesByCategory(categoryEnum)
		fmt.Printf("Found %d modules in category '%s'\n\n", len(results), *category)
		for _, module := range results {
			fmt.Printf("%s: %s\n", module.ID, module.Name)
		}
		return
	}
	
	// Filter by language
	if *language != "" {
		languageEnum := modules.ModuleLanguage(*language)
		results := registry.ListModulesByLanguage(languageEnum)
		fmt.Printf("Found %d modules in language '%s'\n\n", len(results), *language)
		for _, module := range results {
			fmt.Printf("%s: %s\n", module.ID, module.Name)
		}
		return
	}
	
	// Show module details
	if *moduleID != "" {
		module, ok := registry.GetModule(*moduleID)
		if !ok {
			log.Fatalf("Module not found: %s", *moduleID)
		}
		
		jsonData, err := module.ToJSON()
		if err != nil {
			log.Fatalf("Failed to serialize module: %v", err)
		}
		
		fmt.Println(string(jsonData))
		return
	}
	
	fmt.Println("Use -help to see available commands")
}

