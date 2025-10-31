package privesc

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ditto/ditto/modules"
)

// PrivescIntelligence analyzes PrivescCheck output and maps findings to available modules
type PrivescIntelligence struct {
	moduleRegistry *modules.ModuleRegistry
}

// PrivescFinding represents a finding from PrivescCheck
type PrivescFinding struct {
	CheckID       string
	Category      string
	Severity      string
	Finding       string
	Recommendation string
}

// ModuleRecommendation maps a finding to recommended modules
type ModuleRecommendation struct {
	Finding          string
	Recommendation   string
	AvailableModules []ModuleMatch
	UnavailableModules []string // Modules that would work but aren't available
}

// ModuleMatch represents a module that matches a finding
type ModuleMatch struct {
	ModuleID       string
	Name           string
	Description    string
	EscalationType string // "User->Admin" or "Admin->System"
	Confidence     string // "High", "Medium", "Low"
	Reason         string
}

// NewPrivescIntelligence creates a new intelligence service
func NewPrivescIntelligence(moduleRegistry *modules.ModuleRegistry) *PrivescIntelligence {
	return &PrivescIntelligence{
		moduleRegistry: moduleRegistry,
	}
}

// AnalyzePrivescCheckOutput parses PrivescCheck output and returns actionable recommendations
func (pi *PrivescIntelligence) AnalyzePrivescCheckOutput(output string, currentUserIsAdmin bool) ([]ModuleRecommendation, error) {
	recommendations := make([]ModuleRecommendation, 0)
	
	// Parse PrivescCheck output - it's text-based, so we need to use regex/keyword matching
	findings := pi.parsePrivescCheckOutput(output)
	
	// Map findings to modules
	for _, finding := range findings {
		matches := pi.mapFindingToModules(finding, currentUserIsAdmin)
		if len(matches.AvailableModules) > 0 || len(matches.UnavailableModules) > 0 {
			recommendations = append(recommendations, matches)
		}
	}
	
	return recommendations, nil
}

// parsePrivescCheckOutput extracts findings from PrivescCheck text output
func (pi *PrivescIntelligence) parsePrivescCheckOutput(output string) []PrivescFinding {
	findings := make([]PrivescFinding, 0)
	
	// PrivescCheck outputs findings with patterns like:
	// - Category headers: "=== [Category] ==="
	// - Findings: usually marked with "Vuln" or "Info" severity
	// - Service misconfigurations
	// - Registry vulnerabilities
	// - File permission issues
	// - Unquoted service paths
	// - Weak service permissions
	
	lines := strings.Split(output, "\n")
	currentCategory := ""
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		
		// Detect category headers
		if strings.HasPrefix(line, "===") && strings.HasSuffix(line, "===") {
			currentCategory = strings.Trim(line, "= []")
			continue
		}
		
		// Look for vulnerability indicators
		if strings.Contains(strings.ToLower(line), "vulnerable") ||
			strings.Contains(strings.ToLower(line), "misconfiguration") ||
			strings.Contains(strings.ToLower(line), "weak permission") ||
			strings.Contains(strings.ToLower(line), "unquoted") ||
			strings.Contains(strings.ToLower(line), "writable") {
			
			// Try to extract check ID and details
			checkID := pi.extractCheckID(line)
			severity := pi.extractSeverity(line)
			
			finding := PrivescFinding{
				CheckID:  checkID,
				Category: currentCategory,
				Severity: severity,
				Finding:  line,
			}
			
			// Get context from surrounding lines
			if i > 0 && i < len(lines)-1 {
				context := strings.Join(lines[max(0, i-2):min(len(lines), i+3)], " ")
				finding.Finding = context
			}
			
			findings = append(findings, finding)
		}
	}
	
	return findings
}

// extractCheckID tries to extract a check ID from a line
func (pi *PrivescIntelligence) extractCheckID(line string) string {
	// Look for patterns like "SERVICE_PERMISSIONS", "REGISTRY_WRITABLE", etc.
	re := regexp.MustCompile(`([A-Z_]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 0 {
		return matches[0]
	}
	return "UNKNOWN"
}

// extractSeverity extracts severity from a line
func (pi *PrivescIntelligence) extractSeverity(line string) string {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "high") || strings.Contains(lineLower, "critical") {
		return "High"
	}
	if strings.Contains(lineLower, "medium") {
		return "Medium"
	}
	if strings.Contains(lineLower, "low") || strings.Contains(lineLower, "info") {
		return "Low"
	}
	return "Unknown"
}

// mapFindingToModules maps a finding to available modules
func (pi *PrivescIntelligence) mapFindingToModules(finding PrivescFinding, currentUserIsAdmin bool) ModuleRecommendation {
	rec := ModuleRecommendation{
		Finding:          finding.Finding,
		AvailableModules: make([]ModuleMatch, 0),
		UnavailableModules: make([]string, 0),
	}
	
	findingLower := strings.ToLower(finding.Finding)
	categoryLower := strings.ToLower(finding.Category)
	checkIDLower := strings.ToLower(finding.CheckID)
	
	// Get all privesc modules
	allModules := pi.moduleRegistry.ListAllModules()
	privescModules := make([]*modules.EmpireModule, 0)
	for _, mod := range allModules {
		if mod.Category == modules.CategoryPrivilegeEscalation {
			privescModules = append(privescModules, mod)
		}
	}
	
	// Mapping rules based on PrivescCheck findings
	
	// 1. Service misconfigurations -> PowerUp service modules
	if strings.Contains(categoryLower, "service") ||
		strings.Contains(checkIDLower, "service") ||
		strings.Contains(findingLower, "service") {
		
		if strings.Contains(findingLower, "unquoted") || strings.Contains(findingLower, "path") {
			rec.Recommendation = "Unquoted service path detected - exploitable via service path manipulation"
			pi.addModuleMatches(privescModules, []string{"powerup", "service"}, "User->Admin", "High", 
				"Unquoted service path allows privilege escalation", &rec, currentUserIsAdmin)
		}
		
		if strings.Contains(findingLower, "permission") || strings.Contains(findingLower, "writable") {
			rec.Recommendation = "Weak service permissions detected - exploitable via service manipulation"
			pi.addModuleMatches(privescModules, []string{"powerup", "service"}, "User->Admin", "High",
				"Weak service permissions allow service modification", &rec, currentUserIsAdmin)
		}
		
		if strings.Contains(findingLower, "dll") || strings.Contains(findingLower, "hijack") {
			rec.Recommendation = "DLL hijacking opportunity detected"
			pi.addModuleMatches(privescModules, []string{"dll", "hijack"}, "User->Admin", "Medium",
				"DLL hijacking vulnerability identified", &rec, currentUserIsAdmin)
		}
	}
	
	// 2. Registry vulnerabilities -> Registry-based privesc
	if strings.Contains(categoryLower, "registry") ||
		strings.Contains(checkIDLower, "registry") ||
		strings.Contains(findingLower, "registry") {
		
		if strings.Contains(findingLower, "writable") || strings.Contains(findingLower, "autorun") {
			rec.Recommendation = "Writable registry key or autorun entry detected"
			pi.addModuleMatches(privescModules, []string{"registry", "autorun"}, "User->Admin", "Medium",
				"Registry misconfiguration allows privilege escalation", &rec, currentUserIsAdmin)
		}
	}
	
	// 3. Scheduled task vulnerabilities
	if strings.Contains(categoryLower, "task") ||
		strings.Contains(checkIDLower, "task") ||
		strings.Contains(findingLower, "scheduled task") {
		
		rec.Recommendation = "Scheduled task misconfiguration detected"
		pi.addModuleMatches(privescModules, []string{"task", "scheduled"}, "User->Admin", "Medium",
			"Scheduled task vulnerability identified", &rec, currentUserIsAdmin)
	}
	
	// 4. UAC bypass opportunities
	if strings.Contains(findingLower, "uac") || strings.Contains(findingLower, "bypass") {
		if !currentUserIsAdmin {
			rec.Recommendation = "UAC bypass opportunity detected"
			pi.addModuleMatches(privescModules, []string{"bypassuac"}, "User->Admin", "High",
				"UAC bypass vulnerability can elevate to admin", &rec, currentUserIsAdmin)
		}
	}
	
	// 5. Token/privilege vulnerabilities -> getsystem modules
	if strings.Contains(findingLower, "token") ||
		strings.Contains(findingLower, "privilege") ||
		strings.Contains(findingLower, "seimpersonate") ||
		strings.Contains(findingLower, "sedebug") {
		
		if currentUserIsAdmin {
			rec.Recommendation = "Token manipulation opportunity - can escalate to SYSTEM"
			pi.addModuleMatches(privescModules, []string{"getsystem", "token"}, "Admin->System", "High",
				"Token privileges allow SYSTEM escalation", &rec, currentUserIsAdmin)
		}
	}
	
	// 6. Named pipe vulnerabilities -> getsystem
	if strings.Contains(findingLower, "pipe") || strings.Contains(findingLower, "named pipe") {
		if currentUserIsAdmin {
			rec.Recommendation = "Named pipe impersonation opportunity - can escalate to SYSTEM"
			pi.addModuleMatches(privescModules, []string{"getsystem", "pipe"}, "Admin->System", "High",
				"Named pipe vulnerability allows SYSTEM escalation", &rec, currentUserIsAdmin)
		}
	}
	
	// 7. CVE-specific vulnerabilities
	if strings.Contains(findingLower, "ms16-032") || strings.Contains(findingLower, "cve-2016-0099") {
		rec.Recommendation = "MS16-032 vulnerability detected"
		pi.addModuleMatches(privescModules, []string{"ms16-032"}, "User->Admin", "High",
			"MS16-032 allows privilege escalation", &rec, currentUserIsAdmin)
	}
	
	if strings.Contains(findingLower, "printnightmare") || strings.Contains(findingLower, "cve-2021-34527") {
		rec.Recommendation = "PrintNightmare vulnerability detected"
		pi.addModuleMatches(privescModules, []string{"printnightmare"}, "User->Admin", "Critical",
			"PrintNightmare allows SYSTEM escalation", &rec, currentUserIsAdmin)
	}
	
	if strings.Contains(findingLower, "printdemon") || strings.Contains(findingLower, "cve-2020-1048") {
		rec.Recommendation = "PrintDemon vulnerability detected"
		pi.addModuleMatches(privescModules, []string{"printdemon"}, "User->Admin", "High",
			"PrintDemon allows privilege escalation", &rec, currentUserIsAdmin)
	}
	
	// 8. GPP passwords
	if strings.Contains(findingLower, "gpp") || strings.Contains(findingLower, "group policy") {
		rec.Recommendation = "Group Policy Preferences (GPP) passwords detected"
		pi.addModuleMatches(privescModules, []string{"gpp"}, "User->Admin", "Medium",
			"GPP passwords can be decrypted for credential reuse", &rec, currentUserIsAdmin)
	}
	
	// 9. McAfee SiteList passwords
	if strings.Contains(findingLower, "mcafee") || strings.Contains(findingLower, "sitelist") {
		rec.Recommendation = "McAfee SiteList password detected"
		pi.addModuleMatches(privescModules, []string{"mcafee", "sitelist"}, "User->Admin", "Medium",
			"McAfee SiteList contains decryptable passwords", &rec, currentUserIsAdmin)
	}
	
	return rec
}

// addModuleMatches adds matching modules to the recommendation
func (pi *PrivescIntelligence) addModuleMatches(modules []*modules.EmpireModule, keywords []string, 
	escalationType string, confidence string, reason string, rec *ModuleRecommendation, currentUserIsAdmin bool) {
	
	for _, mod := range modules {
		modIDLower := strings.ToLower(mod.ID)
		modNameLower := strings.ToLower(mod.Name)
		modDescLower := strings.ToLower(mod.Description)
		
		// Check if module matches keywords
		matches := false
		for _, keyword := range keywords {
			if strings.Contains(modIDLower, keyword) ||
				strings.Contains(modNameLower, keyword) ||
				strings.Contains(modDescLower, keyword) {
				matches = true
				break
			}
		}
		
		if matches {
			// Check if escalation type matches current user state
			if escalationType == "User->Admin" && currentUserIsAdmin {
				continue // Skip User->Admin modules if already admin
			}
			if escalationType == "Admin->System" && !currentUserIsAdmin {
				continue // Skip Admin->System modules if not admin
			}
			
			// Check if module needs admin but user isn't admin
			if mod.NeedsAdmin && !currentUserIsAdmin {
				continue
			}
			
			match := ModuleMatch{
				ModuleID:       mod.ID,
				Name:           mod.Name,
				Description:    mod.Description,
				EscalationType: escalationType,
				Confidence:     confidence,
				Reason:         reason,
			}
			
			rec.AvailableModules = append(rec.AvailableModules, match)
		}
	}
}

// FormatRecommendations formats recommendations for display
func (pi *PrivescIntelligence) FormatRecommendations(recommendations []ModuleRecommendation) string {
	if len(recommendations) == 0 {
		return "\n[*] No actionable privilege escalation opportunities found.\n"
	}
	
	var output strings.Builder
	output.WriteString("\n")
	output.WriteString("=" + strings.Repeat("=", 78) + "=\n")
	output.WriteString(" PRIVILEGE ESCALATION RECOMMENDATIONS\n")
	output.WriteString("=" + strings.Repeat("=", 78) + "=\n\n")
	
	for i, rec := range recommendations {
		if len(rec.AvailableModules) == 0 {
			continue
		}
		
		output.WriteString(fmt.Sprintf("[%d] Finding: %s\n", i+1, rec.Finding))
		if rec.Recommendation != "" {
			output.WriteString(fmt.Sprintf("     Recommendation: %s\n", rec.Recommendation))
		}
		output.WriteString("\n")
		
		// Group modules by escalation type
		userToAdmin := make([]ModuleMatch, 0)
		adminToSystem := make([]ModuleMatch, 0)
		
		for _, match := range rec.AvailableModules {
			if match.EscalationType == "User->Admin" {
				userToAdmin = append(userToAdmin, match)
			} else if match.EscalationType == "Admin->System" {
				adminToSystem = append(adminToSystem, match)
			}
		}
		
		if len(userToAdmin) > 0 {
			output.WriteString("     [USER -> ADMIN] Modules:\n")
			for _, match := range userToAdmin {
				output.WriteString(fmt.Sprintf("       ✓ %s (%s confidence)\n", match.ModuleID, match.Confidence))
				output.WriteString(fmt.Sprintf("         Reason: %s\n", match.Reason))
			}
			output.WriteString("\n")
		}
		
		if len(adminToSystem) > 0 {
			output.WriteString("     [ADMIN -> SYSTEM] Modules:\n")
			for _, match := range adminToSystem {
				output.WriteString(fmt.Sprintf("       ✓ %s (%s confidence)\n", match.ModuleID, match.Confidence))
				output.WriteString(fmt.Sprintf("         Reason: %s\n", match.Reason))
			}
			output.WriteString("\n")
		}
		
		output.WriteString(strings.Repeat("-", 80) + "\n\n")
	}
	
	return output.String()
}

// DetermineUserLevel attempts to determine if current user is admin from PrivescCheck output
func (pi *PrivescIntelligence) DetermineUserLevel(output string) bool {
	outputLower := strings.ToLower(output)
	
	// Look for indicators that user is admin
	if strings.Contains(outputLower, "administrator") ||
		strings.Contains(outputLower, "high integrity") ||
		strings.Contains(outputLower, "sid-500") {
		return true
	}
	
	// Look for indicators that user is NOT admin
	if strings.Contains(outputLower, "medium integrity") ||
		strings.Contains(outputLower, "standard user") {
		return false
	}
	
	// Default to false (safer assumption)
	return false
}

// AnalyzeAccessChkOutput parses AccessChk output and identifies exploitable permissions
func (pi *PrivescIntelligence) AnalyzeAccessChkOutput(output string) ([]ModuleMatch, error) {
	matches := make([]ModuleMatch, 0)
	
	if output == "" {
		return matches, nil
	}
	
	lines := strings.Split(output, "\n")
	var currentSection string
	var currentObject string
	var currentPermissions string
	var currentAccount string
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		
		// Detect section headers
		if strings.HasPrefix(line, "===") && strings.HasSuffix(line, "===") {
			currentSection = line
			continue
		}
		
		// Skip empty lines
		if line == "" {
			continue
		}
		
		// AccessChk output format:
		// objectname
		// RW account1
		// R account2
		// ...
		
		// Check if this line is an object name (no R/W prefix, not indented)
		// Object names are typically paths, service names, or registry keys
		if !strings.HasPrefix(line, "R") && !strings.HasPrefix(line, "W") && 
		   !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "  ") &&
		   !strings.Contains(strings.ToLower(line), "error") &&
		   !strings.Contains(strings.ToLower(line), "not recognized") {
			
			// This might be an object name
			// Check if next line has permissions
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if strings.HasPrefix(nextLine, "R") || strings.HasPrefix(nextLine, "W") {
					currentObject = line
				}
			}
			continue
		}
		
		// Check if this is a permission line (starts with R or W)
		if strings.HasPrefix(line, "R") || strings.HasPrefix(line, "W") {
			// Extract permissions (R, W, RW)
			permissions := ""
			if strings.HasPrefix(line, "RW") {
				permissions = "RW"
			} else if strings.HasPrefix(line, "W") {
				permissions = "W"
			} else if strings.HasPrefix(line, "R") {
				permissions = "R"
			}
			
			// Extract account name (everything after permissions)
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				account := strings.Join(parts[1:], " ")
				currentPermissions = permissions
				currentAccount = account
				
				// Check if this is exploitable
				if permissions == "W" || permissions == "RW" {
					// Check if account is Users, Authenticated Users, or Everyone
					accountLower := strings.ToLower(account)
					if strings.Contains(accountLower, "users") ||
						strings.Contains(accountLower, "everyone") ||
						strings.Contains(accountLower, "authenticated") {
						
						// Determine exploitation type based on object type
						objectLower := strings.ToLower(currentObject)
						escalationType := "User->Admin"
						confidence := "Medium"
						reason := ""
						
						// Service weak permissions
						if strings.Contains(currentSection, "service") || strings.Contains(currentSection, "wsvc") {
							escalationType = "User->Admin"
							confidence = "High"
							reason = fmt.Sprintf("Service '%s' has weak permissions - writable by %s", currentObject, account)
							
							match := ModuleMatch{
								ModuleID:       "powershell/privesc/powerup/service_exe_restore",
								Name:           "Service Binary Manipulation",
								Description:    fmt.Sprintf("Service '%s' has weak permissions allowing binary replacement", currentObject),
								EscalationType: escalationType,
								Confidence:     confidence,
								Reason:         reason,
							}
							matches = append(matches, match)
						}
						
						// Writable directories (DLL hijacking opportunities)
						if strings.Contains(currentSection, "writable") || strings.Contains(currentSection, "wus") {
							// Check if it's a directory path
							if strings.Contains(objectLower, ":\\") || strings.Contains(objectLower, "/") {
								escalationType = "User->Admin"
								confidence = "Medium"
								reason = fmt.Sprintf("Directory '%s' is writable by %s - potential DLL hijacking", currentObject, account)
								
								match := ModuleMatch{
									ModuleID:       "powershell/privesc/powerup/dll_hijack",
									Name:           "DLL Hijacking",
									Description:    fmt.Sprintf("Writable directory '%s' allows DLL hijacking", currentObject),
									EscalationType: escalationType,
									Confidence:     confidence,
									Reason:         reason,
								}
								matches = append(matches, match)
							}
						}
					}
				}
			}
		}
	}
	
	return matches, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

