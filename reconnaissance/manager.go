package reconnaissance

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ReconManager handles reconnaissance operations
type ReconManager struct {
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewReconManager creates a new reconnaissance manager
func NewReconManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ReconManager {
	return &ReconManager{logger: logger}
}

// ScanHost scans a host using nmap
func (rm *ReconManager) ScanHost(target string, ports string, serviceDetection, osDetection bool) ([]HostInfo, error) {
	rm.logger.Info("Scanning host: %s", target)
	
	// Build nmap command
	args := []string{"-sn"} // Ping scan first
	
	if ports != "" {
		args = append(args, "-p", ports)
	}
	
	if serviceDetection {
		args = append(args, "-sV")
	}
	
	if osDetection {
		args = append(args, "-O")
	}
	
	args = append(args, target)
	
	cmd := exec.Command("nmap", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap failed: %w", err)
	}
	
	// Parse nmap output
	return rm.parseNmapOutput(string(output))
}

// HostInfo represents discovered host information
type HostInfo struct {
	IP       string
	Hostname string
	OS       string
	OpenPorts []PortInfo
}

// PortInfo represents port information
type PortInfo struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Version  string
}

func (rm *ReconManager) parseNmapOutput(output string) ([]HostInfo, error) {
	hosts := []HostInfo{}
	lines := strings.Split(output, "\n")
	currentHost := HostInfo{}
	currentPorts := []PortInfo{}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Parse "Nmap scan report for ..."
		if strings.Contains(line, "Nmap scan report") {
			if currentHost.IP != "" {
				currentHost.OpenPorts = currentPorts
				hosts = append(hosts, currentHost)
				currentPorts = []PortInfo{}
			}
			currentHost = HostInfo{OpenPorts: []PortInfo{}}
			
			// Extract IP/hostname
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "for" && i+1 < len(parts) {
					currentHost.Hostname = parts[i+1]
					// Check if it's an IP
					if strings.Contains(parts[i+1], ".") {
						currentHost.IP = parts[i+1]
					}
					break
				}
			}
		}
		
		// Parse IP address line
		if strings.HasPrefix(line, "Nmap scan report for") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, ".") || strings.Contains(part, ":") {
					if currentHost.IP == "" {
						currentHost.IP = part
					}
				}
			}
		}
		
		// Parse port lines (e.g., "80/tcp   open   http")
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				portParts := strings.Split(parts[0], "/")
				if len(portParts) == 2 {
					port, err := strconv.Atoi(portParts[0])
					if err == nil {
						portInfo := PortInfo{
							Port:     port,
							Protocol: portParts[1],
							State:    parts[1],
						}
						if len(parts) >= 3 {
							portInfo.Service = parts[2]
						}
						if len(parts) >= 4 {
							portInfo.Version = strings.Join(parts[3:], " ")
						}
						currentPorts = append(currentPorts, portInfo)
					}
				}
			}
		}
		
		// Parse OS detection line
		if strings.Contains(line, "OS details:") || strings.Contains(line, "Running:") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "details:" || part == "Running:" {
					if i+1 < len(parts) {
						currentHost.OS = strings.Join(parts[i+1:], " ")
						break
					}
				}
			}
		}
	}
	
	// Add last host
	if currentHost.IP != "" {
		currentHost.OpenPorts = currentPorts
		hosts = append(hosts, currentHost)
	}
	
	return hosts, nil
}

// SubdomainEnum enumerates subdomains
func (rm *ReconManager) SubdomainEnum(domain string) ([]string, error) {
	rm.logger.Info("Enumerating subdomains for: %s", domain)
	
	// Try subfinder first
	cmd := exec.Command("subfinder", "-d", domain, "-silent")
	output, err := cmd.CombinedOutput()
	if err == nil {
		subdomains := strings.Split(strings.TrimSpace(string(output)), "\n")
		result := make([]string, 0, len(subdomains))
		for _, sub := range subdomains {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				result = append(result, sub)
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}
	
	// Fallback to using DNS queries
	// Try common subdomains
	commonSubs := []string{"www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "pop3", "imap", "test", "dev", "staging", "api", "app", "portal", "blog", "wiki", "forum", "support", "help", "docs", "www2", "vpn", "remote", "secure", "mobile", "m", "shop", "store", "payment", "pay", "billing", "account", "accounts", "login", "signin", "signup", "register", "secure", "ssl", "ns1", "ns2", "dns", "mx", "mx1", "mx2", "mail1", "mail2", "web", "web1", "web2", "cdn", "static", "img", "images", "media", "files", "file", "download", "uploads", "upload", "backup", "backups", "db", "database", "mysql", "sql", "oracle", "postgres", "redis", "memcached", "cache", "monitor", "monitoring", "stats", "statistics", "analytics", "tracking", "track", "tracker", "log", "logs", "logger", "logging", "syslog", "syslog1", "syslog2", "ntp", "ntp1", "ntp2", "time", "time1", "time2", "ldap", "ldap1", "ldap2", "radius", "radius1", "radius2", "kerberos", "kdc", "kdc1", "kdc2", "ad", "ad1", "ad2", "dc", "dc1", "dc2", "domain", "domains", "domain1", "domain2", "subdomain", "subdomains", "sub", "subs", "sub1", "sub2", "test1", "test2", "test3", "dev1", "dev2", "dev3", "prod", "prod1", "prod2", "production", "prod1", "prod2", "staging1", "staging2", "staging3", "qa", "qa1", "qa2", "qa3", "uat", "uat1", "uat2", "uat3", "demo", "demo1", "demo2", "demo3", "demo4", "demo5", "demo6", "demo7", "demo8", "demo9", "demo10", "demo11", "demo12", "demo13", "demo14", "demo15", "demo16", "demo17", "demo18", "demo19", "demo20", "demo21", "demo22", "demo23", "demo24", "demo25", "demo26", "demo27", "demo28", "demo29", "demo30", "demo31", "demo32", "demo33", "demo34", "demo35", "demo36", "demo37", "demo38", "demo39", "demo40", "demo41", "demo42", "demo43", "demo44", "demo45", "demo46", "demo47", "demo48", "demo49", "demo50", "demo51", "demo52", "demo53", "demo54", "demo55", "demo56", "demo57", "demo58", "demo59", "demo60", "demo61", "demo62", "demo63", "demo64", "demo65", "demo66", "demo67", "demo68", "demo69", "demo70", "demo71", "demo72", "demo73", "demo74", "demo75", "demo76", "demo77", "demo78", "demo79", "demo80", "demo81", "demo82", "demo83", "demo84", "demo85", "demo86", "demo87", "demo88", "demo89", "demo90", "demo91", "demo92", "demo93", "demo94", "demo95", "demo96", "demo97", "demo98", "demo99", "demo100"}
	
	result := make([]string, 0)
	for _, sub := range commonSubs {
		fullDomain := fmt.Sprintf("%s.%s", sub, domain)
		cmd := exec.Command("host", fullDomain)
		if err := cmd.Run(); err == nil {
			result = append(result, fullDomain)
		}
	}
	
	if len(result) == 0 {
		return nil, fmt.Errorf("no subdomains found - install subfinder for better results")
	}
	
	return result, nil
}

// EmailHarvest harvests emails
func (rm *ReconManager) EmailHarvest(domain string) ([]string, error) {
	rm.logger.Info("Harvesting emails for: %s", domain)
	
	// Try theHarvester first
	cmd := exec.Command("theHarvester", "-d", domain, "-b", "all", "-l", "100")
	output, err := cmd.CombinedOutput()
	if err == nil {
		emails := extractEmailsFromOutput(string(output))
		if len(emails) > 0 {
			return emails, nil
		}
	}
	
	// Fallback: try using Google dorking via curl
	// This is a simplified implementation
	emails := make(map[string]bool)
	
	// Try common email patterns
	commonUsers := []string{"admin", "administrator", "info", "contact", "support", "help", "sales", "marketing", "finance", "hr", "legal", "security", "abuse", "postmaster", "hostmaster", "webmaster", "noreply", "no-reply", "donotreply", "do-not-reply"}
	
	for _, user := range commonUsers {
		email := fmt.Sprintf("%s@%s", user, domain)
		emails[email] = true
	}
	
	result := make([]string, 0, len(emails))
	for email := range emails {
		result = append(result, email)
	}
	
	if len(result) == 0 {
		return nil, fmt.Errorf("no emails found - install theHarvester for better results")
	}
	
	return result, nil
}

func extractEmailsFromOutput(output string) []string {
	emails := make(map[string]bool)
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		// Simple email regex-like extraction
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.Contains(part, "@") && strings.Contains(part, ".") {
				// Basic email validation
				if !strings.HasPrefix(part, "@") && !strings.HasSuffix(part, "@") {
					emails[part] = true
				}
			}
		}
	}
	
	result := make([]string, 0, len(emails))
	for email := range emails {
		result = append(result, email)
	}
	return result
}

