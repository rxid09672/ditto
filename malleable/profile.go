package malleable

/*
	Malleable C2 Profile Parser and Manager
	Streamlined implementation following Cobalt Strike architecture
*/

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/ditto/ditto/malleable/parser"
)

// Profile represents a parsed malleable C2 profile
type Profile struct {
	Name string
	Raw  []byte

	// HTTP GET configuration
	GetURIs        []string
	GetMetadata    []Function // Transform pipeline for GET metadata
	GetServer      *ServerConfig

	// HTTP POST configuration
	PostURIs       []string
	PostID         []Function // Transform pipeline for POST session ID
	PostOutput     []Function // Transform pipeline for POST output
	PostServer     *ServerConfig

	// Headers and parameters from profile
	GetHeaders     map[string]string
	GetParameters  map[string]string
	PostHeaders    map[string]string
	PostParameters map[string]string

	// Global settings
	UserAgent string
	SleepTime int
	Jitter    int

	mu sync.RWMutex
}

// ServerConfig holds server-side response configuration
type ServerConfig struct {
	Headers []HeaderPair
	Output  []Function // Transform pipeline for server output
}

// HeaderPair represents a header name-value pair
type HeaderPair struct {
	Name  string
	Value string
}

// Function represents a transform function with arguments
type Function struct {
	Func string
	Args []string
}

// ProfileRegistry manages loaded profiles
type ProfileRegistry struct {
	profiles map[string]*Profile
	active   string // Name of active profile
	mu       sync.RWMutex
}

var globalRegistry = &ProfileRegistry{
	profiles: make(map[string]*Profile),
}

// GetRegistry returns the global profile registry
func GetRegistry() *ProfileRegistry {
	return globalRegistry
}

// ParseProfile parses a malleable profile from raw bytes using goMalleable parser
func ParseProfile(name string, profileData []byte) (*Profile, error) {
	reader := bytes.NewReader(profileData)
	
	// Parse using goMalleable parser
	parsedProfile, err := parser.Parse(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse profile: %w", err)
	}

	profile := &Profile{
		Name:          name,
		Raw:           profileData,
		GetURIs:       make([]string, 0),
		PostURIs:      make([]string, 0),
		GetHeaders:    make(map[string]string),
		GetParameters: make(map[string]string),
		PostHeaders:   make(map[string]string),
		PostParameters: make(map[string]string),
		GetServer:     &ServerConfig{Headers: make([]HeaderPair, 0)},
		PostServer:    &ServerConfig{Headers: make([]HeaderPair, 0)},
	}

	// Extract global settings
	if parsedProfile.UserAgent != "" {
		profile.UserAgent = parsedProfile.UserAgent
	}
	if parsedProfile.SleepTime > 0 {
		profile.SleepTime = parsedProfile.SleepTime
	}
	if parsedProfile.Jitter > 0 {
		profile.Jitter = parsedProfile.Jitter
	}

	// Extract HTTP GET configuration
	if len(parsedProfile.HTTPGet) > 0 {
		httpGet := parsedProfile.HTTPGet[0]
		
		// Extract URIs
		if len(httpGet.URI) > 0 {
			profile.GetURIs = httpGet.URI
		}

		// Extract metadata transforms
		if len(httpGet.Client.Metadata) > 0 {
			profile.GetMetadata = convertFunctions(httpGet.Client.Metadata)
		}

		// Extract headers
		for _, h := range httpGet.Client.Headers {
			profile.GetHeaders[h.Name] = h.Value
		}

		// Extract parameters
		for _, p := range httpGet.Client.Parameters {
			profile.GetParameters[p.Name] = p.Value
		}

		// Extract server configuration
		if len(httpGet.Server.Headers) > 0 {
			profile.GetServer.Headers = make([]HeaderPair, len(httpGet.Server.Headers))
			for i, h := range httpGet.Server.Headers {
				profile.GetServer.Headers[i] = HeaderPair{Name: h.Name, Value: h.Value}
			}
		}
		if len(httpGet.Server.Output) > 0 {
			profile.GetServer.Output = convertFunctions(httpGet.Server.Output)
		}
	}

	// Extract HTTP POST configuration
	if len(parsedProfile.HTTPPost) > 0 {
		httpPost := parsedProfile.HTTPPost[0]
		
		// Extract URIs
		if len(httpPost.URI) > 0 {
			profile.PostURIs = httpPost.URI
		}

		// Extract ID transforms (session ID)
		if len(httpPost.Client.ID) > 0 {
			profile.PostID = convertFunctions(httpPost.Client.ID)
		}

		// Extract output transforms (task results)
		if len(httpPost.Client.Output) > 0 {
			profile.PostOutput = convertFunctions(httpPost.Client.Output)
		}

		// Extract headers
		for _, h := range httpPost.Client.Headers {
			profile.PostHeaders[h.Name] = h.Value
		}

		// Extract parameters
		for _, p := range httpPost.Client.Parameters {
			profile.PostParameters[p.Name] = p.Value
		}

		// Extract server configuration
		if len(httpPost.Server.Headers) > 0 {
			profile.PostServer.Headers = make([]HeaderPair, len(httpPost.Server.Headers))
			for i, h := range httpPost.Server.Headers {
				profile.PostServer.Headers[i] = HeaderPair{Name: h.Name, Value: h.Value}
			}
		}
		if len(httpPost.Server.Output) > 0 {
			profile.PostServer.Output = convertFunctions(httpPost.Server.Output)
		}
	}

	return profile, nil
}

// convertFunctions converts parser.Function to our Function type
func convertFunctions(parserFuncs []parser.Function) []Function {
	functions := make([]Function, len(parserFuncs))
	for i, f := range parserFuncs {
		functions[i] = Function{
			Func: f.Func,
			Args: f.Args,
		}
	}
	return functions
}

// Register adds a profile to the registry
func (r *ProfileRegistry) Register(profile *Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if profile == nil || profile.Name == "" {
		return fmt.Errorf("invalid profile")
	}

	r.profiles[profile.Name] = profile
	return nil
}

// Get retrieves a profile by name
func (r *ProfileRegistry) Get(name string) (*Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, ok := r.profiles[name]
	return profile, ok
}

// List returns all registered profiles
func (r *ProfileRegistry) List() []*Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profiles := make([]*Profile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		profiles = append(profiles, profile)
	}

	return profiles
}

// SetActive sets the active profile
func (r *ProfileRegistry) SetActive(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[name]; !ok {
		return fmt.Errorf("profile not found: %s", name)
	}

	r.active = name
	return nil
}

// GetActive returns the active profile
func (r *ProfileRegistry) GetActive() (*Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.active == "" {
		return nil, false
	}

	profile, ok := r.profiles[r.active]
	return profile, ok
}

// Delete removes a profile from the registry
func (r *ProfileRegistry) Delete(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[name]; !ok {
		return fmt.Errorf("profile not found: %s", name)
	}

	delete(r.profiles, name)
	
	// If this was the active profile, clear it
	if r.active == name {
		r.active = ""
	}

	return nil
}

