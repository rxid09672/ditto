package core

import (
	"strings"
	"sync"
	"time"
)

// SessionType represents the type of session
type SessionType string

const (
	SessionTypeBeacon  SessionType = "beacon"
	SessionTypeInteractive SessionType = "interactive"
)

// SessionState represents the state of a session
type SessionState string

const (
	SessionStateIdle      SessionState = "idle"
	SessionStateActive     SessionState = "active"
	SessionStateBackground SessionState = "background"
	SessionStateDead      SessionState = "dead"
)

// PrivilegeLevel represents the privilege level of a session
type PrivilegeLevel string

const (
	PrivilegeUser    PrivilegeLevel = "user"
	PrivilegeAdmin   PrivilegeLevel = "admin"
	PrivilegeSystem  PrivilegeLevel = "system"
	PrivilegeUnknown PrivilegeLevel = "unknown"
)

// Session represents a client session (beacon or interactive)
type Session struct {
	ID          string
	Type        SessionType
	State       SessionState
	RemoteAddr  string
	Transport   string
	ConnectedAt time.Time
	LastSeen    time.Time
	Metadata    map[string]interface{}
	
	// Beacon-specific fields
	BeaconInterval time.Duration
	BeaconJitter   float64
	
	// Interactive session fields
	IsInteractive bool
	ActiveCommand string
	
	// Privilege and user information
	Username      string
	PrivilegeLevel PrivilegeLevel
	
	mu sync.RWMutex
}

// NewSession creates a new session
func NewSession(id string, sessionType SessionType, transport string) *Session {
	return &Session{
		ID:            id,
		Type:          sessionType,
		State:         SessionStateActive,
		Transport:     transport,
		ConnectedAt:   time.Now(),
		LastSeen:      time.Now(),
		Metadata:      make(map[string]interface{}),
		BeaconInterval: 60 * time.Second,
		BeaconJitter:   0.3,
		IsInteractive:  sessionType == SessionTypeInteractive,
		PrivilegeLevel: PrivilegeUnknown,
		Username:       "",
	}
}

// GetID returns the session ID (thread-safe)
func (s *Session) GetID() string {
	// ID is immutable after creation, safe to read without lock
	return s.ID
}

// GetType returns the session type (thread-safe)
func (s *Session) GetType() SessionType {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Type
}

// GetTransport returns the transport type (thread-safe)
func (s *Session) GetTransport() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Transport
}

// GetRemoteAddr returns the remote address (thread-safe)
func (s *Session) GetRemoteAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RemoteAddr
}

// SetPrivilegeLevel sets the privilege level of the session
// Publishes SessionPrivilegeChanged event if level changed
func (s *Session) SetPrivilegeLevel(level PrivilegeLevel) {
	s.mu.Lock()
	oldLevel := s.PrivilegeLevel
	s.PrivilegeLevel = level
	s.mu.Unlock()

	// Publish event if level changed
	if oldLevel != level {
		EventBroker.Publish(Event{
			EventType: EventSessionPrivilegeChanged,
			Session:   s,
			Metadata: map[string]interface{}{
				"session_id":    s.GetID(), // Use getter for consistency
				"old_privilege": string(oldLevel),
				"new_privilege": string(level),
			},
		})
	}
}

// GetPrivilegeLevel returns the privilege level
func (s *Session) GetPrivilegeLevel() PrivilegeLevel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PrivilegeLevel
}

// SetUsername sets the username for the session
func (s *Session) SetUsername(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Username = username
}

// GetUsername returns the username
func (s *Session) GetUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Username
}

// UpdateLastSeen updates the last seen timestamp
func (s *Session) UpdateLastSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// SetState updates the session state
// Publishes SessionStateChanged event if state changed
func (s *Session) SetState(state SessionState) {
	s.mu.Lock()
	oldState := s.State
	s.State = state
	s.mu.Unlock()

	// Publish event if state changed
	if oldState != state {
		EventBroker.Publish(Event{
			EventType: EventSessionStateChanged,
			Session:   s,
			Metadata: map[string]interface{}{
				"session_id": s.GetID(), // Use getter for consistency
				"old_state":  string(oldState),
				"new_state":  string(state),
			},
		})
	}
}

// GetState returns the current state
func (s *Session) GetState() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// UpgradeToInteractive upgrades a beacon to an interactive session
func (s *Session) UpgradeToInteractive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Type = SessionTypeInteractive
	s.IsInteractive = true
	s.State = SessionStateActive
}

// SetMetadata sets a metadata value
func (s *Session) SetMetadata(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Metadata == nil {
		s.Metadata = make(map[string]interface{})
	}
	s.Metadata[key] = value
}

// GetMetadata retrieves a metadata value
func (s *Session) GetMetadata(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.Metadata[key]
	return value, ok
}

// SessionManager manages all sessions
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// AddSession adds a session and publishes SessionOpened event
func (sm *SessionManager) AddSession(session *Session) {
	if session == nil {
		return // Safety check
	}
	
	sm.mu.Lock()
	sm.sessions[session.ID] = session
	sm.mu.Unlock()

	// Read session fields with locks before publishing event
	session.mu.RLock()
	sessionID := session.ID
	sessionType := string(session.Type)
	transport := session.Transport
	remoteAddr := session.RemoteAddr
	session.mu.RUnlock()

	// Publish event (do this outside the lock to avoid deadlock)
	EventBroker.Publish(Event{
		EventType: EventSessionOpened,
		Session:   session,
		Metadata: map[string]interface{}{
			"session_id": sessionID,
			"type":       sessionType,
			"transport":  transport,
			"remote_addr": remoteAddr,
		},
	})
}

// GetSession retrieves a session by ID (supports partial matching)
func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Try exact match first
	if session, ok := sm.sessions[id]; ok {
		return session, ok
	}
	
	// Try partial match (for short IDs like Sliver/Empire)
	// Match sessions that start with the provided ID
	id = strings.ToLower(id)
	for sessionID, session := range sm.sessions {
		if strings.HasPrefix(strings.ToLower(sessionID), id) {
			return session, true
		}
	}
	
	return nil, false
}

// RemoveSession removes a session and publishes SessionClosed event
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	session, exists := sm.sessions[id]
	if exists {
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()

	// Publish event if session existed
	if exists {
		EventBroker.Publish(Event{
			EventType: EventSessionClosed,
			Session:   session,
			Metadata: map[string]interface{}{
				"session_id": id,
			},
		})
	}
}

// ListSessions returns all sessions
func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetBeacons returns all beacon sessions
func (sm *SessionManager) GetBeacons() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	beacons := make([]*Session, 0)
	for _, session := range sm.sessions {
		session.mu.RLock()
		isBeacon := session.Type == SessionTypeBeacon
		session.mu.RUnlock()
		if isBeacon {
			beacons = append(beacons, session)
		}
	}
	return beacons
}

// GetInteractiveSessions returns all interactive sessions
func (sm *SessionManager) GetInteractiveSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sessions := make([]*Session, 0)
	for _, session := range sm.sessions {
		session.mu.RLock()
		isInteractive := session.Type == SessionTypeInteractive
		session.mu.RUnlock()
		if isInteractive {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// CleanupDeadSessions removes sessions that haven't been seen in timeout duration
// Publishes SessionClosed events for cleaned up sessions
func (sm *SessionManager) CleanupDeadSessions(timeout time.Duration) {
	sm.mu.Lock()
	
	now := time.Now()
	deadSessions := make([]*Session, 0)
	for id, session := range sm.sessions {
		session.mu.RLock()
		lastSeen := session.LastSeen
		session.mu.RUnlock()
		
		if now.Sub(lastSeen) > timeout {
			// Don't call SetState here as it will publish EventSessionStateChanged
			// We'll just mark it dead and publish SessionClosed event
			session.mu.Lock()
			session.State = SessionStateDead
			session.mu.Unlock()
			deadSessions = append(deadSessions, session)
			delete(sm.sessions, id)
		}
	}
	sm.mu.Unlock()

	// Publish events for dead sessions (outside the lock)
	for _, session := range deadSessions {
		EventBroker.Publish(Event{
			EventType: EventSessionClosed,
			Session:   session,
			Metadata: map[string]interface{}{
				"session_id": session.GetID(), // Use getter for thread safety
				"reason":     "timeout",
			},
		})
	}
}

