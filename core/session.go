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
	
	mu sync.RWMutex
}

// NewSession creates a new session
func NewSession(id string, sessionType SessionType, transport string) *Session {
	return &Session{
		ID:          id,
		Type:        sessionType,
		State:       SessionStateActive,
		Transport:   transport,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
		Metadata:    make(map[string]interface{}),
		BeaconInterval: 60 * time.Second,
		BeaconJitter:   0.3,
		IsInteractive: sessionType == SessionTypeInteractive,
	}
}

// UpdateLastSeen updates the last seen timestamp
func (s *Session) UpdateLastSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// SetState updates the session state
func (s *Session) SetState(state SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = state
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

// AddSession adds a session
func (sm *SessionManager) AddSession(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.ID] = session
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

// RemoveSession removes a session
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
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
		if session.Type == SessionTypeBeacon {
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
		if session.Type == SessionTypeInteractive {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// CleanupDeadSessions removes sessions that haven't been seen in timeout duration
func (sm *SessionManager) CleanupDeadSessions(timeout time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	now := time.Now()
	for id, session := range sm.sessions {
		if now.Sub(session.LastSeen) > timeout {
			session.SetState(SessionStateDead)
			delete(sm.sessions, id)
		}
	}
}

