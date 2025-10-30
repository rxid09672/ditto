package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	require.NotNil(t, session)
	assert.Equal(t, "test-id", session.ID)
	assert.Equal(t, SessionTypeBeacon, session.Type)
	assert.Equal(t, SessionStateActive, session.State)
	assert.Equal(t, "http", session.Transport)
	assert.False(t, session.IsInteractive)
	assert.NotZero(t, session.ConnectedAt)
	assert.NotZero(t, session.LastSeen)
	assert.Equal(t, 60*time.Second, session.BeaconInterval)
	assert.Equal(t, 0.3, session.BeaconJitter)
}

func TestNewSession_Interactive(t *testing.T) {
	session := NewSession("test-id", SessionTypeInteractive, "https")
	
	assert.Equal(t, SessionTypeInteractive, session.Type)
	assert.True(t, session.IsInteractive)
}

func TestSession_UpdateLastSeen(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	oldLastSeen := session.LastSeen
	
	time.Sleep(10 * time.Millisecond)
	session.UpdateLastSeen()
	
	assert.True(t, session.LastSeen.After(oldLastSeen))
}

func TestSession_SetState(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	session.SetState(SessionStateIdle)
	assert.Equal(t, SessionStateIdle, session.GetState())
	
	session.SetState(SessionStateActive)
	assert.Equal(t, SessionStateActive, session.GetState())
	
	session.SetState(SessionStateBackground)
	assert.Equal(t, SessionStateBackground, session.GetState())
	
	session.SetState(SessionStateDead)
	assert.Equal(t, SessionStateDead, session.GetState())
}

func TestSession_GetState(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	assert.Equal(t, SessionStateActive, session.GetState())
	
	session.SetState(SessionStateIdle)
	assert.Equal(t, SessionStateIdle, session.GetState())
}

func TestSession_UpgradeToInteractive(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	session.UpgradeToInteractive()
	
	assert.Equal(t, SessionTypeInteractive, session.Type)
	assert.True(t, session.IsInteractive)
	assert.Equal(t, SessionStateActive, session.State)
}

func TestSession_SetMetadata(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	session.SetMetadata("key1", "value1")
	session.SetMetadata("key2", 123)
	session.SetMetadata("key3", true)
	
	val1, ok := session.GetMetadata("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val1)
	
	val2, ok := session.GetMetadata("key2")
	assert.True(t, ok)
	assert.Equal(t, 123, val2)
	
	val3, ok := session.GetMetadata("key3")
	assert.True(t, ok)
	assert.Equal(t, true, val3)
}

func TestSession_GetMetadata_NotExists(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	val, ok := session.GetMetadata("nonexistent")
	
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSession_GetMetadata_Overwrite(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	session.SetMetadata("key", "value1")
	session.SetMetadata("key", "value2")
	
	val, ok := session.GetMetadata("key")
	assert.True(t, ok)
	assert.Equal(t, "value2", val)
}

func TestNewSessionManager(t *testing.T) {
	sm := NewSessionManager()
	
	require.NotNil(t, sm)
	assert.NotNil(t, sm.sessions)
}

func TestSessionManager_AddSession(t *testing.T) {
	sm := NewSessionManager()
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	sm.AddSession(session)
	
	retrieved, ok := sm.GetSession("test-id")
	assert.True(t, ok)
	assert.Equal(t, session, retrieved)
}

func TestSessionManager_GetSession_Exists(t *testing.T) {
	sm := NewSessionManager()
	session := NewSession("test-id", SessionTypeBeacon, "http")
	sm.AddSession(session)
	
	retrieved, ok := sm.GetSession("test-id")
	
	assert.True(t, ok)
	assert.Equal(t, session, retrieved)
}

func TestSessionManager_GetSession_NotExists(t *testing.T) {
	sm := NewSessionManager()
	
	_, ok := sm.GetSession("nonexistent")
	
	assert.False(t, ok)
}

func TestSessionManager_RemoveSession(t *testing.T) {
	sm := NewSessionManager()
	session := NewSession("test-id", SessionTypeBeacon, "http")
	sm.AddSession(session)
	
	sm.RemoveSession("test-id")
	
	_, ok := sm.GetSession("test-id")
	assert.False(t, ok)
}

func TestSessionManager_RemoveSession_NotExists(t *testing.T) {
	sm := NewSessionManager()
	
	// Should not panic
	sm.RemoveSession("nonexistent")
}

func TestSessionManager_ListSessions(t *testing.T) {
	sm := NewSessionManager()
	
	session1 := NewSession("id1", SessionTypeBeacon, "http")
	session2 := NewSession("id2", SessionTypeInteractive, "https")
	session3 := NewSession("id3", SessionTypeBeacon, "http")
	
	sm.AddSession(session1)
	sm.AddSession(session2)
	sm.AddSession(session3)
	
	sessions := sm.ListSessions()
	
	assert.Len(t, sessions, 3)
}

func TestSessionManager_ListSessions_Empty(t *testing.T) {
	sm := NewSessionManager()
	
	sessions := sm.ListSessions()
	
	assert.Len(t, sessions, 0)
}

func TestSessionManager_GetBeacons(t *testing.T) {
	sm := NewSessionManager()
	
	session1 := NewSession("id1", SessionTypeBeacon, "http")
	session2 := NewSession("id2", SessionTypeInteractive, "https")
	session3 := NewSession("id3", SessionTypeBeacon, "http")
	
	sm.AddSession(session1)
	sm.AddSession(session2)
	sm.AddSession(session3)
	
	beacons := sm.GetBeacons()
	
	assert.Len(t, beacons, 2)
	for _, beacon := range beacons {
		assert.Equal(t, SessionTypeBeacon, beacon.Type)
	}
}

func TestSessionManager_GetInteractiveSessions(t *testing.T) {
	sm := NewSessionManager()
	
	session1 := NewSession("id1", SessionTypeBeacon, "http")
	session2 := NewSession("id2", SessionTypeInteractive, "https")
	session3 := NewSession("id3", SessionTypeBeacon, "http")
	
	sm.AddSession(session1)
	sm.AddSession(session2)
	sm.AddSession(session3)
	
	interactive := sm.GetInteractiveSessions()
	
	assert.Len(t, interactive, 1)
	assert.Equal(t, SessionTypeInteractive, interactive[0].Type)
}

func TestSessionManager_CleanupDeadSessions(t *testing.T) {
	sm := NewSessionManager()
	
	session1 := NewSession("id1", SessionTypeBeacon, "http")
	session2 := NewSession("id2", SessionTypeBeacon, "http")
	
	sm.AddSession(session1)
	sm.AddSession(session2)
	
	// Make session2 old
	session2.SetState(SessionStateDead)
	session2.mu.Lock()
	session2.LastSeen = time.Now().Add(-10 * time.Minute)
	session2.mu.Unlock()
	
	sm.CleanupDeadSessions(5 * time.Minute)
	
	_, ok1 := sm.GetSession("id1")
	_, ok2 := sm.GetSession("id2")
	
	assert.True(t, ok1)
	assert.False(t, ok2) // Should be cleaned up
}

func TestSessionManager_Concurrent(t *testing.T) {
	sm := NewSessionManager()
	
	// Concurrent adds
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			session := NewSession(string(rune(id)), SessionTypeBeacon, "http")
			sm.AddSession(session)
			done <- true
		}(i)
	}
	
	// Wait for all adds
	for i := 0; i < 100; i++ {
		<-done
	}
	
	sessions := sm.ListSessions()
	assert.Len(t, sessions, 100)
}

func TestSession_ConcurrentAccess(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	// Concurrent metadata access
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			session.SetMetadata("key", id)
			session.GetMetadata("key")
			session.UpdateLastSeen()
			session.SetState(SessionStateActive)
			done <- true
		}(i)
	}
	
	// Wait for all operations
	for i := 0; i < 100; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, session)
}

func TestSession_SetMetadata_NilInitialization(t *testing.T) {
	session := NewSession("test-id", SessionTypeBeacon, "http")
	
	// Set metadata before accessing - tests nil map initialization
	session.mu.Lock()
	session.Metadata = nil
	session.mu.Unlock()
	
	// This should initialize the map
	session.SetMetadata("key1", "value1")
	
	val, ok := session.GetMetadata("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

