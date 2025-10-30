package reactions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewReactionManager(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	require.NotNil(t, rm)
	assert.NotNil(t, rm.reactions)
	assert.Equal(t, logger, rm.logger)
}

func TestReactionManager_AddReaction(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Condition: func(data map[string]interface{}) bool {
			return true
		},
		Action: func(data map[string]interface{}) error {
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	// Should be stored
	assert.Len(t, rm.reactions, 1)
}

func TestReactionManager_TriggerEvent_WithCondition(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	triggered := false
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Condition: func(data map[string]interface{}) bool {
			return data["os"] == "windows"
		},
		Action: func(data map[string]interface{}) error {
			triggered = true
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	data := map[string]interface{}{"os": "windows"}
	err := rm.TriggerEvent(EventTypeSessionNew, data)
	
	require.NoError(t, err)
	assert.True(t, triggered)
}

func TestReactionManager_TriggerEvent_ConditionFalse(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	triggered := false
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Condition: func(data map[string]interface{}) bool {
			return data["os"] == "windows"
		},
		Action: func(data map[string]interface{}) error {
			triggered = true
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	data := map[string]interface{}{"os": "linux"}
	err := rm.TriggerEvent(EventTypeSessionNew, data)
	
	require.NoError(t, err)
	assert.False(t, triggered)
}

func TestReactionManager_TriggerEvent_NoCondition(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	triggered := false
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Condition: nil,
		Action: func(data map[string]interface{}) error {
			triggered = true
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	err := rm.TriggerEvent(EventTypeSessionNew, map[string]interface{}{})
	
	require.NoError(t, err)
	assert.True(t, triggered)
}

func TestReactionManager_TriggerEvent_Disabled(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	triggered := false
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   false,
		Action: func(data map[string]interface{}) error {
			triggered = true
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	err := rm.TriggerEvent(EventTypeSessionNew, map[string]interface{}{})
	
	require.NoError(t, err)
	assert.False(t, triggered)
}

func TestReactionManager_TriggerEvent_WrongEventType(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	triggered := false
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Action: func(data map[string]interface{}) error {
			triggered = true
			return nil
		},
	}
	
	rm.AddReaction(reaction)
	
	err := rm.TriggerEvent(EventTypeSessionDead, map[string]interface{}{})
	
	require.NoError(t, err)
	assert.False(t, triggered)
}

func TestReactionManager_TriggerEvent_ActionError(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	reaction := &Reaction{
		ID:        "react-1",
		EventType: EventTypeSessionNew,
		Enabled:   true,
		Action: func(data map[string]interface{}) error {
			return assert.AnError
		},
	}
	
	rm.AddReaction(reaction)
	
	err := rm.TriggerEvent(EventTypeSessionNew, map[string]interface{}{})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "react-1 failed")
}

func TestReactionManager_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReactionManager(logger)
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			reaction := &Reaction{
				ID:        string(rune(id)),
				EventType: EventTypeSessionNew,
				Enabled:   true,
				Action: func(data map[string]interface{}) error {
					return nil
				},
			}
			rm.AddReaction(reaction)
			rm.TriggerEvent(EventTypeSessionNew, map[string]interface{}{})
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, rm.reactions)
}

