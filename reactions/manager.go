package reactions

import (
	"fmt"
	"sync"
)

// EventType represents event types
type EventType string

const (
	EventTypeSessionNew  EventType = "session_new"
	EventTypeSessionDead EventType = "session_dead"
)

// Reaction represents an automated reaction
type Reaction struct {
	ID        string
	EventType EventType
	Condition func(map[string]interface{}) bool
	Action    func(map[string]interface{}) error
	Enabled   bool
}

// ReactionManager manages automated reactions
type ReactionManager struct {
	reactions map[string]*Reaction
	mu        sync.RWMutex
	logger    interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewReactionManager creates a new reaction manager
func NewReactionManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ReactionManager {
	return &ReactionManager{
		reactions: make(map[string]*Reaction),
		logger:    logger,
	}
}

// AddReaction adds a reaction
func (rm *ReactionManager) AddReaction(reaction *Reaction) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.reactions[reaction.ID] = reaction
	rm.logger.Info("Added reaction: %s", reaction.ID)
}

// TriggerEvent triggers an event
func (rm *ReactionManager) TriggerEvent(eventType EventType, data map[string]interface{}) error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	for _, reaction := range rm.reactions {
		if reaction.EventType == eventType && reaction.Enabled {
			if reaction.Condition == nil || reaction.Condition(data) {
				if err := reaction.Action(data); err != nil {
					return fmt.Errorf("reaction %s failed: %w", reaction.ID, err)
				}
			}
		}
	}
	return nil
}

