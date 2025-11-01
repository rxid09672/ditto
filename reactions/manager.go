package reactions

import (
	"fmt"
	"sync"

	"github.com/ditto/ditto/core"
)

// EventType represents event types (keeping for backward compatibility)
// These map to core.EventType values
type EventType string

const (
	EventTypeSessionNew  EventType = "session_new"  // Maps to core.EventSessionOpened
	EventTypeSessionDead EventType = "session_dead"  // Maps to core.EventSessionClosed
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
// Now subscribes to core.EventBroker for event-driven automation
type ReactionManager struct {
	reactions map[string]*Reaction
	mu        sync.RWMutex
	logger    interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	stop chan struct{}
}

// NewReactionManager creates a new reaction manager
// Automatically subscribes to EventBroker for event-driven reactions
func NewReactionManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *ReactionManager {
	rm := &ReactionManager{
		reactions: make(map[string]*Reaction),
		logger:    logger,
		stop:      make(chan struct{}),
	}

	// Subscribe to EventBroker
	rm.startEventSubscription()

	return rm
}

// startEventSubscription subscribes to EventBroker and processes events
func (rm *ReactionManager) startEventSubscription() {
	events := core.EventBroker.Subscribe()
	if events == nil {
		// Broker stopped or unavailable
		rm.logger.Error("Failed to subscribe to EventBroker")
		return
	}
	go func() {
		defer func() {
			if events != nil {
				core.EventBroker.Unsubscribe(events)
			}
		}()
		for {
			select {
			case <-rm.stop:
				return
			case event, ok := <-events:
				if !ok {
					// Channel closed
					return
				}
				rm.handleEvent(event)
			}
		}
	}()
}

// handleEvent processes events from EventBroker
func (rm *ReactionManager) handleEvent(event core.Event) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Map core.EventType to reactions.EventType
	var reactionEventType EventType
	switch event.EventType {
	case core.EventSessionOpened:
		reactionEventType = EventTypeSessionNew
	case core.EventSessionClosed, core.EventSessionKilled:
		reactionEventType = EventTypeSessionDead
	case core.EventSessionPrivilegeChanged:
		// Handle privilege escalation reactions
		// Note: We don't have a specific reaction event type for privilege changes yet
		// For now, we'll just log it - can be extended later with a new EventTypePrivilegeChanged
		if event.Session != nil {
			// Use getter methods for thread safety (ID is immutable)
			sessionID := event.Session.GetID()
			
			oldPriv, oldOk := event.Metadata["old_privilege"].(string)
			newPriv, newOk := event.Metadata["new_privilege"].(string)
			if oldOk && newOk && oldPriv != newPriv {
				// Log privilege change for debugging
				rm.logger.Debug("Privilege changed for session %s: %s -> %s", 
					sessionID, oldPriv, newPriv)
			}
		}
		return
	default:
		// Only handle session events for now
		return
	}

	// Build data map for reactions
	data := make(map[string]interface{})
	if event.Session != nil {
		// Use getter methods for thread safety
		sessionID := event.Session.GetID()
		sessionType := string(event.Session.GetType())
		transport := event.Session.GetTransport()
		remoteAddr := event.Session.GetRemoteAddr()
		
		data["session"] = event.Session
		data["session_id"] = sessionID
		data["type"] = sessionType
		data["transport"] = transport
		data["remote_addr"] = remoteAddr
	}
	// Merge metadata (metadata is already a copy from event creation, safe to iterate)
	for k, v := range event.Metadata {
		data[k] = v
	}

	rm.triggerReactions(reactionEventType, data)
}

// triggerReactions triggers reactions matching the event type
func (rm *ReactionManager) triggerReactions(eventType EventType, data map[string]interface{}) {
	for _, reaction := range rm.reactions {
		if reaction.EventType == eventType && reaction.Enabled {
			if reaction.Condition == nil || reaction.Condition(data) {
				if err := reaction.Action(data); err != nil {
					rm.logger.Error("Reaction %s failed: %v", reaction.ID, err)
				} else {
					rm.logger.Debug("Reaction %s executed successfully", reaction.ID)
				}
			}
		}
	}
}

// AddReaction adds a reaction
func (rm *ReactionManager) AddReaction(reaction *Reaction) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.reactions[reaction.ID] = reaction
	rm.logger.Info("Added reaction: %s", reaction.ID)
}

// RemoveReaction removes a reaction
func (rm *ReactionManager) RemoveReaction(id string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.reactions, id)
	rm.logger.Info("Removed reaction: %s", id)
}

// ListReactions returns all reactions
func (rm *ReactionManager) ListReactions() []*Reaction {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	reactions := make([]*Reaction, 0, len(rm.reactions))
	for _, reaction := range rm.reactions {
		reactions = append(reactions, reaction)
	}
	return reactions
}

// TriggerEvent triggers an event (backward compatibility)
// This is now deprecated - events come from EventBroker automatically
// Returns error if any reaction fails (for backward compatibility with tests)
func (rm *ReactionManager) TriggerEvent(eventType EventType, data map[string]interface{}) error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var lastErr error
	for _, reaction := range rm.reactions {
		if reaction.EventType == eventType && reaction.Enabled {
			if reaction.Condition == nil || reaction.Condition(data) {
				if err := reaction.Action(data); err != nil {
					rm.logger.Error("Reaction %s failed: %v", reaction.ID, err)
					lastErr = fmt.Errorf("reaction %s failed: %w", reaction.ID, err)
				}
			}
		}
	}
	return lastErr
}

// Stop stops the reaction manager and unsubscribes from events
// Safe to call multiple times
func (rm *ReactionManager) Stop() {
	// Use select to avoid panic if channel is already closed
	select {
	case <-rm.stop:
		// Already closed
		return
	default:
		close(rm.stop)
	}
}


