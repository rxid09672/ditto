package core

/*
	Event-Driven Architecture for Ditto
	Implements a pub/sub EventBroker pattern for decoupled component communication
*/

import (
	"time"
)

const (
	// eventBufSize - Buffer size for event channels to avoid blocking
	eventBufSize = 100
)

// EventType represents the type of event
type EventType string

const (
	// Session Events
	EventSessionOpened           EventType = "session_opened"
	EventSessionClosed           EventType = "session_closed"
	EventSessionKilled           EventType = "session_killed"
	EventSessionPrivilegeChanged EventType = "session_privilege_changed"
	EventSessionStateChanged     EventType = "session_state_changed"

	// Task Events
	EventTaskQueued    EventType = "task_queued"
	EventTaskStarted   EventType = "task_started"
	EventTaskCompleted EventType = "task_completed"
	EventTaskFailed    EventType = "task_failed"

	// Job Events
	EventJobStarted EventType = "job_started"
	EventJobStopped EventType = "job_stopped"
	EventJobFailed  EventType = "job_failed"

	// Loot Events
	EventLootAdded   EventType = "loot_added"
	EventLootRemoved EventType = "loot_removed"
	EventLootUpdated EventType = "loot_updated"

	// Module Events
	EventModuleExecuted EventType = "module_executed"
	EventModuleFailed   EventType = "module_failed"

	// Privilege Escalation Events
	EventPrivilegeEscalated       EventType = "privilege_escalated"
	EventPrivilegeEscalationFailed EventType = "privilege_escalation_failed"

	// System Events
	EventServerStarted      EventType = "server_started"
	EventServerStopped      EventType = "server_stopped"
	EventListenerStarted    EventType = "listener_started"
	EventListenerStopped    EventType = "listener_stopped"
)

// Event represents a system event
// Events are published when state changes occur in the system
type Event struct {
	// EventType - The type of event (e.g., EventSessionOpened)
	EventType EventType

	// Timestamp - When the event occurred
	Timestamp time.Time

	// Session - Associated session (if applicable)
	Session *Session

	// Job - Associated job (if applicable)
	Job interface{} // *jobs.Job (avoid circular import)

	// Task - Associated task (if applicable)
	Task interface{} // *tasks.Task (avoid circular import)

	// Data - Additional event data (arbitrary bytes)
	Data []byte

	// Metadata - Additional event metadata (key-value pairs)
	Metadata map[string]interface{}

	// Err - Error (if event represents a failure)
	Err error
}

// eventBroker implements the pub/sub pattern for events
type eventBroker struct {
	stop        chan struct{}
	publish     chan Event
	subscribe   chan chan Event
	unsubscribe chan chan Event
}

// Start starts the event broker goroutine
func (broker *eventBroker) Start() {
	subscribers := map[chan Event]struct{}{}
	for {
		select {
		case <-broker.stop:
			// Stop all subscribers
			for sub := range subscribers {
				close(sub)
			}
			return
		case sub := <-broker.subscribe:
			subscribers[sub] = struct{}{}
		case sub := <-broker.unsubscribe:
			// Check if subscriber exists before closing
			// This prevents double-closing if Stop() already closed it
			if _, exists := subscribers[sub]; exists {
				delete(subscribers, sub)
				// Safe to close - if already closed by Stop(), this will panic
				// but that's a programming error that should be caught
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Channel already closed, ignore panic
						}
					}()
					close(sub)
				}()
			}
		case event := <-broker.publish:
			// Ensure timestamp is set
			if event.Timestamp.IsZero() {
				event.Timestamp = time.Now()
			}
			// Broadcast to all subscribers
			for sub := range subscribers {
				select {
				case sub <- event:
					// Event sent successfully
				default:
					// Subscriber channel full, skip (non-blocking)
					// This prevents blocking if a subscriber is slow
				}
			}
		}
	}
}

// Stop stops the event broker
// This should only be called during application shutdown
func (broker *eventBroker) Stop() {
	// Don't close the stop channel if it's already closed
	select {
	case <-broker.stop:
		// Already closed
		return
	default:
		close(broker.stop)
	}
}

// Subscribe creates a new subscription channel
// Subscribers should call Unsubscribe when done
// Returns nil if broker is stopped
func (broker *eventBroker) Subscribe() chan Event {
	events := make(chan Event, eventBufSize)
	select {
	case broker.subscribe <- events:
		// Successfully subscribed
		return events
	case <-broker.stop:
		// Broker stopped, return nil
		return nil
	default:
		// Channel full - broker might be busy, try non-blocking
		select {
		case broker.subscribe <- events:
			return events
		case <-broker.stop:
			return nil
		default:
			// Both channels full - return nil (shouldn't happen normally)
			return nil
		}
	}
}

// Unsubscribe removes a subscription channel
// Non-blocking - if broker is stopped or events is nil, this is a no-op
func (broker *eventBroker) Unsubscribe(events chan Event) {
	if events == nil {
		return // Nothing to unsubscribe
	}
	select {
	case broker.unsubscribe <- events:
		// Successfully queued unsubscribe
	case <-broker.stop:
		// Broker stopped, channel will be closed by broker
		return
	default:
		// Channel full - broker might be busy, but this is non-critical
		// The broker will close channels on stop anyway
	}
}

// Publish publishes an event to all subscribers
// This is non-blocking - if subscribers are slow, events may be dropped
func (broker *eventBroker) Publish(event Event) {
	// Ensure timestamp is set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	// Ensure metadata is initialized
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}
	select {
	case broker.publish <- event:
		// Event published successfully
	default:
		// Publish channel full - this shouldn't happen in normal operation
		// but we handle it gracefully to avoid blocking
	}
}

// newBroker creates a new event broker
func newBroker() *eventBroker {
	broker := &eventBroker{
		stop:        make(chan struct{}),
		publish:     make(chan Event, eventBufSize),
		subscribe:   make(chan chan Event, eventBufSize),
		unsubscribe: make(chan chan Event, eventBufSize),
	}
	go broker.Start()
	return broker
}

var (
	// EventBroker - Global event broker instance
	// Components publish events here and subscribe to events they care about
	EventBroker = newBroker()
)

