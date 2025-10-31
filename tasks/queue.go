package tasks

import (
	"sync"
	"time"
)

// Task represents a task to be executed
type Task struct {
	ID          string
	Type        string
	Command     string
	Parameters  map[string]interface{}
	CreatedAt   time.Time
	Status      string
	Result      interface{}
	Retries     int
	MaxRetries  int
}

// Queue manages task queue
type Queue struct {
	tasks   []*Task
	mu      sync.RWMutex
	maxSize int
}

// NewQueue creates a new task queue
func NewQueue(maxSize int) *Queue {
	return &Queue{
		tasks:   make([]*Task, 0),
		maxSize: maxSize,
	}
}

// Add adds a task to the queue
func (q *Queue) Add(task *Task) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	
	if len(q.tasks) >= q.maxSize {
		return ErrQueueFull
	}
	
	task.CreatedAt = time.Now()
	task.Status = "pending"
	q.tasks = append(q.tasks, task)
	return nil
}

// Get retrieves a task by ID
func (q *Queue) Get(id string) *Task {
	q.mu.RLock()
	defer q.mu.RUnlock()
	
	for _, task := range q.tasks {
		if task.ID == id {
			return task
		}
	}
	return nil
}

// GetPending retrieves all pending tasks
func (q *Queue) GetPending() []*Task {
	q.mu.RLock()
	defer q.mu.RUnlock()
	
	pending := make([]*Task, 0)
	for _, task := range q.tasks {
		if task.Status == "pending" {
			pending = append(pending, task)
		}
	}
	return pending
}

// GetAll retrieves all tasks
func (q *Queue) GetAll() []*Task {
	q.mu.RLock()
	defer q.mu.RUnlock()
	
	allTasks := make([]*Task, len(q.tasks))
	copy(allTasks, q.tasks)
	return allTasks
}

// UpdateStatus updates task status
func (q *Queue) UpdateStatus(id, status string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	
	for _, task := range q.tasks {
		if task.ID == id {
			task.Status = status
			break
		}
	}
}

// SetResult sets task result
func (q *Queue) SetResult(id string, result interface{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	
	for _, task := range q.tasks {
		if task.ID == id {
			task.Result = result
			task.Status = "completed"
			break
		}
	}
}

// Remove removes a task from queue
func (q *Queue) Remove(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	
	for i, task := range q.tasks {
		if task.ID == id {
			q.tasks = append(q.tasks[:i], q.tasks[i+1:]...)
			break
		}
	}
}

// Size returns queue size
func (q *Queue) Size() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.tasks)
}

// Clear clears all tasks
func (q *Queue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.tasks = make([]*Task, 0)
}

var ErrQueueFull = &QueueError{Message: "queue is full"}

type QueueError struct {
	Message string
}

func (e *QueueError) Error() string {
	return e.Message
}

