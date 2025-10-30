package tasks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewQueue(t *testing.T) {
	queue := NewQueue(100)
	
	require.NotNil(t, queue)
	assert.NotNil(t, queue.tasks)
	assert.Equal(t, 100, queue.maxSize)
	assert.Len(t, queue.tasks, 0)
}

func TestQueue_Add(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{
		ID:      "test-id",
		Type:    "command",
		Command: "whoami",
	}
	
	err := queue.Add(task)
	
	require.NoError(t, err)
	assert.Len(t, queue.tasks, 1)
	assert.Equal(t, "pending", task.Status)
	assert.NotZero(t, task.CreatedAt)
}

func TestQueue_Add_Full(t *testing.T) {
	queue := NewQueue(2)
	
	task1 := &Task{ID: "1"}
	task2 := &Task{ID: "2"}
	task3 := &Task{ID: "3"}
	
	err1 := queue.Add(task1)
	err2 := queue.Add(task2)
	err3 := queue.Add(task3)
	
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Error(t, err3)
	assert.Equal(t, ErrQueueFull, err3)
	assert.Len(t, queue.tasks, 2)
}

func TestQueue_Get(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{
		ID:     "test-id",
		Type:   "command",
		Status: "pending",
	}
	queue.Add(task)
	
	retrieved := queue.Get("test-id")
	
	require.NotNil(t, retrieved)
	assert.Equal(t, task, retrieved)
}

func TestQueue_Get_NotExists(t *testing.T) {
	queue := NewQueue(10)
	
	retrieved := queue.Get("nonexistent")
	
	assert.Nil(t, retrieved)
}

func TestQueue_GetPending(t *testing.T) {
	queue := NewQueue(10)
	
	task1 := &Task{ID: "1"}
	task2 := &Task{ID: "2"}
	task3 := &Task{ID: "3"}
	
	queue.Add(task1)
	queue.Add(task2)
	queue.Add(task3)
	
	// Mark task2 as completed
	queue.UpdateStatus("2", "completed")
	
	pending := queue.GetPending()
	
	assert.Len(t, pending, 2)
	for _, task := range pending {
		assert.Equal(t, "pending", task.Status)
		assert.NotEqual(t, "2", task.ID)
	}
}

func TestQueue_UpdateStatus(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{ID: "test-id", Status: "pending"}
	queue.Add(task)
	
	queue.UpdateStatus("test-id", "running")
	
	updated := queue.Get("test-id")
	assert.Equal(t, "running", updated.Status)
}

func TestQueue_UpdateStatus_NotExists(t *testing.T) {
	queue := NewQueue(10)
	
	// Should not panic
	queue.UpdateStatus("nonexistent", "running")
}

func TestQueue_SetResult(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{ID: "test-id", Status: "pending"}
	queue.Add(task)
	
	result := "test result"
	queue.SetResult("test-id", result)
	
	updated := queue.Get("test-id")
	assert.Equal(t, result, updated.Result)
	assert.Equal(t, "completed", updated.Status)
}

func TestQueue_Remove(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{ID: "test-id"}
	queue.Add(task)
	
	queue.Remove("test-id")
	
	assert.Nil(t, queue.Get("test-id"))
	assert.Len(t, queue.tasks, 0)
}

func TestQueue_Remove_NotExists(t *testing.T) {
	queue := NewQueue(10)
	
	// Should not panic
	queue.Remove("nonexistent")
}

func TestQueue_Concurrent(t *testing.T) {
	queue := NewQueue(1000)
	done := make(chan bool)
	
	// Concurrent adds
	for i := 0; i < 100; i++ {
		go func(id int) {
			task := &Task{ID: string(rune(id))}
			queue.Add(task)
			done <- true
		}(i)
	}
	
	// Wait for all adds
	for i := 0; i < 100; i++ {
		<-done
	}
	
	assert.Len(t, queue.tasks, 100)
}

func TestQueue_ConcurrentGetSet(t *testing.T) {
	queue := NewQueue(100)
	task := &Task{ID: "test-id", Status: "pending"}
	queue.Add(task)
	
	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func() {
			queue.Get("test-id")
			queue.UpdateStatus("test-id", "running")
			queue.SetResult("test-id", "result")
			done <- true
		}()
	}
	
	for i := 0; i < 50; i++ {
		<-done
	}
	
	// Should not panic
	retrieved := queue.Get("test-id")
	assert.NotNil(t, retrieved)
}

func TestTask_CreatedAt(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{ID: "test-id"}
	
	before := time.Now()
	queue.Add(task)
	after := time.Now()
	
	assert.True(t, task.CreatedAt.After(before) || task.CreatedAt.Equal(before))
	assert.True(t, task.CreatedAt.Before(after) || task.CreatedAt.Equal(after))
}

func TestTask_Retries(t *testing.T) {
	queue := NewQueue(10)
	task := &Task{
		ID:         "test-id",
		Retries:    0,
		MaxRetries: 3,
	}
	queue.Add(task)
	
	updated := queue.Get("test-id")
	assert.Equal(t, 0, updated.Retries)
	assert.Equal(t, 3, updated.MaxRetries)
}

func TestQueue_Clear(t *testing.T) {
	queue := NewQueue(10)
	queue.Add(&Task{ID: "1"})
	queue.Add(&Task{ID: "2"})
	
	queue.Clear()
	
	assert.Len(t, queue.tasks, 0)
}

func TestQueue_Size(t *testing.T) {
	queue := NewQueue(10)
	queue.Add(&Task{ID: "1"})
	queue.Add(&Task{ID: "2"})
	
	size := queue.Size()
	assert.Equal(t, 2, size)
}

func TestQueue_IsEmpty(t *testing.T) {
	queue := NewQueue(10)
	assert.Equal(t, 0, queue.Size())
	
	queue.Add(&Task{ID: "1"})
	assert.Equal(t, 1, queue.Size())
}

