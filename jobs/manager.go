package jobs

import (
	"fmt"
	"sync"
	"time"
)

// JobType represents the type of job
type JobType string

const (
	JobTypePortForward JobType = "portforward"
	JobTypeSOCKS5      JobType = "socks5"
	JobTypeListener    JobType = "listener"
)

// JobStatus represents job status
type JobStatus string

const (
	JobStatusRunning JobStatus = "running"
	JobStatusStopped JobStatus = "stopped"
	JobStatusError   JobStatus = "error"
)

// Job represents a background job
type Job struct {
	ID        uint64
	Type      JobType
	Name      string
	Status    JobStatus
	CreatedAt time.Time
	Metadata  map[string]interface{}
	StopFunc  func() error
}

// JobManager manages background jobs
type JobManager struct {
	jobs   map[uint64]*Job
	nextID uint64
	mu     sync.RWMutex
}

// NewJobManager creates a new job manager
func NewJobManager() *JobManager {
	return &JobManager{
		jobs:   make(map[uint64]*Job),
		nextID: 1,
	}
}

// AddJob adds a new job
func (jm *JobManager) AddJob(jobType JobType, name string, stopFunc func() error) *Job {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	
	id := jm.nextID
	jm.nextID++
	
	job := &Job{
		ID:        id,
		Type:      jobType,
		Name:      name,
		Status:    JobStatusRunning,
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
		StopFunc:  stopFunc,
	}
	
	jm.jobs[id] = job
	return job
}

// StopJob stops a job
func (jm *JobManager) StopJob(id uint64) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	
	job, ok := jm.jobs[id]
	if !ok {
		return fmt.Errorf("job not found: %d", id)
	}
	
	if job.StopFunc != nil {
		if err := job.StopFunc(); err != nil {
			job.Status = JobStatusError
			return err
		}
	}
	
	job.Status = JobStatusStopped
	delete(jm.jobs, id)
	return nil
}

// ListJobs lists all jobs
func (jm *JobManager) ListJobs() []*Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	
	jobs := make([]*Job, 0, len(jm.jobs))
	for _, job := range jm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

