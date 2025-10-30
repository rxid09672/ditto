package jobs

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ditto/ditto/database"
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
	return NewJobManagerWithRestore(true)
}

// NewJobManagerWithRestore creates a new job manager with optional restore
func NewJobManagerWithRestore(restore bool) *JobManager {
	jm := &JobManager{
		jobs:   make(map[uint64]*Job),
		nextID: 1,
	}
	
	if restore {
		// Restore jobs from database
		jm.restoreJobs()
	}
	
	return jm
}

// restoreJobs restores jobs from database on startup
func (jm *JobManager) restoreJobs() {
	dbJobs, err := database.GetJobs()
	if err != nil {
		// Database might not exist yet, that's okay
		return
	}
	
	jm.mu.Lock()
	defer jm.mu.Unlock()
	
	for _, dbJob := range dbJobs {
		if dbJob.Status == "running" {
			// Job was running, restore it (but mark as stopped since we can't restore StopFunc)
			job := &Job{
				ID:        dbJob.ID,
				Type:      JobType(dbJob.Type),
				Name:      dbJob.Name,
				Status:    JobStatusStopped, // Can't restore running state
				CreatedAt: time.Unix(dbJob.CreatedAt, 0),
				Metadata:  make(map[string]interface{}),
			}
			
			// Parse metadata
			if dbJob.Metadata != "" {
				if err := json.Unmarshal([]byte(dbJob.Metadata), &job.Metadata); err != nil {
					// Log but continue - job metadata parsing failed
					fmt.Printf("[!] Warning: Failed to parse job metadata for job %d: %v\n", dbJob.ID, err)
				}
			}
			
			jm.jobs[dbJob.ID] = job
			if dbJob.ID >= jm.nextID {
				jm.nextID = dbJob.ID + 1
			}
		}
	}
}

// AddJob adds a new job and persists it to database
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
	
	// Persist to database
	metadataJSON, err := json.Marshal(job.Metadata)
	if err != nil {
		// Log but continue - job is still created in memory
		fmt.Printf("[!] Warning: Failed to marshal job metadata: %v\n", err)
	}
	dbJob := &database.Job{
		ID:        id,
		Type:      string(jobType),
		Name:      name,
		Status:    "running",
		Metadata:  string(metadataJSON),
		CreatedAt: job.CreatedAt.Unix(),
	}
	if err := database.SaveJob(dbJob); err != nil {
		// Log but continue - job is still created in memory
		fmt.Printf("[!] Warning: Failed to save job to database: %v\n", err)
	}
	
	return job
}

// StopJob stops a job and updates database
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
			// Update database
			metadataJSON, err := json.Marshal(job.Metadata)
			if err != nil {
				// Log but continue
				fmt.Printf("[!] Warning: Failed to marshal job metadata: %v\n", err)
			}
			dbJob := &database.Job{
				ID:        id,
				Type:      string(job.Type),
				Name:      job.Name,
				Status:    "error",
				Metadata:  string(metadataJSON),
				CreatedAt: job.CreatedAt.Unix(),
			}
			if err := database.SaveJob(dbJob); err != nil {
				fmt.Printf("[!] Warning: Failed to update job status in database: %v\n", err)
			}
			return err
		}
	}
	
	job.Status = JobStatusStopped
	delete(jm.jobs, id)
	
	// Update database
	if err := database.DeleteJob(id); err != nil {
		// Log but continue - job is already stopped in memory
		fmt.Printf("[!] Warning: Failed to delete job from database: %v\n", err)
	}
	
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

