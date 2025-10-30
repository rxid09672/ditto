package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJobManager(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	require.NotNil(t, jm)
	assert.NotNil(t, jm.jobs)
	assert.Equal(t, uint64(1), jm.nextID)
}

func TestJobManager_AddJob(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	stopFunc := func() error { return nil }
	job := jm.AddJob(JobTypePortForward, "test-forward", stopFunc)
	
	require.NotNil(t, job)
	assert.Equal(t, uint64(1), job.ID)
	assert.Equal(t, JobTypePortForward, job.Type)
	assert.Equal(t, "test-forward", job.Name)
	assert.Equal(t, JobStatusRunning, job.Status)
	assert.NotNil(t, job.StopFunc)
}

func TestJobManager_AddJob_Multiple(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	job1 := jm.AddJob(JobTypePortForward, "job1", nil)
	job2 := jm.AddJob(JobTypeSOCKS5, "job2", nil)
	
	assert.Equal(t, uint64(1), job1.ID)
	assert.Equal(t, uint64(2), job2.ID)
	assert.Len(t, jm.ListJobs(), 2)
}

func TestJobManager_StopJob_Success(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	stopCalled := false
	stopFunc := func() error {
		stopCalled = true
		return nil
	}
	
	job := jm.AddJob(JobTypePortForward, "test", stopFunc)
	
	err := jm.StopJob(job.ID)
	
	require.NoError(t, err)
	assert.True(t, stopCalled)
	assert.Len(t, jm.ListJobs(), 0)
}

func TestJobManager_StopJob_NotFound(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	err := jm.StopJob(999)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestJobManager_StopJob_StopFuncError(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	stopFunc := func() error {
		return assert.AnError
	}
	
	job := jm.AddJob(JobTypePortForward, "test", stopFunc)
	
	err := jm.StopJob(job.ID)
	
	assert.Error(t, err)
	assert.Equal(t, JobStatusError, job.Status)
}

func TestJobManager_StopJob_NoStopFunc(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	job := jm.AddJob(JobTypePortForward, "test", nil)
	
	err := jm.StopJob(job.ID)
	
	require.NoError(t, err)
	assert.Len(t, jm.ListJobs(), 0)
}

func TestJobManager_ListJobs(t *testing.T) {
	jm := NewJobManagerWithRestore(false)
	
	assert.Len(t, jm.ListJobs(), 0)
	
	jm.AddJob(JobTypePortForward, "job1", nil)
	jm.AddJob(JobTypeSOCKS5, "job2", nil)
	
	jobs := jm.ListJobs()
	assert.Len(t, jobs, 2)
}

func TestJobManager_Concurrent(t *testing.T) {
	jm := NewJobManager()
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			job := jm.AddJob(JobTypePortForward, string(rune(id)), nil)
			jm.ListJobs()
			jm.StopJob(job.ID)
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, jm.jobs)
}

func TestJob_CreatedAt(t *testing.T) {
	jm := NewJobManager()
	
	before := time.Now()
	job := jm.AddJob(JobTypePortForward, "test", nil)
	after := time.Now()
	
	assert.True(t, job.CreatedAt.After(before) || job.CreatedAt.Equal(before))
	assert.True(t, job.CreatedAt.Before(after) || job.CreatedAt.Equal(after))
}

func TestJob_Metadata(t *testing.T) {
	jm := NewJobManager()
	
	job := jm.AddJob(JobTypePortForward, "test", nil)
	
	require.NotNil(t, job.Metadata)
	job.Metadata["key"] = "value"
	assert.Equal(t, "value", job.Metadata["key"])
}

func BenchmarkJobManager_AddJob(b *testing.B) {
	jm := NewJobManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = jm.AddJob(JobTypePortForward, "test", nil)
	}
}

