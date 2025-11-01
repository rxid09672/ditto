package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	dbInstance *gorm.DB
	dbOnce     sync.Once
	dbMu       sync.RWMutex
)

// GetDB returns the database instance (singleton)
func GetDB() (*gorm.DB, error) {
	var err error
	dbOnce.Do(func() {
		dbPath := getDatabasePath()
		
		// Ensure directory exists
		dir := filepath.Dir(dbPath)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return
		}
		
		// Open database
		dbInstance, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent), // Silent for production
		})
		if err != nil {
			return
		}
		
		// Auto-migrate tables
		err = dbInstance.AutoMigrate(
			&ListenerJob{},
			&ImplantBuild{},
			&Job{},
		)
	})
	
	return dbInstance, err
}

// getDatabasePath returns the path to the database file
func getDatabasePath() string {
	homeDir, _ := os.UserHomeDir()
	dittoDir := filepath.Join(homeDir, ".ditto")
	return filepath.Join(dittoDir, "ditto.db")
}

// ListenerJob represents a persistent listener job
type ListenerJob struct {
	ID        string `gorm:"primaryKey"`
	Type      string `gorm:"not null"` // http, https, mtls
	JobID     uint64 `gorm:"index"`    // Not unique - can change on restart
	Host      string
	Port      uint32
	Secure    bool   // HTTPS/TLS enabled
	CertPath  string // Certificate path
	KeyPath   string // Key path
	Status    string // running, stopped
	CreatedAt int64  `gorm:"autoCreateTime"`
	UpdatedAt int64  `gorm:"autoUpdateTime"`
}

// BeforeCreate hook to generate UUID
func (l *ListenerJob) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	if l.CreatedAt == 0 {
		l.CreatedAt = time.Now().Unix()
	}
	l.UpdatedAt = time.Now().Unix()
	return nil
}

// ImplantBuild represents a generated implant build
type ImplantBuild struct {
	ID          string `gorm:"primaryKey"`
	Name        string `gorm:"index"`
	Type        string // stager, shellcode, full
	OS          string
	Arch        string
	CallbackURL string
	Delay       int
	Jitter      float64
	UserAgent   string
	Protocol    string
	OutputPath  string
	Size        int64
	Modules     string `gorm:"type:text"` // JSON array of module IDs
	Evasion     string `gorm:"type:text"` // JSON evasion config
	CreatedAt   int64  `gorm:"autoCreateTime"`
	UpdatedAt   int64  `gorm:"autoUpdateTime"`
}

// BeforeCreate hook to generate UUID
func (i *ImplantBuild) BeforeCreate(tx *gorm.DB) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	if i.CreatedAt == 0 {
		i.CreatedAt = time.Now().Unix()
	}
	i.UpdatedAt = time.Now().Unix()
	return nil
}

// Job represents a persistent background job
type Job struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement"`
	Type      string `gorm:"not null;index"` // listener, portforward, socks5
	Name      string
	Status    string `gorm:"default:'running'"`
	Metadata  string `gorm:"type:text"` // JSON metadata
	CreatedAt int64  `gorm:"autoCreateTime"`
	UpdatedAt int64  `gorm:"autoUpdateTime"`
}

// BeforeCreate hook
func (j *Job) BeforeCreate(tx *gorm.DB) error {
	if j.CreatedAt == 0 {
		j.CreatedAt = time.Now().Unix()
	}
	j.UpdatedAt = time.Now().Unix()
	return nil
}

// SaveListenerJob saves a listener job to database
func SaveListenerJob(job *ListenerJob) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	return db.Save(job).Error
}

// UpdateListenerJob updates an existing listener job
func UpdateListenerJob(job *ListenerJob) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	// Use Updates with Where clause to avoid UNIQUE constraint issues
	// Update by ID (primary key), not JobID
	return db.Model(&ListenerJob{}).Where("id = ?", job.ID).Updates(map[string]interface{}{
		"job_id":    job.JobID,
		"type":      job.Type,
		"host":      job.Host,
		"port":      job.Port,
		"secure":    job.Secure,
		"cert_path": job.CertPath,
		"key_path":  job.KeyPath,
		"status":    job.Status,
	}).Error
}

// GetListenerJobs retrieves all listener jobs
func GetListenerJobs() ([]*ListenerJob, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var jobs []*ListenerJob
	err = db.Find(&jobs).Error
	return jobs, err
}

// GetListenerJobByID retrieves a listener job by ID
func GetListenerJobByID(id string) (*ListenerJob, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var job ListenerJob
	err = db.Where("id = ?", id).First(&job).Error
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// GetListenerJobByAddress retrieves a listener job by type, host, and port
func GetListenerJobByAddress(listenerType, host string, port uint32) (*ListenerJob, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var job ListenerJob
	err = db.Where("type = ? AND host = ? AND port = ?", listenerType, host, port).First(&job).Error
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// DeleteListenerJob deletes a listener job
func DeleteListenerJob(id string) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	return db.Delete(&ListenerJob{}, "id = ?", id).Error
}

// SaveImplantBuild saves an implant build to database
func SaveImplantBuild(build *ImplantBuild) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	return db.Save(build).Error
}

// GetImplantBuilds retrieves all implant builds
func GetImplantBuilds() ([]*ImplantBuild, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var builds []*ImplantBuild
	err = db.Order("created_at DESC").Find(&builds).Error
	return builds, err
}

// GetImplantBuildByID retrieves an implant build by ID
func GetImplantBuildByID(id string) (*ImplantBuild, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var build ImplantBuild
	err = db.Where("id = ?", id).First(&build).Error
	if err != nil {
		return nil, err
	}
	return &build, nil
}

// SaveJob saves a job to database
func SaveJob(job *Job) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	return db.Save(job).Error
}

// SaveJobFromMap saves a job from map data (for restoring from database)
func SaveJobFromMap(metadata map[string]interface{}) (*Job, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	job := &Job{
		Type:     metadata["type"].(string),
		Name:     metadata["name"].(string),
		Status:   "stopped", // Will be started separately
		Metadata: string(metadataJSON),
	}
	
	if err := db.Create(job).Error; err != nil {
		return nil, err
	}
	
	return job, nil
}

// GetJobs retrieves all jobs
func GetJobs() ([]*Job, error) {
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	
	var jobs []*Job
	err = db.Order("created_at DESC").Find(&jobs).Error
	return jobs, err
}

// DeleteJob deletes a job
func DeleteJob(id uint64) error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to get database: %w", err)
	}
	
	return db.Delete(&Job{}, "id = ?", id).Error
}
