package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Credential represents a stored credential
type Credential struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // password, token, key, etc.
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	Token       string            `json:"token,omitempty"`
	PrivateKey  string            `json:"private_key,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// CredentialStore manages credential storage and retrieval
type CredentialStore interface {
	// Store stores a credential
	Store(ctx context.Context, cred *Credential) error
	
	// Get retrieves a credential by ID
	Get(ctx context.Context, id string) (*Credential, error)
	
	// Find searches for credentials matching criteria
	Find(ctx context.Context, criteria map[string]interface{}) ([]*Credential, error)
	
	// Delete removes a credential
	Delete(ctx context.Context, id string) error
	
	// List lists all credentials
	List(ctx context.Context) ([]*Credential, error)
	
	// Update updates an existing credential
	Update(ctx context.Context, cred *Credential) error
}

// InMemoryCredentialStore is an in-memory implementation
type InMemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*Credential
	encrypted   bool
	key         []byte
}

// NewInMemoryCredentialStore creates a new in-memory credential store
func NewInMemoryCredentialStore(encrypted bool) (*InMemoryCredentialStore, error) {
	store := &InMemoryCredentialStore{
		credentials: make(map[string]*Credential),
		encrypted:   encrypted,
	}
	
	if encrypted {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		store.key = key
	}
	
	return store, nil
}

// Store stores a credential
func (s *InMemoryCredentialStore) Store(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if cred.ID == "" {
		// Generate ID
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			return fmt.Errorf("failed to generate ID: %w", err)
		}
		cred.ID = base64.URLEncoding.EncodeToString(idBytes)
	}
	
	now := time.Now()
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = now
	}
	cred.UpdatedAt = now
	
	// Encrypt sensitive fields if enabled
	if s.encrypted {
		if err := s.encryptCredential(cred); err != nil {
			return fmt.Errorf("failed to encrypt credential: %w", err)
		}
	}
	
	// Deep copy to prevent external modification
	credCopy := *cred
	s.credentials[cred.ID] = &credCopy
	
	return nil
}

// Get retrieves a credential by ID
func (s *InMemoryCredentialStore) Get(ctx context.Context, id string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	cred, exists := s.credentials[id]
	if !exists {
		return nil, fmt.Errorf("credential not found: %s", id)
	}
	
	// Deep copy and decrypt if needed
	credCopy := *cred
	if s.encrypted {
		if err := s.decryptCredential(&credCopy); err != nil {
			return nil, fmt.Errorf("failed to decrypt credential: %w", err)
		}
	}
	
	return &credCopy, nil
}

// Find searches for credentials matching criteria
func (s *InMemoryCredentialStore) Find(ctx context.Context, criteria map[string]interface{}) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var results []*Credential
	
	for _, cred := range s.credentials {
		credCopy := *cred
		if s.encrypted {
			if err := s.decryptCredential(&credCopy); err != nil {
				continue // Skip corrupted entries
			}
		}
		
		matches := true
		for key, value := range criteria {
			switch key {
			case "type":
				if credCopy.Type != value {
					matches = false
				}
			case "username":
				if credCopy.Username != value {
					matches = false
				}
			case "domain":
				if credCopy.Domain != value {
					matches = false
				}
			case "metadata":
				if meta, ok := value.(map[string]string); ok {
					for k, v := range meta {
						if credCopy.Metadata[k] != v {
							matches = false
							break
						}
					}
				}
			}
			
			if !matches {
				break
			}
		}
		
		if matches {
			results = append(results, &credCopy)
		}
	}
	
	return results, nil
}

// Delete removes a credential
func (s *InMemoryCredentialStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.credentials[id]; !exists {
		return fmt.Errorf("credential not found: %s", id)
	}
	
	delete(s.credentials, id)
	return nil
}

// List lists all credentials
func (s *InMemoryCredentialStore) List(ctx context.Context) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	results := make([]*Credential, 0, len(s.credentials))
	for _, cred := range s.credentials {
		credCopy := *cred
		if s.encrypted {
			if err := s.decryptCredential(&credCopy); err != nil {
				continue // Skip corrupted entries
			}
		}
		results = append(results, &credCopy)
	}
	
	return results, nil
}

// Update updates an existing credential
func (s *InMemoryCredentialStore) Update(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.credentials[cred.ID]; !exists {
		return fmt.Errorf("credential not found: %s", cred.ID)
	}
	
	cred.UpdatedAt = time.Now()
	
	if s.encrypted {
		if err := s.encryptCredential(cred); err != nil {
			return fmt.Errorf("failed to encrypt credential: %w", err)
		}
	}
	
	credCopy := *cred
	s.credentials[cred.ID] = &credCopy
	
	return nil
}

// encryptCredential encrypts sensitive fields
func (s *InMemoryCredentialStore) encryptCredential(cred *Credential) error {
	// Simple XOR encryption (in production, use AES)
	if cred.Password != "" {
		cred.Password = s.xorEncrypt(cred.Password)
	}
	if cred.Token != "" {
		cred.Token = s.xorEncrypt(cred.Token)
	}
	if cred.PrivateKey != "" {
		cred.PrivateKey = s.xorEncrypt(cred.PrivateKey)
	}
	return nil
}

// decryptCredential decrypts sensitive fields
func (s *InMemoryCredentialStore) decryptCredential(cred *Credential) error {
	if cred.Password != "" {
		cred.Password = s.xorDecrypt(cred.Password)
	}
	if cred.Token != "" {
		cred.Token = s.xorDecrypt(cred.Token)
	}
	if cred.PrivateKey != "" {
		cred.PrivateKey = s.xorDecrypt(cred.PrivateKey)
	}
	return nil
}

// xorEncrypt performs simple XOR encryption
func (s *InMemoryCredentialStore) xorEncrypt(data string) string {
	// Use key hash for deterministic encryption
	hasher := sha256.New()
	hasher.Write(s.key)
	keyHash := hasher.Sum(nil)
	
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ keyHash[i%len(keyHash)]
	}
	
	return base64.StdEncoding.EncodeToString(encrypted)
}

// xorDecrypt performs XOR decryption
func (s *InMemoryCredentialStore) xorDecrypt(data string) string {
	encrypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data // Return original if decode fails
	}
	
	hasher := sha256.New()
	hasher.Write(s.key)
	keyHash := hasher.Sum(nil)
	
	decrypted := make([]byte, len(encrypted))
	for i := range encrypted {
		decrypted[i] = encrypted[i] ^ keyHash[i%len(keyHash)]
	}
	
	return string(decrypted)
}

// Export exports all credentials as JSON
func (s *InMemoryCredentialStore) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	creds, err := s.List(context.Background())
	if err != nil {
		return nil, err
	}
	
	return json.Marshal(creds)
}

// Import imports credentials from JSON
func (s *InMemoryCredentialStore) Import(data []byte) error {
	var creds []*Credential
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("failed to unmarshal credentials: %w", err)
	}
	
	for _, cred := range creds {
		if err := s.Store(context.Background(), cred); err != nil {
			return fmt.Errorf("failed to store credential %s: %w", cred.ID, err)
		}
	}
	
	return nil
}

