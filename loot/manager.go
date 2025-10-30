package loot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// LootType represents the type of loot
type LootType string

const (
	LootTypeCredential LootType = "credential"
	LootTypeFile       LootType = "file"
	LootTypeToken      LootType = "token"
	LootTypeHash       LootType = "hash"
)

// Credential represents stored credentials
type Credential struct {
	Username string
	Password string
	Domain   string
	Source   string
	Metadata map[string]interface{}
}

// LootItem represents a loot item
type LootItem struct {
	ID          string
	Type        LootType
	Name        string
	Data        []byte
	Encrypted   bool
	CreatedAt   time.Time
	Metadata    map[string]interface{}
}

// LootManager manages loot storage
type LootManager struct {
	items  map[string]*LootItem
	key    []byte
	mu     sync.RWMutex
	logger interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
}

// NewLootManager creates a new loot manager
func NewLootManager(logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *LootManager {
	key := make([]byte, 32)
	rand.Read(key)
	
	return &LootManager{
		items:  make(map[string]*LootItem),
		key:    key,
		logger: logger,
	}
}

// AddLoot adds a loot item
func (lm *LootManager) AddLoot(lootType LootType, name string, data []byte, metadata map[string]interface{}) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	id := fmt.Sprintf("loot-%d", time.Now().UnixNano())
	
	// Encrypt data
	encrypted, err := lm.encrypt(data)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}
	
	item := &LootItem{
		ID:        id,
		Type:      lootType,
		Name:      name,
		Data:      encrypted,
		Encrypted: true,
		CreatedAt: time.Now(),
		Metadata:  metadata,
	}
	
	lm.items[id] = item
	lm.logger.Info("Added loot: %s (%s)", id, lootType)
	
	return id, nil
}

// GetLoot retrieves a loot item
func (lm *LootManager) GetLoot(id string) (*LootItem, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	
	item, ok := lm.items[id]
	if !ok {
		return nil, fmt.Errorf("loot not found: %s", id)
	}
	
	return item, nil
}

// DecryptLoot decrypts loot data
func (lm *LootManager) DecryptLoot(item *LootItem) ([]byte, error) {
	if !item.Encrypted {
		return item.Data, nil
	}
	
	return lm.decrypt(item.Data)
}

// ListLoot lists all loot items
func (lm *LootManager) ListLoot() []*LootItem {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	
	items := make([]*LootItem, 0, len(lm.items))
	for _, item := range lm.items {
		items = append(items, item)
	}
	return items
}

// RemoveLoot removes a loot item
func (lm *LootManager) RemoveLoot(id string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	delete(lm.items, id)
	return nil
}

// AddCredential adds a credential to loot
func (lm *LootManager) AddCredential(cred *Credential) (string, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	
	return lm.AddLoot(LootTypeCredential, cred.Username, data, map[string]interface{}{
		"domain": cred.Domain,
		"source": cred.Source,
	})
}

// Export exports loot to JSON
func (lm *LootManager) Export() ([]byte, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	
	export := struct {
		Items []*LootItem `json:"items"`
		Count int         `json:"count"`
	}{
		Items: make([]*LootItem, 0, len(lm.items)),
		Count: len(lm.items),
	}
	
	for _, item := range lm.items {
		export.Items = append(export.Items, item)
	}
	
	return json.MarshalIndent(export, "", "  ")
}

func (lm *LootManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(lm.key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (lm *LootManager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(lm.key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

