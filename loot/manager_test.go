package loot

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.logs = append(m.logs, "INFO: "+format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.logs = append(m.logs, "DEBUG: "+format)
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.logs = append(m.logs, "ERROR: "+format)
}

func TestNewLootManager(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	require.NotNil(t, lm)
	assert.NotNil(t, lm.items)
	assert.NotNil(t, lm.key)
	assert.Len(t, lm.key, 32)
	assert.Equal(t, logger, lm.logger)
}

func TestLootManager_AddLoot(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	id, err := lm.AddLoot(LootTypeCredential, "test_cred", []byte("test data"), nil)
	
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Contains(t, id, "loot-")
}

func TestLootManager_AddLoot_WithMetadata(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	metadata := map[string]interface{}{
		"source": "mimikatz",
		"domain": "test.local",
	}
	
	id, err := lm.AddLoot(LootTypeCredential, "test_cred", []byte("data"), metadata)
	
	require.NoError(t, err)
	
	item, err := lm.GetLoot(id)
	require.NoError(t, err)
	assert.Equal(t, metadata, item.Metadata)
}

func TestLootManager_GetLoot_Exists(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	id, _ := lm.AddLoot(LootTypeCredential, "test", []byte("data"), nil)
	
	item, err := lm.GetLoot(id)
	
	require.NoError(t, err)
	assert.Equal(t, id, item.ID)
	assert.Equal(t, LootTypeCredential, item.Type)
	assert.True(t, item.Encrypted)
}

func TestLootManager_GetLoot_NotExists(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	_, err := lm.GetLoot("nonexistent")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLootManager_GetLoot_Decrypt(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	originalData := []byte("secret data")
	id, _ := lm.AddLoot(LootTypeCredential, "test", originalData, nil)
	
	item, err := lm.GetLoot(id)
	require.NoError(t, err)
	
	decrypted, err := lm.decrypt(item.Data)
	require.NoError(t, err)
	
	assert.Equal(t, originalData, decrypted)
}

func TestLootManager_ListLoot(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	lm.AddLoot(LootTypeCredential, "cred1", []byte("data1"), nil)
	lm.AddLoot(LootTypeFile, "file1", []byte("data2"), nil)
	
	items := lm.ListLoot()
	
	assert.Len(t, items, 2)
}

func TestLootManager_ListLoot_FilterByType(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	lm.AddLoot(LootTypeCredential, "cred1", []byte("data1"), nil)
	lm.AddLoot(LootTypeFile, "file1", []byte("data2"), nil)
	lm.AddLoot(LootTypeCredential, "cred2", []byte("data3"), nil)
	
	allItems := lm.ListLoot()
	credItems := make([]*LootItem, 0)
	for _, item := range allItems {
		if item.Type == LootTypeCredential {
			credItems = append(credItems, item)
		}
	}
	
	assert.Len(t, credItems, 2)
	for _, item := range credItems {
		assert.Equal(t, LootTypeCredential, item.Type)
	}
}

func TestLootManager_RemoveLoot(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	id, _ := lm.AddLoot(LootTypeCredential, "test", []byte("data"), nil)
	
	err := lm.RemoveLoot(id)
	
	require.NoError(t, err)
	_, err = lm.GetLoot(id)
	assert.Error(t, err)
}

func TestLootManager_RemoveLoot_NotExists(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	err := lm.RemoveLoot("nonexistent")
	
	assert.NoError(t, err)
}

func TestLootManager_AddCredential(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	cred := &Credential{
		Username: "testuser",
		Password: "testpass",
		Domain:   "test.local",
		Source:   "mimikatz",
	}
	
	id, err := lm.AddCredential(cred)
	
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	
	item, err := lm.GetLoot(id)
	require.NoError(t, err)
	
	decrypted, err := lm.DecryptLoot(item)
	require.NoError(t, err)
	
	var retrieved Credential
	err = json.Unmarshal(decrypted, &retrieved)
	require.NoError(t, err)
	
	assert.Equal(t, cred.Username, retrieved.Username)
	assert.Equal(t, cred.Password, retrieved.Password)
	assert.Equal(t, cred.Domain, retrieved.Domain)
}

func TestLootManager_AddCredential_Multiple(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	id1, _ := lm.AddCredential(&Credential{Username: "user1", Password: "pass1"})
	id2, _ := lm.AddCredential(&Credential{Username: "user2", Password: "pass2"})
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	
	item1, _ := lm.GetLoot(id1)
	item2, _ := lm.GetLoot(id2)
	
	assert.Equal(t, LootTypeCredential, item1.Type)
	assert.Equal(t, LootTypeCredential, item2.Type)
}

func TestLootManager_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			lm.AddLoot(LootTypeCredential, string(rune(id)), []byte("data"), nil)
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	assert.Len(t, lm.ListLoot(), 10)
}

func TestLootManager_EncryptDecrypt_RoundTrip(t *testing.T) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	originalData := []byte("test data")
	id, _ := lm.AddLoot(LootTypeCredential, "test", originalData, nil)
	
	item, _ := lm.GetLoot(id)
	decrypted, err := lm.decrypt(item.Data)
	
	require.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func BenchmarkLootManager_AddLoot(b *testing.B) {
	logger := &mockLogger{}
	lm := NewLootManager(logger)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lm.AddLoot(LootTypeCredential, "test", []byte("data"), nil)
	}
}

