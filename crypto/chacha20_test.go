package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChaCha20Encrypt_Decrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := []byte("test plaintext data")
	
	ciphertext, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.Greater(t, len(ciphertext), len(plaintext))
	
	decrypted, err := ChaCha20Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Encrypt_DifferentKeys(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	
	plaintext := []byte("test data")
	
	ciphertext1, err := ChaCha20Encrypt(plaintext, key1)
	require.NoError(t, err)
	
	ciphertext2, err := ChaCha20Encrypt(plaintext, key2)
	require.NoError(t, err)
	
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestChaCha20Encrypt_DifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("test data")
	
	ciphertext1, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	
	ciphertext2, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	
	// Should be different due to random nonce
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestChaCha20Encrypt_ShortKey(t *testing.T) {
	key := []byte("short")
	plaintext := []byte("test data")
	
	ciphertext, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	
	decrypted, err := ChaCha20Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Decrypt_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	shortCiphertext := []byte("short")
	
	_, err := ChaCha20Decrypt(shortCiphertext, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestChaCha20Decrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	
	plaintext := []byte("test data")
	
	ciphertext, err := ChaCha20Encrypt(plaintext, key1)
	require.NoError(t, err)
	
	_, err = ChaCha20Decrypt(ciphertext, key2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestChaCha20Encrypt_LargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := make([]byte, 1024*1024) // 1MB
	rand.Read(plaintext)
	
	ciphertext, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	
	decrypted, err := ChaCha20Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Encrypt_EmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := []byte{}
	
	ciphertext, err := ChaCha20Encrypt(plaintext, key)
	require.NoError(t, err)
	
	decrypted, err := ChaCha20Decrypt(ciphertext, key)
	require.NoError(t, err)
	// AEAD may return nil for empty plaintext, which is semantically equivalent to empty slice
	if decrypted == nil {
		decrypted = []byte{}
	}
	assert.Equal(t, plaintext, decrypted)
	assert.Len(t, decrypted, 0)
}

func TestChaCha20Encrypt_NilKey(t *testing.T) {
	plaintext := []byte("test")
	
	ciphertext, err := ChaCha20Encrypt(plaintext, nil)
	require.NoError(t, err)
	
	decrypted, err := ChaCha20Decrypt(ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func BenchmarkChaCha20Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ChaCha20Encrypt(plaintext, key)
	}
}

func BenchmarkChaCha20Decrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	ciphertext, _ := ChaCha20Encrypt(plaintext, key)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ChaCha20Decrypt(ciphertext, key)
	}
}

