package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAES256Encrypt_Decrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := []byte("test plaintext data")
	
	ciphertext, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.Greater(t, len(ciphertext), len(plaintext))
	
	decrypted, err := AES256Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES256Encrypt_DifferentKeys(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	
	plaintext := []byte("test data")
	
	ciphertext1, err := AES256Encrypt(plaintext, key1)
	require.NoError(t, err)
	
	ciphertext2, err := AES256Encrypt(plaintext, key2)
	require.NoError(t, err)
	
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestAES256Encrypt_DifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("test data")
	
	ciphertext1, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	
	ciphertext2, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	
	// Should be different due to random nonce
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestAES256Encrypt_ShortKey(t *testing.T) {
	key := []byte("short")
	plaintext := []byte("test data")
	
	ciphertext, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	
	decrypted, err := AES256Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES256Encrypt_LongKey(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	plaintext := []byte("test data")
	
	ciphertext, err := AES256Encrypt(plaintext, key[:32])
	require.NoError(t, err)
	
	decrypted, err := AES256Decrypt(ciphertext, key[:32])
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES256Decrypt_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	shortCiphertext := []byte("short")
	
	_, err := AES256Decrypt(shortCiphertext, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestAES256Decrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	
	plaintext := []byte("test data")
	
	ciphertext, err := AES256Encrypt(plaintext, key1)
	require.NoError(t, err)
	
	_, err = AES256Decrypt(ciphertext, key2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestAES256Encrypt_LargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := make([]byte, 1024*1024) // 1MB
	rand.Read(plaintext)
	
	ciphertext, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	
	decrypted, err := AES256Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES256Encrypt_EmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	
	plaintext := []byte{}
	
	ciphertext, err := AES256Encrypt(plaintext, key)
	require.NoError(t, err)
	
	decrypted, err := AES256Decrypt(ciphertext, key)
	require.NoError(t, err)
	// GCM may return nil for empty plaintext, which is semantically equivalent to empty slice
	if decrypted == nil {
		decrypted = []byte{}
	}
	assert.Equal(t, plaintext, decrypted)
	assert.Len(t, decrypted, 0)
}

func TestPadKey(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		size     int
		expected int
	}{
		{"short key", []byte("short"), 32, 32},
		{"exact size", make([]byte, 32), 32, 32},
		{"long key", make([]byte, 64), 32, 32},
		{"empty key", []byte{}, 32, 32},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				padded := padKey(tt.key, tt.size)
				assert.Len(t, padded, tt.expected)
			})
		})
	}
}

func TestPadKey_RepeatedPattern(t *testing.T) {
	key := []byte("abc")
	padded := padKey(key, 32)
	
	assert.Len(t, padded, 32)
	assert.Equal(t, byte('a'), padded[0])
	assert.Equal(t, byte('b'), padded[1])
	assert.Equal(t, byte('c'), padded[2])
	assert.Equal(t, byte('a'), padded[3]) // Should repeat
}

func TestAES256Encrypt_NilKey(t *testing.T) {
	plaintext := []byte("test")
	
	ciphertext, err := AES256Encrypt(plaintext, nil)
	require.NoError(t, err)
	
	decrypted, err := AES256Decrypt(ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES256Encrypt_MultipleRounds(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("test data")
	
	// Encrypt multiple times
	result := plaintext
	var err error
	for i := 0; i < 10; i++ {
		result, err = AES256Encrypt(result, key)
		require.NoError(t, err)
	}
	
	// Decrypt same number of times
	for i := 0; i < 10; i++ {
		result, err = AES256Decrypt(result, key)
		require.NoError(t, err)
	}
	
	assert.Equal(t, plaintext, result)
}

func BenchmarkAES256Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AES256Encrypt(plaintext, key)
	}
}

func BenchmarkAES256Decrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	ciphertext, _ := AES256Encrypt(plaintext, key)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AES256Decrypt(ciphertext, key)
	}
}

