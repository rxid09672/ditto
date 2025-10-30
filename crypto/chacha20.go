package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Encrypt encrypts data using ChaCha20-Poly1305
func ChaCha20Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Ensure key is 32 bytes
	if len(key) != chacha20poly1305.KeySize {
		key = padKey(key, chacha20poly1305.KeySize)
	}
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// ChaCha20Decrypt decrypts data using ChaCha20-Poly1305
func ChaCha20Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Ensure key is 32 bytes
	if len(key) != chacha20poly1305.KeySize {
		key = padKey(key, chacha20poly1305.KeySize)
	}
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

