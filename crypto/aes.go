package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// AES256Encrypt encrypts data using AES-256-GCM
func AES256Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Ensure key is 32 bytes
	if len(key) != 32 {
		key = padKey(key, 32)
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// AES256Decrypt decrypts data using AES-256-GCM
func AES256Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Ensure key is 32 bytes
	if len(key) != 32 {
		key = padKey(key, 32)
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

func padKey(key []byte, size int) []byte {
	padded := make([]byte, size)
	copy(padded, key)
	// Simple padding with repeated key
	if len(key) > 0 {
		for i := len(key); i < size; i++ {
			padded[i] = key[i%len(key)]
		}
	} else {
		// If key is empty, pad with zeros
		for i := len(key); i < size; i++ {
			padded[i] = 0
		}
	}
	return padded
}

