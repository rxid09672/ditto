package evasion

import (
	"crypto/rand"
	"fmt"
)

// ObfuscateCode applies code obfuscation techniques
func ObfuscateCode(data []byte) []byte {
	// Simple XOR obfuscation (would be more sophisticated in production)
	key := make([]byte, len(data))
	if _, err := rand.Read(key); err != nil {
		return data
	}
	
	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ key[i%len(key)]
	}
	
	return obfuscated
}

// DeobfuscateCode reverses obfuscation
func DeobfuscateCode(data []byte, key []byte) []byte {
	deobfuscated := make([]byte, len(data))
	for i := range data {
		deobfuscated[i] = data[i] ^ key[i%len(key)]
	}
	return deobfuscated
}

// ApplyPolymorphism applies polymorphic transformations
func ApplyPolymorphism(code []byte) []byte {
	// Add NOPs, reorder instructions, etc.
	polymorphic := make([]byte, 0, len(code)*2)
	
	// Insert random NOPs
	nopCount := len(code) / 10
	for i := 0; i < len(code); i++ {
		polymorphic = append(polymorphic, code[i])
		if i%nopCount == 0 && i > 0 {
			polymorphic = append(polymorphic, 0x90) // NOP
		}
	}
	
	return polymorphic
}

// StringObfuscation obfuscates strings
func StringObfuscation(plaintext string) string {
	// Simple ROT13 + base64 encoding
	rot13 := make([]byte, len(plaintext))
	for i := range plaintext {
		c := plaintext[i]
		if c >= 'a' && c <= 'z' {
			rot13[i] = 'a' + (c-'a'+13)%26
		} else if c >= 'A' && c <= 'Z' {
			rot13[i] = 'A' + (c-'A'+13)%26
		} else {
			rot13[i] = c
		}
	}
	return fmt.Sprintf("obf_%x", rot13)
}

