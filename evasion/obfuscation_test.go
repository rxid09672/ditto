package evasion

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestObfuscateCode(t *testing.T) {
	data := []byte("test data")
	
	obfuscated := ObfuscateCode(data)
	
	assert.NotNil(t, obfuscated)
	assert.NotEqual(t, data, obfuscated)
	assert.Len(t, obfuscated, len(data))
}

func TestObfuscateCode_Empty(t *testing.T) {
	data := []byte{}
	
	obfuscated := ObfuscateCode(data)
	
	assert.NotNil(t, obfuscated)
	assert.Len(t, obfuscated, 0)
}

func TestDeobfuscateCode(t *testing.T) {
	data := []byte("test data")
	key := []byte("key123")
	
	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ key[i%len(key)]
	}
	
	deobfuscated := DeobfuscateCode(obfuscated, key)
	
	assert.Equal(t, data, deobfuscated)
}

func TestDeobfuscateCode_RoundTrip(t *testing.T) {
	data := []byte("original data")
	knownKey := []byte("testkey")
	
	// Test with known key
	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ knownKey[i%len(knownKey)]
	}
	
	deobfuscated := DeobfuscateCode(obfuscated, knownKey)
	assert.Equal(t, data, deobfuscated)
}

func TestApplyPolymorphism(t *testing.T) {
	code := []byte{0x90, 0x90, 0x90, 0x90} // NOPs
	
	polymorphic := ApplyPolymorphism(code)
	
	assert.NotNil(t, polymorphic)
	assert.GreaterOrEqual(t, len(polymorphic), len(code))
}

func TestApplyPolymorphism_Empty(t *testing.T) {
	code := []byte{}
	
	polymorphic := ApplyPolymorphism(code)
	
	assert.NotNil(t, polymorphic)
	assert.Len(t, polymorphic, 0)
	assert.Equal(t, []byte{}, polymorphic)
}

func TestStringObfuscation(t *testing.T) {
	plaintext := "Hello World"
	
	obfuscated := StringObfuscation(plaintext)
	
	assert.NotEmpty(t, obfuscated)
	assert.NotEqual(t, plaintext, obfuscated)
	assert.Contains(t, obfuscated, "obf_")
}

func TestStringObfuscation_Empty(t *testing.T) {
	plaintext := ""
	
	obfuscated := StringObfuscation(plaintext)
	
	assert.NotEmpty(t, obfuscated)
}

func TestStringObfuscation_SpecialChars(t *testing.T) {
	plaintext := "Test123!@#"
	
	obfuscated := StringObfuscation(plaintext)
	
	assert.NotEmpty(t, obfuscated)
}

func BenchmarkObfuscateCode(b *testing.B) {
	data := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ObfuscateCode(data)
	}
}

func BenchmarkDeobfuscateCode(b *testing.B) {
	data := make([]byte, 1024)
	key := make([]byte, 16)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DeobfuscateCode(data, key)
	}
}

func BenchmarkApplyPolymorphism(b *testing.B) {
	code := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ApplyPolymorphism(code)
	}
}

func BenchmarkStringObfuscation(b *testing.B) {
	plaintext := "This is a test string for obfuscation"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StringObfuscation(plaintext)
	}
}

