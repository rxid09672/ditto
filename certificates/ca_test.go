package certificates

import (
	"net"
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

func TestNewCAManager(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	require.NotNil(t, cm)
	assert.Equal(t, logger, cm.logger)
	assert.Nil(t, cm.cert)
	assert.Nil(t, cm.key)
}

func TestCAManager_GenerateCA(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err := cm.GenerateCA("Test CA")
	
	require.NoError(t, err)
	assert.NotNil(t, cm.cert)
	assert.NotNil(t, cm.key)
	assert.True(t, cm.cert.IsCA)
	assert.Equal(t, "Test CA", cm.cert.Subject.CommonName)
}

func TestCAManager_GenerateCA_Multiple(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err1 := cm.GenerateCA("CA 1")
	require.NoError(t, err1)
	
	err2 := cm.GenerateCA("CA 2")
	require.NoError(t, err2)
	
	// Should overwrite previous CA
	assert.Equal(t, "CA 2", cm.cert.Subject.CommonName)
}

func TestCAManager_GenerateCertificate_WithoutCA(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	_, _, err := cm.GenerateCertificate("test.com", nil, nil)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA not initialized")
}

func TestCAManager_GenerateCertificate_WithCA(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err := cm.GenerateCA("Test CA")
	require.NoError(t, err)
	
	certPEM, keyPEM, err := cm.GenerateCertificate("test.com", []string{"test.com", "www.test.com"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)
	assert.Contains(t, string(certPEM), "CERTIFICATE")
	assert.Contains(t, string(keyPEM), "PRIVATE KEY")
}

func TestCAManager_GenerateCertificate_DNSNames(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err := cm.GenerateCA("Test CA")
	require.NoError(t, err)
	
	certPEM, _, err := cm.GenerateCertificate("test.com", []string{"test.com", "www.test.com"}, nil)
	
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
}

func TestCAManager_GenerateCertificate_IPAddresses(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err := cm.GenerateCA("Test CA")
	require.NoError(t, err)
	
	certPEM, _, err := cm.GenerateCertificate("test.com", nil, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
}

func TestCAManager_GenerateCertificate_Empty(t *testing.T) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	err := cm.GenerateCA("Test CA")
	require.NoError(t, err)
	
	certPEM, keyPEM, err := cm.GenerateCertificate("test.com", nil, nil)
	
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)
}

func BenchmarkCAManager_GenerateCA(b *testing.B) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cm.GenerateCA("Test CA")
	}
}

func BenchmarkCAManager_GenerateCertificate(b *testing.B) {
	logger := &mockLogger{}
	cm := NewCAManager(logger)
	cm.GenerateCA("Test CA")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = cm.GenerateCertificate("test.com", nil, nil)
	}
}

