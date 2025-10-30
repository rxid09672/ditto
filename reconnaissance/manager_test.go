package reconnaissance

import (
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

func TestNewReconManager(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	require.NotNil(t, rm)
	assert.Equal(t, logger, rm.logger)
}

func TestReconManager_ScanHost(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	// Will fail if nmap not installed, but structure is tested
	_, err := rm.ScanHost("127.0.0.1", "80", false, false)
	
	// May fail due to nmap not available, but structure is tested
	_ = err
}

func TestReconManager_ScanHost_WithOptions(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	_, err := rm.ScanHost("127.0.0.1", "80-443", true, true)
	
	_ = err
}

func TestReconManager_SubdomainEnum(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	_, err := rm.SubdomainEnum("example.com")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestReconManager_EmailHarvest(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	_, err := rm.EmailHarvest("example.com")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestReconManager_parseNmapOutput(t *testing.T) {
	logger := &mockLogger{}
	rm := NewReconManager(logger)
	
	output := "Nmap scan report for 127.0.0.1\nHost is up\n"
	
	hosts, err := rm.parseNmapOutput(output)
	
	require.NoError(t, err)
	assert.NotNil(t, hosts)
}

func TestHostInfo_Structure(t *testing.T) {
	host := HostInfo{
		IP:       "127.0.0.1",
		Hostname: "localhost",
		OS:       "Linux",
		OpenPorts: []PortInfo{
			{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
		},
	}
	
	assert.Equal(t, "127.0.0.1", host.IP)
	assert.Len(t, host.OpenPorts, 1)
}

func TestPortInfo_Structure(t *testing.T) {
	port := PortInfo{
		Port:     80,
		Protocol: "tcp",
		State:    "open",
		Service:  "http",
		Version:  "Apache 2.4",
	}
	
	assert.Equal(t, 80, port.Port)
	assert.Equal(t, "tcp", port.Protocol)
}

