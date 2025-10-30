package multiplayer

import (
	"context"
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

func TestNewMultiplayerManager(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	require.NotNil(t, mm)
	assert.NotNil(t, mm.operators)
	assert.Equal(t, logger, mm.logger)
}

func TestMultiplayerManager_AddOperator(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	op := mm.AddOperator("op-1", "testuser", addr)
	
	require.NotNil(t, op)
	assert.Equal(t, "op-1", op.ID)
	assert.Equal(t, "testuser", op.Username)
	assert.Equal(t, addr, op.Address)
	assert.True(t, op.Active)
}

func TestMultiplayerManager_AddOperator_Multiple(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	addr1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	addr2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	
	mm.AddOperator("op-1", "user1", addr1)
	mm.AddOperator("op-2", "user2", addr2)
	
	operators := mm.ListOperators()
	assert.Len(t, operators, 2)
}

func TestMultiplayerManager_ListOperators(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	assert.Len(t, mm.ListOperators(), 0)
	
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	mm.AddOperator("op-1", "user1", addr)
	
	operators := mm.ListOperators()
	assert.Len(t, operators, 1)
	assert.Equal(t, "op-1", operators[0].ID)
}

func TestMultiplayerManager_StartGRPCServer(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	ctx := context.Background()
	err := mm.StartGRPCServer(ctx, "127.0.0.1:50051")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestMultiplayerManager_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080 + id}
			mm.AddOperator(string(rune(id)), "user", addr)
			mm.ListOperators()
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Should not panic
	assert.NotNil(t, mm.operators)
}

func TestOperator_Structure(t *testing.T) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	op := mm.AddOperator("op-1", "testuser", addr)
	
	op.Active = false
	assert.False(t, op.Active)
}

func BenchmarkMultiplayerManager_AddOperator(b *testing.B) {
	logger := &mockLogger{}
	mm := NewMultiplayerManager(logger)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mm.AddOperator(string(rune(i)), "user", addr)
	}
}

