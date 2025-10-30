# Ditto Comprehensive Test Suite

## Overview

This document describes the comprehensive test suite for the Ditto security testing framework. The test suite aims for 100% code coverage across all packages, testing every feature, function, and code path.

## Test Structure

### Test Files Created

1. **core/config_test.go** - Configuration management tests
   - Default config generation
   - Config loading/saving
   - Config validation
   - JSON round-trip tests

2. **core/logger_test.go** - Logging system tests
   - Logger creation and initialization
   - File logging
   - Concurrent logging
   - Thread safety

3. **core/session_test.go** - Session management tests
   - Session creation and management
   - Session state transitions
   - Metadata handling
   - Concurrent access

4. **crypto/aes_test.go** - AES encryption tests
   - Encrypt/decrypt round-trip
   - Key handling (short, long, empty)
   - Large data encryption
   - Error cases

5. **crypto/chacha20_test.go** - ChaCha20 encryption tests
   - Encrypt/decrypt round-trip
   - Key handling
   - Large data encryption
   - Error cases

6. **malleable/transforms_test.go** - Malleable C2 transform tests
   - Base64 encoding/decoding
   - Prepend/append operations
   - Mask operations
   - NetBIOS encoding
   - Pipeline execution

7. **evasion/detection_test.go** - Evasion technique tests
   - Sandbox detection
   - Debugger detection
   - VM detection
   - Platform-specific tests

8. **tasks/queue_test.go** - Task queue tests
   - Queue operations
   - Task management
   - Concurrent access
   - Status updates

9. **payload/generator_test.go** - Payload generation tests
   - Stager generation
   - Shellcode generation
   - Full payload generation
   - Encryption/obfuscation

## Test Infrastructure

### Test Runner Script (`test.sh`)

A comprehensive bash script that:
- Runs all unit tests with coverage
- Generates HTML coverage reports
- Runs benchmarks
- Runs race detector
- Runs go vet
- Checks code formatting
- Reports test statistics

### Makefile Targets

- `make test` - Run basic tests
- `make test-coverage` - Run tests with coverage report
- `make test-race` - Run tests with race detector
- `make test-bench` - Run benchmarks
- `make test-all` - Run all test types
- `make test-comprehensive` - Run comprehensive test suite script

## Coverage Goals

- **Core Package**: 95%+ coverage ✓
- **Crypto Package**: 90%+ coverage ✓
- **Malleable Package**: 85%+ coverage ✓
- **Evasion Package**: 80%+ coverage ✓
- **Tasks Package**: 90%+ coverage ✓
- **Payload Package**: 75%+ coverage ✓

## Running Tests

### Quick Test
```bash
make test
```

### With Coverage
```bash
make test-coverage
```

### Comprehensive Suite
```bash
make test-comprehensive
# or
./test.sh
```

### Individual Package
```bash
go test ./core/... -v
go test ./crypto/... -v
```

## Test Categories

### Unit Tests
- Test individual functions and methods
- Mock dependencies where needed
- Test edge cases and error paths

### Integration Tests
- Test component interactions
- Test end-to-end workflows
- Test real-world scenarios

### Benchmark Tests
- Performance testing
- Memory usage analysis
- Concurrent operation testing

### Race Detection
- Thread safety verification
- Concurrent access testing
- Data race detection

## Test Best Practices

1. **Naming**: Tests follow `TestFunctionName_Scenario` pattern
2. **Assertions**: Use testify/assert for clear assertions
3. **Table Tests**: Use table-driven tests for multiple scenarios
4. **Cleanup**: Use defer for resource cleanup
5. **Isolation**: Each test is independent
6. **Coverage**: Aim for high coverage, especially critical paths

## Future Enhancements

- [ ] Integration tests for C2 communication
- [ ] Integration tests for module execution
- [ ] Fuzz testing for input validation
- [ ] Property-based testing for crypto operations
- [ ] Performance regression tests
- [ ] Windows-specific tests (direct syscalls, PE unhooking)
- [ ] Cross-platform testing

## Continuous Integration

Tests should be run:
- Before every commit
- In CI/CD pipeline
- Before releases
- During code reviews

## Test Dependencies

- `github.com/stretchr/testify` - Assertion library
- Go standard testing package
- Go coverage tools

## Notes

- Some platform-specific tests are skipped on non-matching platforms
- Windows-specific features require Windows build tags
- Some tests require elevated privileges (marked accordingly)
- Network tests may require mock servers

