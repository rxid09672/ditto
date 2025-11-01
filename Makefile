.PHONY: build clean test install cover pretty

build:
	@echo "Building Ditto Framework..."
	@go build -ldflags "-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" -o bin/ditto .

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@go clean

test:
	@echo "Running tests..."
	@go test -v ./...

cover: test-coverage
	@echo "Coverage report generated in coverage.html"

test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

test-race:
	@echo "Running tests with race detector..."
	@go test -race ./...

test-bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

test-all: test test-coverage test-race test-bench
	@echo "All tests completed!"

test-comprehensive:
	@if [ -f test.sh ]; then ./test.sh; else echo "test.sh not found (gitignored)"; fi

pretty:
	@echo "Demonstrating pretty output..."
	@DITTO_PRETTY=1 ./bin/ditto --help || go run . --pretty --help

install:
	@echo "Installing..."
	@go install -ldflags "-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" .

build-windows:
	@echo "Building Windows payload..."
	@GOOS=windows GOARCH=amd64 go build -ldflags "-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" -o bin/ditto.exe .

build-linux:
	@echo "Building Linux payload..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" -o bin/ditto-linux .

build-darwin:
	@echo "Building macOS payload..."
	@GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" -o bin/ditto-darwin .

build-all: build-windows build-linux build-darwin

