.PHONY: build clean test install

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

