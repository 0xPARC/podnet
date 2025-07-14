# PodNet

A cryptographically-secured content publishing platform using zero-knowledge proofs (PODs).

## Quick Start

### 1. Start the servers

```bash
# Start main server (port 3000)
cargo run -p podnet-server

# Start identity server (port 3001) 
cargo run -p podnet-ident-strawman
```

### 2. Use the CLI

```bash
# Generate a keypair
cargo run -p podnet-cli -- keygen --output alice.json

# Get identity from identity server
cargo run -p podnet-cli -- get-identity --keypair alice.json --username alice

# Publish a document
cargo run -p podnet-cli -- publish --keypair alice.json --identity-pod alice_identity.json --message "Hello PodNet!"

# List posts
cargo run -p podnet-cli -- list-posts
```

## Configuration

### Server Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PODNET_MOCK_PROOFS` | Use mock proofs for development | `true` |
| `PODNET_PORT` | Server port | `3000` |
| `PODNET_HOST` | Server host | `0.0.0.0` |
| `PODNET_DATABASE_PATH` | SQLite database file path | `podnet.db` |
| `PODNET_CONTENT_STORAGE_PATH` | Content storage directory | `content` |

### Identity Server Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Identity server port | `3001` |
| `PODNET_SERVER_URL` | Main server URL for registration | `http://localhost:3000` |
| `IDENTITY_KEYPAIR_FILE` | Path to keypair file | `identity-server-keypair.json` |

### CLI Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PODNET_SERVER_URL` | Main server URL | `http://localhost:3000` |
| `PODNET_IDENTITY_SERVER_URL` | Identity server URL | `http://localhost:3001` |

## Documentation

- **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** - Complete API reference, request/response formats, and cryptographic specifications
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide for Render and other platforms
