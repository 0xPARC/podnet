# PodNet Deployment Configuration

PodNet uses environment variables for configuration to make deployment easy across different platforms.

## Server Configuration

### Environment Variables

- `PORT` - Port to run the server on (default: 3000)
  - Note: Most platforms like Render automatically set this
- `PODNET_HOST` - Host to bind to (default: "0.0.0.0")
- `PODNET_MOCK_PROOFS` - Use mock proofs for faster development (default: true)

### Examples

#### Development
```bash
# Use defaults (mock proofs enabled, port 3000)
cargo run -p podnet-server
```

#### Production on Render
Set these environment variables in your Render service:
```
PODNET_MOCK_PROOFS=false
```

The `PORT` environment variable will be automatically set by Render.

## CLI Configuration

### Environment Variables

- `PODNET_SERVER_URL` - Main server URL (default: "http://localhost:3000")
- `PODNET_IDENTITY_SERVER_URL` - Identity server URL (default: "http://localhost:3001")

### Examples

#### Development
```bash
# Use defaults (localhost URLs)
cargo run -p podnet-cli -- --help
```

#### Production
```bash
export PODNET_SERVER_URL="https://your-podnet-server.onrender.com"
export PODNET_IDENTITY_SERVER_URL="https://your-identity-server.onrender.com"
cargo run -p podnet-cli -- list-posts
```

## Identity Server Configuration

The identity server will also use environment variables:
- `PORT` - Port to run on (default: 3001)
- `PODNET_HOST` - Host to bind to (default: "0.0.0.0")

## Quick Setup for Render

1. Create two Render services (one for main server, one for identity server)
2. Set environment variables:
   - Main server: `PODNET_MOCK_PROOFS=false`
   - Identity server: (no special config needed)
3. Update your CLI environment:
   ```bash
   export PODNET_SERVER_URL="https://your-podnet-server.onrender.com"
   export PODNET_IDENTITY_SERVER_URL="https://your-identity-server.onrender.com"
   ```

That's it! No config files needed.