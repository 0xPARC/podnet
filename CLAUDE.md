# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PodNet is a cryptographically-secured content publishing platform built with Rust. It consists of three main components that work together to provide trustless document publishing and upvoting using zero-knowledge proofs (PODs - Proof of Data).

### Architecture Components

1. **PodNet Server** (`server/`) - Main content server (port 3000)
   - Axum-based REST API server
   - SQLite database for metadata storage
   - Content-addressed storage for document content
   - Cryptographic verification of MainPods for publishing and upvoting

2. **Identity Server** (`identity-providers/strawman/`) - Identity verification service (port 3001)
   - Strawman implementation for user identity verification
   - Issues cryptographic identity pods after challenge-response flow
   - Registers with PodNet server to become trusted identity provider

3. **CLI Client** (`cli/`) - Command-line interface
   - User interface for document publishing, upvoting, and identity management
   - Generates required cryptographic proofs (MainPods) for server verification

4. **Shared Models** (`models/`) - Common data structures and verification predicates
   - Defines POD predicates for publish verification, upvote verification, and upvote counting
   - Contains request/response structures shared across components

5. **Utilities** (`utils/`) - Shared utility functions

### Cryptographic Architecture

The system uses the `pod2` library for zero-knowledge proofs. Three main types of MainPods are used:

1. **Publish Verification MainPod** - Proves document authenticity using `publish_verification` predicate
2. **Upvote Verification MainPod** - Proves upvote authenticity using `upvote_verification` predicate  
3. **Upvote Count MainPod** - Proves correct upvote count using recursive `upvote_count` predicate

## Development Commands

### Building and Running

```bash
# Build all workspace members
cargo build

# Build specific component
cargo build -p podnet-server
cargo build -p podnet-cli
cargo build -p podnet-ident-strawman

# Run components (from workspace root)
cargo run -p podnet-server              # Server on port 3000
cargo run -p podnet-ident-strawman      # Identity server on port 3001
cargo run -p podnet-cli -- --help       # CLI help

# Build for release
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for specific component  
cargo test -p podnet-server
cargo test -p podnet-models

# Run specific test
cargo test test_full_upvote_verification_predicate

# Run tests with output
cargo test -- --nocapture
```

### Development Configuration

The server uses a `config.toml` file for configuration:
- `mock_proofs = true` - Use mock proofs for faster development (default in dev)
- `mock_proofs = false` - Use real ZK proofs for production

Environment variables can override config with `PODNET_` prefix (e.g., `PODNET_MOCK_PROOFS=false`).

## Key Architectural Patterns

### POD Verification Flow
1. Client generates identity pod from identity server
2. Client creates document/upvote pod with content hash and metadata
3. Client builds MainPod that cryptographically proves:
   - Identity pod signed by registered identity server
   - Document/upvote pod signed by authenticated user
   - Cross-verification between identity and document/upvote signers
4. Server verifies MainPod and extracts public statements for database storage

### Content-Addressed Storage
- Document content stored separately from metadata using Poseidon hash
- MainPods cryptographically bind documents to their content hashes
- Prevents content tampering while maintaining verifiable references

### Database Design
- Posts contain multiple document revisions
- Documents store MainPod JSON for verification and timestamp pods from server
- Upvotes reference documents and store MainPod proofs
- Identity servers registered with public keys for verification

### Mock vs Real Proofs
The system supports both mock proofs (fast, for development) and real ZK proofs (slow, for production). This is controlled by the `mock_proofs` configuration and affects the `PodConfig` setup in the server.

## File Structure Notes

- Predicates are defined in `models/src/lib.rs` using the POD2 predicate language
- Server handlers are organized by feature in `server/src/handlers/`
- Database operations are centralized in `server/src/db/mod.rs`
- CLI commands are organized in `cli/src/commands/`
- POD configuration and server key management in `server/src/pod/`

## Documentation

Update the API_DOCUMENTATION.md each time the APIs change.
