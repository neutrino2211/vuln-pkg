# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

vuln-pkg is a Rust CLI tool that acts as a package manager for deliberately-vulnerable applications used in security training and CTF environments. It fetches app manifests from remote YAML files, manages Docker containers, and runs an embedded DNS server for local domain resolution.

## Build Commands

```bash
# Development build
cargo build

# Release build
cargo build --release

# Static musl build for Linux x86_64
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test

# Run a single test
cargo test test_parse_manifest

# Check without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

## Architecture

### Source Modules (`src/`)

- **main.rs** - Entry point and command handlers (`cmd_list`, `cmd_install`, `cmd_run`, `cmd_remove`, `cmd_rebuild`, `cmd_status`)
- **cli.rs** - Clap CLI definitions with `Commands` enum
- **manifest.rs** - YAML manifest fetching and parsing with `Manifest`, `App`, and `PackageType` enum
- **state.rs** - Local state management (`StateManager`, `State`, `AppState`, `ImageSource`) for `~/.vuln-pkg/`
- **docker.rs** - Docker operations via bollard (`DockerManager`) including image building
- **output.rs** - Colored console output and JSON formatting (`Output`)
- **error.rs** - Error types with thiserror (`VulnPkgError`)

### CLI Commands
- `vuln-pkg list` - Display available vulnerable apps from manifest
- `vuln-pkg install <app>` - Pull/build Docker image and create local config
- `vuln-pkg run <app>` - Start container with Traefik routing
- `vuln-pkg stop <app>` - Stop a running container (keeps container for restart)
- `vuln-pkg remove <app> [--purge]` - Stop and remove container
- `vuln-pkg rebuild <app>` - Rebuild custom package (dockerfile/git types only)
- `vuln-pkg status` - Show status of managed applications

### Package Types
- **prebuilt** (default) - Pull existing Docker images from registries
- **dockerfile** - Build from inline or remote Dockerfile
- **git** - Clone repository and build from Dockerfile

### Local State (`~/.vuln-pkg/`)
- `manifests/` - Cached YAML manifest files
- `repos/` - Cloned git repositories for git-based packages
- `images/` - Optional Docker image tarball cache
- `state.json` - Application state (installed apps, containers, image source, build metadata)

### Networking
- Embedded DNS server binds to port 53 (requires `sudo` or `setcap`)
- Containers get sequential high ports starting at 30000
- Apps accessible via `<app>.lab.local`

## Key Dependencies

- `tokio` - Async runtime (full features)
- `clap` - CLI argument parsing with derive
- `serde` + `serde_yaml` - YAML manifest parsing
- `reqwest` - HTTP client with rustls
- `bollard` - Docker API client (pull and build images)
- `git2` - Git operations for cloning repositories
- `tar` + `flate2` - Tarball creation for Docker build context
- `chrono` - Timestamps for build metadata
- `colored` - Terminal colors
- `tracing` / `tracing-subscriber` - Logging

## Testing

Tests are co-located in each module using `#[cfg(test)]`:
- `manifest::tests::test_parse_prebuilt_manifest` - Prebuilt YAML parsing
- `manifest::tests::test_parse_dockerfile_inline_manifest` - Inline Dockerfile parsing
- `manifest::tests::test_parse_dockerfile_url_manifest` - Remote Dockerfile parsing
- `manifest::tests::test_parse_git_manifest` - Git package parsing
- `manifest::tests::test_backward_compatibility` - Manifests without type field
- `manifest::tests::test_validation_*` - Validation error tests
- `state::tests::test_url_to_filename` - URL sanitization
