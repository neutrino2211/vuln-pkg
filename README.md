# vuln-pkg

> **Work in Progress** - This project is under active development. APIs and features may change.

**The NPM for your home lab.**

One command to spin up any vulnerable application for security training. No configuration, no port conflicts, no hassle.

```bash
vuln-pkg run dvwa
# That's it. DVWA is now running at http://dvwa.127.0.0.1.sslip.io
```

## Overview

vuln-pkg is a package manager for deliberately-vulnerable applications used in security training and penetration testing. Think of it as `npm install` but for security labs - browse a catalog of intentionally vulnerable apps, pick one, and have it running in seconds with a clean URL.

Whether you're practicing for OSCP, running a CTF, or teaching a security workshop, vuln-pkg eliminates the friction of setting up vulnerable environments. It handles Docker containers, networking, and DNS automatically so you can focus on hacking, not infrastructure.

**Key Features:**
- Zero-config DNS via sslip.io - works immediately without any local DNS setup
- Traefik reverse proxy for clean subdomain URLs (e.g., `http://dvwa.127.0.0.1.sslip.io`)
- Simple CLI to list, install, run, stop, and remove vulnerable apps
- Supports multiple apps running simultaneously
- **Custom packages** - build your own vulnerable labs from Dockerfiles or Git repositories
- JSON output for automation

## Requirements

- Docker (running)

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/neutrino2211/vuln-pkg/main/install.sh | bash
```

This will automatically detect your OS and architecture, download the latest release, and install it to `/usr/local/bin` (or `~/.local/bin` if you don't have write access).

#### Install Options

```bash
# Install a specific version
VULN_PKG_VERSION=v0.2.0 curl -fsSL https://raw.githubusercontent.com/neutrino2211/vuln-pkg/main/install.sh | bash

# Install to a custom directory
VULN_PKG_INSTALL_DIR=~/bin curl -fsSL https://raw.githubusercontent.com/neutrino2211/vuln-pkg/main/install.sh | bash
```

### Download from Releases

Download pre-built binaries from the [GitHub Releases](https://github.com/neutrino2211/vuln-pkg/releases) page.

Available binaries:
- `vuln-pkg-linux-x86_64-musl.tar.gz` - Linux x86_64 (static binary, works on any distro)
- `vuln-pkg-linux-aarch64.tar.gz` - Linux ARM64
- `vuln-pkg-darwin-x86_64.tar.gz` - macOS Intel
- `vuln-pkg-darwin-aarch64.tar.gz` - macOS Apple Silicon

### Build from Source

Requires the Rust toolchain.

```bash
git clone https://github.com/neutrino2211/vuln-pkg.git
cd vuln-pkg
cargo build --release

# Binary will be at target/release/vuln-pkg
```

## Quick Start

```bash
# List available vulnerable applications
vuln-pkg list

# Run DVWA (Damn Vulnerable Web Application)
vuln-pkg run dvwa

# The app is now available at http://dvwa.127.0.0.1.sslip.io
```

## Commands

### list

List all available vulnerable applications from the manifest.

```bash
vuln-pkg list
vuln-pkg --json list
```

### search

Search for applications by name, description, or tags.

```bash
vuln-pkg search sqli
vuln-pkg search owasp
vuln-pkg search CVE-2021
vuln-pkg --json search api
```

The search is case-insensitive and matches against:
- Application name
- Description text
- Tags (CVEs, vulnerability types, etc.)

### install

Pull the Docker image for an application without starting it.

```bash
vuln-pkg install <app>
```

### run

Start a vulnerable application. This will:
1. Pull the Docker image if needed
2. Create the vuln-pkg Docker network
3. Start Traefik reverse proxy (if not already running)
4. Create and start the application container

```bash
vuln-pkg run <app>
```

Example output:
```
[*] Fetching manifest from https://vulns.io/apps.yml
[+] Loaded 5 applications
[*] Ensuring vuln-pkg network exists
[*] Starting Traefik reverse proxy
[+] Traefik running (dashboard: http://traefik.127.0.0.1.sslip.io)
[*] Creating container for dvwa
[*] Starting container
[+] Started dvwa

  -> http://dvwa.127.0.0.1.sslip.io
```

### stop

Stop a running application without removing it.

```bash
vuln-pkg stop <app>
```

### remove

Stop and remove an application container.

```bash
vuln-pkg remove <app>

# Also remove the Docker image
vuln-pkg remove <app> --purge
```

### rebuild

Rebuild a custom application (dockerfile or git type). This is useful when you've updated the Dockerfile or want to pull the latest changes from a git repository.

```bash
vuln-pkg rebuild <app>
```

Note: This command only works with custom packages (`type: dockerfile` or `type: git`). For prebuilt packages, use `remove --purge` followed by `install` to get a fresh image.

### status

Show the status of all managed applications.

```bash
vuln-pkg status
vuln-pkg --json status
```

### manifest

Manage manifests - view information, list accepted manifests, or forget previously accepted ones.

```bash
# Show manifest information and contents
vuln-pkg manifest show

# List all accepted manifests
vuln-pkg manifest accepted

# Forget (un-accept) a manifest
vuln-pkg manifest forget
vuln-pkg manifest forget https://example.com/custom-manifest.yml
```

## Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format for automation |
| `-y, --yes` | Auto-accept new manifests without prompting (for scripting) |
| `--manifest-url <URL>` | Custom manifest URL (default: official vuln-pkg manifest) |
| `--resolve-address <IP>` | IP address for hostname resolution (default: 127.0.0.1) |
| `--domain <DOMAIN>` | Custom domain suffix (e.g., `lab.local`). Requires local DNS setup. |
| `--https` | Enable HTTPS with self-signed certificates |

## How It Works

### Zero-Config DNS

By default, vuln-pkg uses [sslip.io](https://sslip.io) for DNS resolution. sslip.io is a free service that resolves any hostname containing an IP address to that IP. For example:

- `dvwa.127.0.0.1.sslip.io` resolves to `127.0.0.1`
- `webgoat.192.168.1.100.sslip.io` resolves to `192.168.1.100`

This means you can start using vuln-pkg immediately without configuring local DNS.

### Custom Domain (Advanced)

If you prefer cleaner URLs like `dvwa.lab.local`, you can use the `--domain` flag:

```bash
vuln-pkg --domain lab.local run dvwa
```

This requires setting up local DNS resolution (e.g., dnsmasq, /etc/hosts, or systemd-resolved) to point `*.lab.local` to `127.0.0.1`.

### Traefik Reverse Proxy

vuln-pkg uses Traefik as a reverse proxy to route requests to the correct container based on the hostname. This enables:
- Clean subdomain-based URLs without port numbers
- Multiple apps running simultaneously on port 80
- Optional HTTPS support

### Traefik Dashboard

When apps are running, the Traefik dashboard is available at:
- Default: `http://traefik.127.0.0.1.sslip.io`
- Custom domain: `http://traefik.<your-domain>`

### Multi-Port Applications

Applications with multiple ports get additional subdomains:
- First port: `<app>.<domain>` (e.g., `webgoat.127.0.0.1.sslip.io`)
- Additional ports: `<app>-<port>.<domain>` (e.g., `webgoat-9090.127.0.0.1.sslip.io`)

### Manifest Trust

When you use a manifest for the first time, vuln-pkg will display information about it and ask you to accept or reject it:

```
════════════════════════════════════════════════════════════
  NEW MANIFEST
════════════════════════════════════════════════════════════

  URL:      https://example.com/manifest.yml
  Author:   Security Lab Team
  Email:    security@example.com
  Website:  https://github.com/example/vuln-lab
  About:    Custom vulnerable apps for internal training

  Contains 5 application(s) available:
    - custom-sqli
    - custom-xss
    ...

════════════════════════════════════════════════════════════

  ⚠ This manifest has not been accepted before.
  Review the information above and decide whether to trust it.

  Accept this manifest? [y/N/show]:
```

Options:
- **y/yes** - Accept the manifest and remember the choice
- **n/no** (or just Enter) - Reject and abort
- **show** - Display the full manifest YAML for inspection before deciding

Once accepted, the manifest is remembered and you won't be prompted again. Use `-y` flag to auto-accept for scripting:

```bash
vuln-pkg -y --manifest-url https://example.com/manifest.yml list
```

To manage accepted manifests:

```bash
# View all accepted manifests
vuln-pkg manifest accepted

# Forget a manifest (will prompt again next time)
vuln-pkg manifest forget https://example.com/manifest.yml
```

## Manifest Format

vuln-pkg reads application definitions from a YAML manifest. A manifest contains metadata about the author and a list of applications.

### Manifest Metadata

Every manifest should include metadata to help users identify and trust it:

```yaml
meta:
  author: "Security Lab Team"
  email: "security@example.com"
  url: "https://github.com/example/vuln-lab"
  description: "Custom vulnerable apps for internal training"

apps:
  # ... application definitions
```

### Package Types

There are three package types:

### Prebuilt Packages (Default)

Pull and run existing Docker images from registries:

```yaml
apps:
  - name: dvwa
    version: "1.0"
    image: vulnerables/web-dvwa:latest
    description: Damn Vulnerable Web Application
    ports:
      - 80
    tags:
      - CVE-2021-12345
    env:
      - MYSQL_ROOT_PASSWORD=root
```

### Dockerfile Packages

Build custom images from inline Dockerfiles or remote URLs:

```yaml
apps:
  # Inline Dockerfile
  - name: custom-sqli-lab
    version: "1.0"
    type: dockerfile
    dockerfile: |
      FROM php:8.0-apache
      RUN docker-php-ext-install mysqli pdo pdo_mysql
      COPY vuln-app/ /var/www/html/
      RUN chmod 777 /var/www/html
      EXPOSE 80
    ports: [80]
    tags:
      - SQL-Injection
    description: Custom SQL injection lab

  # Remote Dockerfile with build context
  - name: remote-vuln-app
    version: "1.0"
    type: dockerfile
    dockerfile_url: https://example.com/Dockerfile
    context_url: https://example.com/context.tar.gz
    ports: [8080]
    description: Build from remote Dockerfile
```

### Git Packages

Clone a repository and build from its Dockerfile:

```yaml
apps:
  - name: git-vuln-lab
    version: "1.0"
    type: git
    repo: https://github.com/user/vulnerable-app.git
    ref: main                    # Branch, tag, or commit (optional)
    dockerfile_path: ./Dockerfile  # Path to Dockerfile (optional, defaults to ./Dockerfile)
    ports: [3000]
    tags:
      - Custom
    description: Build from git repository
```

### Manifest Fields Reference

#### Common Fields (All Package Types)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for the app |
| `version` | Yes | Version string |
| `type` | No | Package type: `prebuilt` (default), `dockerfile`, or `git` |
| `description` | No | Human-readable description |
| `ports` | Yes | List of container ports to expose |
| `tags` | No | Tags for categorization (CVEs, vulnerability types, etc.) |
| `env` | No | Environment variables |

#### Prebuilt Package Fields

| Field | Required | Description |
|-------|----------|-------------|
| `image` | Yes | Docker image to pull (e.g., `vulnerables/web-dvwa`) |

#### Dockerfile Package Fields

| Field | Required | Description |
|-------|----------|-------------|
| `dockerfile` | * | Inline Dockerfile content |
| `dockerfile_url` | * | URL to fetch Dockerfile from |
| `context_url` | No | URL to fetch build context tarball (tar.gz) |

\* Either `dockerfile` or `dockerfile_url` is required.

#### Git Package Fields

| Field | Required | Description |
|-------|----------|-------------|
| `repo` | Yes | Git repository URL |
| `ref` | No | Branch, tag, or commit to checkout (defaults to default branch) |
| `dockerfile_path` | No | Path to Dockerfile in repo (defaults to `./Dockerfile`) |

### Image Naming

- **Prebuilt packages**: Uses the `image` field as-is
- **Custom packages**: Images are tagged as `vuln-pkg/<name>:<version>`

## Examples

### Run multiple apps

```bash
vuln-pkg run dvwa
vuln-pkg run webgoat
vuln-pkg run juice-shop
```

All apps will be accessible via their respective subdomains.

### Use with a custom manifest

```bash
vuln-pkg --manifest-url file:///path/to/manifest.yml list
vuln-pkg --manifest-url https://example.com/apps.yml run myapp
```

### JSON output for scripting

```bash
# Get list as JSON
vuln-pkg --json list

# Get status as JSON
vuln-pkg --json status
```

### Create a custom vulnerable lab

Create a manifest with your own Dockerfile:

```yaml
# my-labs.yml
apps:
  - name: sqli-lab
    version: "1.0"
    type: dockerfile
    dockerfile: |
      FROM php:8.0-apache
      RUN docker-php-ext-install mysqli
      COPY <<EOF /var/www/html/index.php
      <?php
      \$conn = new mysqli("db", "root", "root", "vuln");
      \$id = \$_GET['id'];
      \$result = \$conn->query("SELECT * FROM users WHERE id = \$id");
      ?>
      EOF
    ports: [80]
    description: "Simple SQL injection lab"
```

```bash
vuln-pkg --manifest-url file://./my-labs.yml run sqli-lab
```

### Use a git-based vulnerable app

```yaml
# git-labs.yml
apps:
  - name: dvwa-custom
    version: "1.0"
    type: git
    repo: https://github.com/digininja/DVWA.git
    ref: master
    ports: [80]
    description: "DVWA built from source"
```

```bash
# Install and run
vuln-pkg --manifest-url file://./git-labs.yml run dvwa-custom

# Later, rebuild to get latest changes
vuln-pkg --manifest-url file://./git-labs.yml rebuild dvwa-custom
```

### Remote access (lab environment)

If running vuln-pkg on a remote server accessible at `192.168.1.100`:

```bash
vuln-pkg --resolve-address 192.168.1.100 run dvwa
# Access at http://dvwa.192.168.1.100.sslip.io from any machine
```

### Enable HTTPS

```bash
vuln-pkg --https run dvwa
# Access at https://dvwa.127.0.0.1.sslip.io
```

Note: Uses self-signed certificates, so you'll need to accept the browser warning.

## State Directory

vuln-pkg stores state in `~/.vuln-pkg/`:

```
~/.vuln-pkg/
├── state.json      # Application state (running containers, network ID, etc.)
├── manifests/      # Cached manifests
├── repos/          # Cloned git repositories (for git packages)
└── images/         # Reserved for future use
```

The `state.json` file tracks:
- Installed applications and their status
- Container IDs for running apps
- Image source (prebuilt, dockerfile, or git)
- Build timestamps and git commit SHAs for custom packages

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Set logging level (`debug`, `info`, `warn`, `error`) |

```bash
RUST_LOG=debug vuln-pkg run dvwa
```

## Troubleshooting

### "Cannot connect to Docker"

Ensure Docker is running:
```bash
docker info
```

### App not accessible

1. Check the app is running: `vuln-pkg status`
2. Verify Traefik is running: `docker ps | grep vuln-pkg-traefik`
3. Check the Traefik dashboard for routing issues
4. Ensure you have internet connectivity (required for sslip.io DNS resolution)

### Port 80/443 already in use

Stop any services using port 80 or 443 (e.g., nginx, apache) before running vuln-pkg, as Traefik needs these ports.

```bash
# Check what's using port 80
sudo lsof -i :80
```

### Container starts but app doesn't load

Some apps take time to initialize. Check container logs:
```bash
docker logs vuln-pkg-<appname>
```

## Security Notes

- This tool manages intentionally vulnerable containers for educational purposes
- Never expose these containers to untrusted networks
- When using `--resolve-address` with a public IP, ensure proper network segmentation
- The Traefik dashboard is exposed without authentication by default

## License

MIT
