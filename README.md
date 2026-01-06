# vuln-pkg

A package manager for deliberately-vulnerable applications used in security training and penetration testing.

## Overview

vuln-pkg makes it easy to run intentionally vulnerable web applications locally for security training, CTF practice, or penetration testing labs. It handles Docker container management and uses Traefik as a reverse proxy to provide clean subdomain-based URLs.

**Key Features:**
- Zero-config DNS via sslip.io - works immediately without any local DNS setup
- Traefik reverse proxy for clean subdomain URLs (e.g., `http://dvwa.127.0.0.1.sslip.io`)
- Simple CLI to list, install, run, stop, and remove vulnerable apps
- Supports multiple apps running simultaneously
- JSON output for automation

## Requirements

- Docker (running)
- Rust toolchain (for building from source)

## Installation

```bash
# Clone and build
git clone https://github.com/yourusername/vuln-pkg.git
cd vuln-pkg
cargo build --release

# The binary will be at target/release/vuln-pkg

# Optional: Static musl build for Linux x86_64
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
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

### status

Show the status of all managed applications.

```bash
vuln-pkg status
vuln-pkg --json status
```

## Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format for automation |
| `--manifest-url <URL>` | Custom manifest URL (default: https://vulns.io/apps.yml) |
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

## Manifest Format

vuln-pkg reads application definitions from a YAML manifest:

```yaml
apps:
  - name: dvwa
    version: "1.0"
    image: vulnerables/web-dvwa:latest
    description: Damn Vulnerable Web Application
    ports:
      - 80
    cve_tags:
      - CVE-2021-12345
    env:
      - MYSQL_ROOT_PASSWORD=root

  - name: juice-shop
    version: "14.0"
    image: bkimminich/juice-shop
    ports:
      - 3000
    cve_tags:
      - OWASP-Top-10
    description: OWASP Juice Shop - Modern vulnerable web app

  - name: webgoat
    version: "8.2"
    image: webgoat/webgoat
    ports:
      - 8080
      - 9090
    description: OWASP WebGoat - A deliberately insecure application

signature: null  # Optional - unsigned manifests show a warning
```

### Manifest Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for the app |
| `version` | Yes | Version string |
| `image` | Yes | Docker image to use |
| `description` | No | Human-readable description |
| `ports` | Yes | List of container ports to expose |
| `cve_tags` | No | Related CVE identifiers |
| `env` | No | Environment variables |

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
└── images/         # Reserved for future use
```

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
