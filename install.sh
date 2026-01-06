#!/bin/bash
#
# vuln-pkg installer
# Usage: curl -fsSL https://raw.githubusercontent.com/neutrino2211/vuln-pkg/main/install.sh | bash
#
# Environment variables:
#   VULN_PKG_VERSION - specific version to install (default: latest)
#   VULN_PKG_INSTALL_DIR - installation directory (default: /usr/local/bin or ~/.local/bin)
#

set -e

REPO="neutrino2211/vuln-pkg"
BINARY_NAME="vuln-pkg"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        CYGWIN*|MINGW*|MSYS*) error "Windows is not supported. Please use WSL.";;
        *)          error "Unsupported operating system: $(uname -s)";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64";;
        aarch64|arm64)  echo "aarch64";;
        *)              error "Unsupported architecture: $(uname -m)";;
    esac
}

# Get the latest release version from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Determine install directory
get_install_dir() {
    if [ -n "$VULN_PKG_INSTALL_DIR" ]; then
        echo "$VULN_PKG_INSTALL_DIR"
    elif [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    else
        mkdir -p "$HOME/.local/bin"
        echo "$HOME/.local/bin"
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Main installation function
main() {
    echo ""
    echo "  ┌─────────────────────────────────────┐"
    echo "  │       vuln-pkg installer            │"
    echo "  │   The NPM for your home lab         │"
    echo "  └─────────────────────────────────────┘"
    echo ""

    # Check for required tools
    if ! command_exists curl; then
        error "curl is required but not installed. Please install curl first."
    fi

    if ! command_exists tar; then
        error "tar is required but not installed. Please install tar first."
    fi

    # Detect platform
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Detected platform: ${OS}-${ARCH}"

    # Determine binary name
    ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}"

    # Use musl build for Linux x86_64 for better compatibility
    if [ "$OS" = "linux" ] && [ "$ARCH" = "x86_64" ]; then
        ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}-musl"
    fi

    # Get version
    if [ -n "$VULN_PKG_VERSION" ]; then
        VERSION="$VULN_PKG_VERSION"
        info "Installing specified version: ${VERSION}"
    else
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            error "Failed to get latest version. Please check your internet connection or specify VULN_PKG_VERSION."
        fi
        info "Latest version: ${VERSION}"
    fi

    # Construct download URL
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}.tar.gz"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}.tar.gz.sha256"

    # Get install directory
    INSTALL_DIR=$(get_install_dir)
    info "Install directory: ${INSTALL_DIR}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    # Download binary
    info "Downloading ${ASSET_NAME}..."
    if ! curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET_NAME}.tar.gz"; then
        error "Failed to download binary. URL: ${DOWNLOAD_URL}"
    fi

    # Download and verify checksum
    info "Verifying checksum..."
    if curl -fsSL "$CHECKSUM_URL" -o "${TMP_DIR}/checksum.sha256" 2>/dev/null; then
        cd "$TMP_DIR"
        if command_exists shasum; then
            if ! shasum -a 256 -c checksum.sha256 >/dev/null 2>&1; then
                error "Checksum verification failed!"
            fi
        elif command_exists sha256sum; then
            if ! sha256sum -c checksum.sha256 >/dev/null 2>&1; then
                error "Checksum verification failed!"
            fi
        else
            warn "No checksum tool available, skipping verification"
        fi
        cd - >/dev/null
        success "Checksum verified"
    else
        warn "Could not download checksum file, skipping verification"
    fi

    # Extract binary
    info "Extracting..."
    tar -xzf "${TMP_DIR}/${ASSET_NAME}.tar.gz" -C "$TMP_DIR"

    # Install binary
    info "Installing to ${INSTALL_DIR}..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    success "vuln-pkg ${VERSION} installed successfully!"
    echo ""

    # Check if install directory is in PATH
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "Note: ${INSTALL_DIR} is not in your PATH"
        echo ""
        echo "  Add it to your PATH by adding this to your shell config:"
        echo ""
        echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
    fi

    # Verify installation
    if command_exists vuln-pkg; then
        echo "  Get started:"
        echo ""
        echo "    vuln-pkg list              # See available apps"
        echo "    vuln-pkg run dvwa          # Run DVWA"
        echo "    vuln-pkg --help            # Show all commands"
        echo ""
    else
        echo "  Run the following to get started:"
        echo ""
        echo "    ${INSTALL_DIR}/${BINARY_NAME} --help"
        echo ""
    fi

    # Check for Docker
    if ! command_exists docker; then
        warn "Docker is not installed. vuln-pkg requires Docker to run."
        echo "  Install Docker: https://docs.docker.com/get-docker/"
        echo ""
    elif ! docker info >/dev/null 2>&1; then
        warn "Docker is installed but not running. Please start Docker."
        echo ""
    fi
}

main "$@"
