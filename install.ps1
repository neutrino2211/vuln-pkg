#
# vuln-pkg installer for Windows
# Usage: irm https://raw.githubusercontent.com/neutrino2211/vuln-pkg/main/install.ps1 | iex
#
# Environment variables:
#   VULN_PKG_VERSION - specific version to install (default: latest)
#   VULN_PKG_INSTALL_DIR - installation directory (default: %LOCALAPPDATA%\vuln-pkg)
#

$ErrorActionPreference = "Stop"

$Repo = "neutrino2211/vuln-pkg"
$BinaryName = "vuln-pkg"

function Write-Info {
    param([string]$Message)
    Write-Host "[*] " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error-Exit {
    param([string]$Message)
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host $Message
    exit 1
}

function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $response.tag_name
    }
    catch {
        return $null
    }
}

function Get-InstallDir {
    if ($env:VULN_PKG_INSTALL_DIR) {
        return $env:VULN_PKG_INSTALL_DIR
    }
    return Join-Path $env:LOCALAPPDATA "vuln-pkg"
}

function Test-InPath {
    param([string]$Dir)
    $pathDirs = $env:PATH -split ";"
    return $pathDirs -contains $Dir
}

function Add-ToUserPath {
    param([string]$Dir)
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$Dir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$Dir", "User")
        $env:PATH = "$env:PATH;$Dir"
        return $true
    }
    return $false
}

function Main {
    Write-Host ""
    Write-Host "  +-------------------------------------+"
    Write-Host "  |       vuln-pkg installer            |"
    Write-Host "  |   The NPM for your home lab         |"
    Write-Host "  +-------------------------------------+"
    Write-Host ""

    # Check architecture
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    if ($arch -ne "AMD64") {
        Write-Error-Exit "Unsupported architecture: $arch. Only x86_64 (AMD64) is supported."
    }
    Write-Info "Detected platform: windows-x86_64"

    $AssetName = "$BinaryName-windows-x86_64"

    # Get version
    if ($env:VULN_PKG_VERSION) {
        $Version = $env:VULN_PKG_VERSION
        Write-Info "Installing specified version: $Version"
    }
    else {
        Write-Info "Fetching latest version..."
        $Version = Get-LatestVersion
        if (-not $Version) {
            Write-Error-Exit "Failed to get latest version. Please check your internet connection or set VULN_PKG_VERSION."
        }
        Write-Info "Latest version: $Version"
    }

    # Construct download URLs
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName.zip"
    $ChecksumUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName.zip.sha256"

    # Get install directory
    $InstallDir = Get-InstallDir
    Write-Info "Install directory: $InstallDir"

    # Create install directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Create temp directory
    $TmpDir = Join-Path $env:TEMP "vuln-pkg-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

    try {
        # Download binary
        $ZipPath = Join-Path $TmpDir "$AssetName.zip"
        Write-Info "Downloading $AssetName..."
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
        }
        catch {
            Write-Error-Exit "Failed to download binary. URL: $DownloadUrl"
        }

        # Download and verify checksum
        Write-Info "Verifying checksum..."
        try {
            $ChecksumPath = Join-Path $TmpDir "checksum.sha256"
            Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing

            $expectedHash = (Get-Content $ChecksumPath -Raw).Split(" ")[0].Trim()
            $actualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()

            if ($expectedHash -ne $actualHash) {
                Write-Error-Exit "Checksum verification failed!"
            }
            Write-Success "Checksum verified"
        }
        catch {
            Write-Warn "Could not verify checksum, skipping verification"
        }

        # Extract binary
        Write-Info "Extracting..."
        Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

        # Install binary
        Write-Info "Installing to $InstallDir..."
        $SourcePath = Join-Path $TmpDir "$BinaryName.exe"
        $DestPath = Join-Path $InstallDir "$BinaryName.exe"
        Move-Item -Path $SourcePath -Destination $DestPath -Force

        Write-Success "vuln-pkg $Version installed successfully!"
        Write-Host ""

        # Add to PATH if not already there
        if (-not (Test-InPath $InstallDir)) {
            Write-Info "Adding $InstallDir to user PATH..."
            if (Add-ToUserPath $InstallDir) {
                Write-Success "Added to PATH. Restart your terminal for changes to take effect."
            }
        }

        Write-Host ""
        Write-Host "  Get started:"
        Write-Host ""
        Write-Host "    vuln-pkg list              # See available apps"
        Write-Host "    vuln-pkg run dvwa          # Run DVWA"
        Write-Host "    vuln-pkg --help            # Show all commands"
        Write-Host ""

        # Check for Docker
        $dockerInstalled = Get-Command docker -ErrorAction SilentlyContinue
        if (-not $dockerInstalled) {
            Write-Warn "Docker is not installed. vuln-pkg requires Docker to run."
            Write-Host "  Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/"
            Write-Host ""
        }
        else {
            try {
                docker info 2>&1 | Out-Null
            }
            catch {
                Write-Warn "Docker is installed but not running. Please start Docker Desktop."
                Write-Host ""
            }
        }
    }
    finally {
        # Cleanup
        if (Test-Path $TmpDir) {
            Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Main
