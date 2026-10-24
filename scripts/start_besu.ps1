<#
.SYNOPSIS
    Starts a local private Hyperledger Besu QBFT node for VERITAS-Vault.
.DESCRIPTION
    Launches Besu using the lightweight single-validator QBFT configuration
    with restricted JVM memory (max 512MB heap) suited for a 16GB laptop.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$besuConfig = Join-Path $root "contracts\besu\config.toml"
$dataDir = Join-Path $root "data\besu"

if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}

Write-Host "=== VERITAS-Vault Hyperledger Besu QBFT Launcher ===" -ForegroundColor Cyan
Write-Host "Config: $besuConfig"
Write-Host "Data:   $dataDir"

# Check if Besu binary is installed
$besuCmd = Get-Command "besu" -ErrorAction SilentlyContinue

if ($besuCmd) {
    Write-Host "Found Besu binary at $($besuCmd.Source)" -ForegroundColor Green
    & besu --config-file="$besuConfig"
} else {
    Write-Host "[!] Hyperledger Besu executable 'besu' not found in PATH." -ForegroundColor Yellow
    Write-Host "To install Besu on Windows:" -ForegroundColor Cyan
    Write-Host "  1. Install Java 21+: choco install openjdk21 -y"
    Write-Host "  2. Install Besu:     choco install hyperledger-besu -y"
    Write-Host "  3. Or run via Docker: docker run -p 8545:8545 -v ${root}:/opt/besu hyperledger/besu:latest --config-file=/opt/besu/contracts/besu/config.toml"
}
