<#
.SYNOPSIS
    Starts VERITAS-Vault local security operations server.
.DESCRIPTION
    Launches the FastAPI backend and PWA static assets with Uvicorn.
    Serves the biometric checkpoint, enrollment station, control room, and audit ledger.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "=== VERITAS-Vault Security Systems Launcher ===" -ForegroundColor Cyan

# 1. Resolve Python executable
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonCmd = $venvPython
    Write-Host "[OK] Using virtual environment Python ($pythonCmd)" -ForegroundColor Green
} else {
    $pythonCmd = "python"
    Write-Host "[!] Virtual environment not found; using system Python." -ForegroundColor Yellow
}

# 2. Re-synchronize static PWA shells
Write-Host "Verifying PWA shell integrity..." -ForegroundColor Gray
& $pythonCmd "$root\scripts\build_shell.py"

# 3. Read configured port or default to 8502
$port = 8502
if ($env:PORT) {
    $port = [int]$env:PORT
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "VERITAS-Vault Server Running at: http://localhost:$port" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  * Biometric Checkpoint: http://localhost:$port/checkpoint" -ForegroundColor Cyan
Write-Host "  * Enrollment Station:   http://localhost:$port/enrollment" -ForegroundColor Cyan
Write-Host "  * System Control Room:  http://localhost:$port/control" -ForegroundColor Cyan
Write-Host "  * Forensics / Audit:    http://localhost:$port/audit" -ForegroundColor Cyan
Write-Host "  * API Documentation:    http://localhost:$port/docs" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

& $pythonCmd -m uvicorn app:app --host 127.0.0.1 --port $port --reload
