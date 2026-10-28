<#
.SYNOPSIS
    Start the NeuroShell Console web UI (Vite dev server).

.DESCRIPTION
    Installs dependencies on first run, then serves the UI on
    http://127.0.0.1:5173 . Requires Supabase values in .env
    (copy from .env.example) and the C1/C2 backend running.

.EXAMPLE
    .\run_web.ps1
#>
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

Set-Location -LiteralPath $Root

if (-not (Test-Path -LiteralPath (Join-Path $Root 'node_modules'))) {
    Write-Host '[..] First run - installing dependencies (npm install)'
    & npm install
}

if (-not (Test-Path -LiteralPath (Join-Path $Root '.env'))) {
    Write-Host '[WARN] .env not found - copying from .env.example'
    Copy-Item -LiteralPath (Join-Path $Root '.env.example') -Destination (Join-Path $Root '.env')
}

Write-Host "[OK] Starting NeuroShell Console at http://127.0.0.1:5173" -ForegroundColor Green
& npm run dev