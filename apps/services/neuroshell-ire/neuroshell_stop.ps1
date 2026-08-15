<#
.SYNOPSIS
    Stop the NeuroShell IRE daemon.

.DESCRIPTION
    Kills the full process tree started by neuroshell_run.ps1 (handles the
    uvicorn --reload reloader + worker children). Falls back to killing
    whatever is listening on port 8001.

.EXAMPLE
    .\neuroshell_stop.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'

$Root    = $PSScriptRoot
$PidFile = Join-Path $Root '.uvicorn.pid'
$stopped = $false

if (Test-Path -LiteralPath $PidFile) {
    $savedPid = (Get-Content -LiteralPath $PidFile).Trim()
    if ($savedPid -match '^\d+$') {
        taskkill /PID $savedPid /T /F 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Daemon PID $savedPid (and children) stopped" -ForegroundColor Green
            $stopped = $true
        }
    }
}

$listener = Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $listener) {
    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Killed process $($conn.OwningProcess) holding port 8001" -ForegroundColor Green
    $stopped = $true
}

if (-not $stopped) {
    Write-Host "[WARN] No NeuroShell IRE daemon appears to be running" -ForegroundColor Yellow
}

Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
