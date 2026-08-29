<#
.SYNOPSIS
    Stop the NeuroShell services (C1 IRE, C2 Dynamic Planner, Web UI).

.DESCRIPTION
    Kills the full process trees started by neuroshell_run.ps1 for all
    services, then falls back to killing whatever is listening on ports
    8001 (C1), 8002 (C2) and 5173 (Web). Removes all PID files.

.EXAMPLE
    .\neuroshell_stop.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'

$Root    = $PSScriptRoot
$C2Root  = Join-Path $Root '..\dynamic-planner-rag'
$WebRoot = Join-Path $Root '..\..\web'
$stopped = $false


function Stop-ServiceTree([string]$PidFile, [int]$PortNo, [string]$Label) {
    if (Test-Path -LiteralPath $PidFile) {
        $savedPid = (Get-Content -LiteralPath $PidFile).Trim()
        if ($savedPid -match '^\d+$') {
            taskkill /PID $savedPid /T /F 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] $Label PID $savedPid (and children) stopped" -ForegroundColor Green
                $script:stopped = $true
            }
        }
        Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
    }

    $listener = Get-NetTCPConnection -LocalPort $PortNo -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $listener) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Killed process $($conn.OwningProcess) holding port $PortNo" -ForegroundColor Green
        $script:stopped = $true
    }
}


Stop-ServiceTree (Join-Path $Root '.uvicorn.pid') 8001 'C1'
Stop-ServiceTree (Join-Path $C2Root '.c2.pid')    8002 'C2'
Stop-ServiceTree (Join-Path $WebRoot '.web.pid')  5173 'Web'

if (-not $stopped) {
    Write-Host "[WARN] No NeuroShell services appear to be running" -ForegroundColor Yellow
}