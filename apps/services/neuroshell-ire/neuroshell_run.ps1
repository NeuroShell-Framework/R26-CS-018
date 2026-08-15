<#
.SYNOPSIS
    Start the NeuroShell IRE server as a background daemon.

.DESCRIPTION
    Launches uvicorn from the local .venv as a detached process, writes
    logs to ./logs/uvicorn.{out,err}.log and saves the process PID to
    ./.uvicorn.pid so neuroshell_stop.ps1 can kill the whole tree.

.EXAMPLE
    .\neuroshell_run.ps1               # port 8001, with reload
    .\neuroshell_run.ps1 -Port 8002    # custom port
    .\neuroshell_run.ps1 -NoReload     # no file-watch reload
#>
[CmdletBinding()]
param(
    [int]$Port = 8001,
    [switch]$NoReload
)

$ErrorActionPreference = 'Stop'

$Root    = $PSScriptRoot
$Py      = Join-Path $Root '.venv\Scripts\python.exe'
$LogDir  = Join-Path $Root 'logs'
$OutLog  = Join-Path $LogDir 'uvicorn.out.log'
$ErrLog  = Join-Path $LogDir 'uvicorn.err.log'
$PidFile = Join-Path $Root '.uvicorn.pid'

if (-not (Test-Path -LiteralPath $Py)) {
    Write-Host "[ERROR] Python venv not found at $Py" -ForegroundColor Red
    exit 1
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    Write-Host "[ERROR] Port $Port is already in use by PID(s): $($listener.OwningProcess -join ', ')" -ForegroundColor Red
    Write-Host "        Stop it first with:  .\neuroshell_stop.ps1" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$uvicornArgs = @('-m', 'uvicorn', 'src.api.main:app', '--host', '127.0.0.1', '--port', "$Port")
if (-not $NoReload) { $uvicornArgs += '--reload' }

$p = Start-Process -FilePath $Py -ArgumentList $uvicornArgs -WorkingDirectory $Root `
    -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -PassThru -NoNewWindow

$p.Id | Set-Content -LiteralPath $PidFile

Write-Host "[OK] NeuroShell IRE daemon started" -ForegroundColor Green
Write-Host "     PID    : $($p.Id)"
Write-Host "     URL    : http://127.0.0.1:$Port"
Write-Host "     Docs   : http://127.0.0.1:$Port/docs"
Write-Host "     Logs   : $OutLog"
Write-Host "     PID file: $PidFile"
