<#
.SYNOPSIS
    Start the NeuroShell services (C1 IRE, C2 Dynamic Planner, Web UI) as
    background daemons.

.DESCRIPTION
    C1  = NeuroShell IRE            (port 8001)  venv: .venv,       app: src.api.main
    C2  = Dynamic Planner & RAG     (port 8002)  venv: c2venv,      app: src.api.main
    Web = NeuroShell Console UI     (port 5173)  Vite dev server     (apps\web)

    By default starts ALL THREE. Use -Service C1|C2|Web|Both to select.
    Each service gets its own PID file so neuroshell_stop.ps1 can kill the
    whole process tree:
        ./.uvicorn.pid                (C1)
        ../dynamic-planner-rag/.c2.pid  (C2)
        ../../web/.web.pid            (Web)

.EXAMPLE
    .\neuroshell_run.ps1               # start C1 + C2 + Web (no reload)
    .\neuroshell_run.ps1 -Service C1   # only C1 (with reload)
    .\neuroshell_run.ps1 -Service C2   # only C2
    .\neuroshell_run.ps1 -Service Web  # only the web UI
    .\neuroshell_run.ps1 -Reload       # C1 with file-watch reload (C2/Web never reload)
    .\neuroshell_run.ps1 -NoReload     # accepted for backward compatibility
#>
[CmdletBinding()]
param(
    [ValidateSet('C1', 'C2', 'Web', 'Both', 'All')]
    [string]$Service = 'All',
    [int]$Port = 8001,
    [switch]$Reload,
    [switch]$NoReload
)

$ErrorActionPreference = 'Stop'

$Root   = $PSScriptRoot
$C2Root = Join-Path $Root '..\dynamic-planner-rag'
$WebRoot = Join-Path $Root '..\..\web'


function Test-PortFree([int]$PortNo) {
    $listener = Get-NetTCPConnection -LocalPort $PortNo -State Listen -ErrorAction SilentlyContinue
    return $null -eq $listener
}


function Start-C1 {
    param([int]$PortNo, [switch]$UseReload)

    $Py     = Join-Path $Root '.venv\Scripts\python.exe'
    $LogDir = Join-Path $Root 'logs'
    $OutLog = Join-Path $LogDir 'uvicorn.out.log'
    $ErrLog = Join-Path $LogDir 'uvicorn.err.log'
    $PidFile = Join-Path $Root '.uvicorn.pid'

    if (-not (Test-Path -LiteralPath $Py)) {
        Write-Host "[ERROR] C1 venv not found at $Py" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir | Out-Null
    }
    if (-not (Test-PortFree $PortNo)) {
        Write-Host "[WARN] C1 port $PortNo already in use - skipping" -ForegroundColor Yellow
        return $false
    }

    $args = @('-m', 'uvicorn', 'src.api.main:app', '--host', '127.0.0.1',
              '--port', "$PortNo")
    if ($UseReload) { $args += '--reload' }

    $p = Start-Process -FilePath $Py -ArgumentList $args -WorkingDirectory $Root `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -NoNewWindow
    $p.Id | Set-Content -LiteralPath $PidFile

    Write-Host "[OK] C1 started" -ForegroundColor Green
    Write-Host "     PID    : $($p.Id)"
    Write-Host "     URL    : http://127.0.0.1:$PortNo"
    Write-Host "     Docs   : http://127.0.0.1:$PortNo/docs"
    Write-Host "     Logs   : $OutLog"
    return $true
}


function Start-C2 {

    $Py      = Join-Path $C2Root 'c2venv\Scripts\python.exe'
    $OutLog  = Join-Path $C2Root 'c2_server.log'
    $ErrLog  = Join-Path $C2Root 'c2_server.err'
    $PidFile = Join-Path $C2Root '.c2.pid'
    $C2Port  = 8002

    if (-not (Test-Path -LiteralPath $Py)) {
        Write-Host "[ERROR] C2 venv not found at $Py" -ForegroundColor Red
        return $false
    }
    if (-not (Test-PortFree $C2Port)) {
        Write-Host "[WARN] C2 port $C2Port already in use - skipping" -ForegroundColor Yellow
        return $false
    }

    $args = @('-m', 'uvicorn', 'src.api.main:app', '--host', '127.0.0.1',
              '--port', "$C2Port")

    $p = Start-Process -FilePath $Py -ArgumentList $args -WorkingDirectory $C2Root `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -NoNewWindow
    $p.Id | Set-Content -LiteralPath $PidFile

    Write-Host "[OK] C2 started" -ForegroundColor Green
    Write-Host "     PID    : $($p.Id)"
    Write-Host "     URL    : http://127.0.0.1:$C2Port"
    Write-Host "     Docs   : http://127.0.0.1:$C2Port/docs"
    Write-Host "     Logs   : $OutLog"
    return $true
}


function Start-Web {

    $WebPort  = 5173
    $OutLog   = Join-Path $WebRoot 'vite.out.log'
    $ErrLog   = Join-Path $WebRoot 'vite.err.log'
    $PidFile  = Join-Path $WebRoot '.web.pid'

    if (-not (Test-Path -LiteralPath $WebRoot)) {
        Write-Host "[ERROR] Web root not found at $WebRoot" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path -LiteralPath (Join-Path $WebRoot 'node_modules'))) {
        Write-Host '[..] Web dependencies missing - running npm install'
        Push-Location -LiteralPath $WebRoot
        try {
            & npm install
            if ($LASTEXITCODE -ne 0) { return $false }
        } finally {
            Pop-Location
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $WebRoot '.env'))) {
        Copy-Item -LiteralPath (Join-Path $WebRoot '.env.example') `
            -Destination (Join-Path $WebRoot '.env')
        Write-Host '[..] Created .env from .env.example - check Supabase values!'
    }
    if (-not (Test-PortFree $WebPort)) {
        Write-Host "[WARN] Web port $WebPort already in use - skipping" -ForegroundColor Yellow
        return $false
    }

    $args = @('run', 'dev', '--', '--port', "$WebPort", '--strictPort')

    $p = Start-Process -FilePath 'npm.cmd' -ArgumentList $args `
        -WorkingDirectory $WebRoot `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -NoNewWindow
    $p.Id | Set-Content -LiteralPath $PidFile

    Write-Host "[OK] Web UI started" -ForegroundColor Green
    Write-Host "     PID    : $($p.Id)"
    Write-Host "     URL    : http://127.0.0.1:$WebPort"
    Write-Host "     Logs   : $OutLog"
    return $true
}


function Wait-Healthy([string]$Url, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { $ok = $true; break }
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    return $ok
}


$startTargets = @()
switch ($Service) {
    'C1'  { $startTargets += 'C1' }
    'C2'  { $startTargets += 'C2' }
    'Web' { $startTargets += 'Web' }
    'Both' { $startTargets += 'C1'; $startTargets += 'C2' }
    'All' { $startTargets += 'C1'; $startTargets += 'C2'; $startTargets += 'Web' }
}

foreach ($svc in $startTargets) {
    switch ($svc) {
        'C1'  { Start-C1 -PortNo $Port -UseReload:$Reload | Out-Null }
        'C2'  { Start-C2 | Out-Null }
        'Web' { Start-Web | Out-Null }
    }
}

# ── Wait for health checks ────────────────────────────────────────────
Write-Host ""
if ('C1' -in $startTargets) {
    $ok = Wait-Healthy "http://127.0.0.1:$Port/health" 20
    if ($ok) {
        Write-Host "[OK] C1 healthy at http://127.0.0.1:$Port/health" -ForegroundColor Green
    } else {
        Write-Host "[WARN] C1 not healthy yet - check logs" -ForegroundColor Yellow
    }
}

if ('C2' -in $startTargets) {
    Write-Host "     (C2 is loading its LLM - first /plan may take a while)"
    $ok = Wait-Healthy "http://127.0.0.1:8002/health" 90
    if ($ok) {
        Write-Host "[OK] C2 healthy at http://127.0.0.1:8002/health" -ForegroundColor Green
    } else {
        Write-Host "[WARN] C2 not healthy yet - check logs at $C2Root\c2_server.log" -ForegroundColor Yellow
    }
}

if ('Web' -in $startTargets) {
    $ok = Wait-Healthy "http://127.0.0.1:5173" 30
    if ($ok) {
        Write-Host "[OK] Web UI healthy at http://127.0.0.1:5173" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Web UI not healthy yet - check logs at $WebRoot\vite.out.log" -ForegroundColor Yellow
    }
}