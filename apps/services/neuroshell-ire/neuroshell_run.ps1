<#
.SYNOPSIS
    Start the NeuroShell services (C1 IRE, C2 Dynamic Planner, C3 AEERE,
    C4 AVAE, Web UI) as background daemons.

.DESCRIPTION
    C1  = NeuroShell IRE            (port 8001)  venv: .venv,            app: src.api.main
    C2  = Dynamic Planner & RAG     (port 8002)  venv: c2venv,           app: src.api.main
    C3  = AEERE                     (port 8003)  venv: app/.venv,        app: src.api.main  (cwd = app)
    C4  = AVAE                      (port 8004)  venv: app/.venv,        app: src.api.main  (cwd = app)
    Web = NeuroShell Console UI     (port 5173)  Vite dev server         (apps\web)
    Kali= Docker readiness: ensures the Docker daemon is up, the 'neuroshell-kali'
          image is built from the C3 Dockerfile, and keeps a persistent warm
          container 'neuroshell-kali-active' running (started automatically
          whenever C3 is part of the target set).
    Redis= Docker readiness: ensures the 'redis:7-alpine' image is pulled and a
          'neuroshell-redis' container runs on 6379 (C3's session state store,
          started automatically whenever C3 is part of the target set).

    By default starts ALL. Use -Service C1|C2|C3|C4|Web|Kali|Redis|Both to select.
    Each service gets its own PID file so neuroshell_stop.ps1 can kill the
    whole process tree:
        ./.uvicorn.pid                      (C1)
        ../dynamic-planner-rag/.c2.pid      (C2)
        ../adaptive-execution-error-recovery/app/.c3.pid  (C3)
        ../ai-vulnerability-analysis/app/.c4.pid          (C4)
        ../../web/.web.pid                  (Web)

.EXAMPLE
    .\neuroshell_run.ps1                   # start ALL services (+ Kali & Redis containers)
    .\neuroshell_run.ps1 -Service C1       # only C1 (with reload)
    .\neuroshell_run.ps1 -Service C2       # only C2
    .\neuroshell_run.ps1 -Service C3       # C3 (Kali & Redis containers ensured first)
    .\neuroshell_run.ps1 -Service C4       # only C4
    .\neuroshell_run.ps1 -Service Web      # only the web UI
    .\neuroshell_run.ps1 -Service Kali     # just ensure Docker + Kali container
    .\neuroshell_run.ps1 -Service Redis    # just ensure Docker + Redis container
    .\neuroshell_run.ps1 -Service Both     # C1 + C2
    .\neuroshell_run.ps1 -Reload           # C1 with file-watch reload (others never reload)
    .\neuroshell_run.ps1 -NoReload         # accepted for backward compatibility
#>
[CmdletBinding()]
param(
    [ValidateSet('C1', 'C2', 'C3', 'C4', 'Web', 'Kali', 'Redis', 'Both', 'All')]
    [string]$Service = 'All',
    [int]$Port = 8001,
    [switch]$Reload,
    [switch]$NoReload
)

$ErrorActionPreference = 'Stop'

# ── Project-root detection: this script works from the service dir OR from
#    the repo root (F:\neuroshell-core), where copies are kept too. ──────────
function Get-ProjectRoot {
    $dir = $PSScriptRoot
    while ($dir) {
        if ((Test-Path -LiteralPath (Join-Path $dir 'apps\services\neuroshell-ire')) -and
            (Test-Path -LiteralPath (Join-Path $dir 'apps\web'))) {
            return $dir
        }
        $parent = Split-Path -LiteralPath $dir -Parent
        if (-not $parent -or $parent -eq $dir) { return $null }
        $dir = $parent
    }
    return $null
}

$ProjectRoot = Get-ProjectRoot
if (-not $ProjectRoot) {
    Write-Host "[ERROR] Could not locate the project root from $PSScriptRoot" -ForegroundColor Red
    exit 1
}

$Root     = Join-Path $ProjectRoot 'apps\services\neuroshell-ire'
$C2Root   = Join-Path $ProjectRoot 'apps\services\dynamic-planner-rag'
$C3Root   = Join-Path $ProjectRoot 'apps\services\adaptive-execution-error-recovery'
$C4Root   = Join-Path $ProjectRoot 'apps\services\ai-vulnerability-analysis'
$C3App    = Join-Path $C3Root 'app'
$C4App    = Join-Path $C4Root 'app'
$WebRoot  = Join-Path $ProjectRoot 'apps\web'


function Test-PortFree([int]$PortNo) {
    $listener = Get-NetTCPConnection -LocalPort $PortNo -State Listen -ErrorAction SilentlyContinue
    return $null -eq $listener
}


function Wait-DockerEngine([int]$TimeoutSeconds = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        & docker info *> $null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}


function Ensure-DockerEngine {

    # Native docker commands write to stderr when failing; keep the script's
    # strict ErrorActionPreference from turning those into terminating errors.
    $ErrorActionPreference = 'Continue'

    $dockerCli = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCli) {
        Write-Host "[ERROR] 'docker' not found in PATH. Install Docker Desktop first." -ForegroundColor Red
        return $false
    }

    & docker info *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "     Docker engine : $(& docker version --format '{{.Server.Version}}')"
        return $true
    }

    # ── Engine down: auto-start Docker Desktop and wait ──
    $dockerExe = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $dockerExe) {
        Write-Host "[ERROR] Docker Desktop not found - start it manually and re-run." -ForegroundColor Red
        return $false
    }
    Write-Host "[..] Docker engine down - starting Docker Desktop..." -ForegroundColor Yellow
    Start-Process -FilePath $dockerExe | Out-Null
    if (Wait-DockerEngine 180) {
        Write-Host "[OK] Docker engine ready" -ForegroundColor Green
        return $true
    }
    Write-Host "[ERROR] Docker engine did not come up within 180s - check Docker Desktop." -ForegroundColor Red
    return $false
}


function Start-Kali {

    Write-Host "[..] Ensuring Docker daemon + Kali container..."
    if (-not (Ensure-DockerEngine)) { return $false }

    $KaliImage  = 'neuroshell-kali'
    $KaliName   = 'neuroshell-kali-active'
    $Dockerfile = Join-Path $C3App 'Dockerfile'

    # ── Ensure the image exists (build once from the C3 Dockerfile) ──
    & docker image inspect $KaliImage *> $null
    if ($LASTEXITCODE -ne 0) {
        if (-not (Test-Path -LiteralPath $Dockerfile)) {
            Write-Host "[ERROR] Dockerfile not found at $Dockerfile" -ForegroundColor Red
            return $false
        }
        Write-Host "[..] Image '$KaliImage' missing - building (large, one-time)..." -ForegroundColor Yellow
        Push-Location -LiteralPath $C3App
        try {
            & docker build -t $KaliImage .
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[ERROR] docker build failed for $KaliImage" -ForegroundColor Red
                return $false
            }
        } finally {
            Pop-Location
        }
    }

    # ── Keep a warm persistent container running ──
    $running = (& docker ps -q -f "name=$KaliName")
    if ($running) {
        Write-Host "[OK] Kali container already active ($($running.Trim()))" -ForegroundColor Green
        return $true
    }

    $existing = (& docker ps -aq -f "name=$KaliName")
    if ($existing) {
        & docker start $KaliName *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Kali container restarted" -ForegroundColor Green
            return $true
        }
    }

    & docker run -d --name $KaliName $KaliImage sleep infinity *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] failed to start Kali container" -ForegroundColor Red
        return $false
    }
    Write-Host "[OK] Kali container active ($KaliName)" -ForegroundColor Green
    return $true
}


function Start-Redis {

    Write-Host "[..] Ensuring Docker daemon + Redis container..."
    if (-not (Ensure-DockerEngine)) { return $false }

    $RedisImage = 'redis:7-alpine'
    $RedisName  = 'neuroshell-redis'

    # ── Ensure the image exists ──
    & docker image inspect $RedisImage *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[..] Pulling $RedisImage ..." -ForegroundColor Yellow
        & docker pull $RedisImage *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] docker pull failed for $RedisImage" -ForegroundColor Red
            return $false
        }
    }

    # ── Keep a persistent container running on 6379 ──
    $running = (& docker ps -q -f "name=$RedisName")
    if ($running) {
        Write-Host "[OK] Redis container already active ($($running.Trim()))" -ForegroundColor Green
        return $true
    }

    $existing = (& docker ps -aq -f "name=$RedisName")
    if ($existing) {
        & docker start $RedisName *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Redis container restarted" -ForegroundColor Green
            return $true
        }
    }

    & docker run -d --name $RedisName -p 6379:6379 --restart unless-stopped $RedisImage *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] failed to start Redis container" -ForegroundColor Red
        return $false
    }
    Write-Host "[OK] Redis container active ($RedisName)" -ForegroundColor Green
    return $true
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


function Start-C3 {

    $Py      = Join-Path $C3App '.venv\Scripts\python.exe'
    $OutLog  = Join-Path $C3App 'c3_server.log'
    $ErrLog  = Join-Path $C3App 'c3_server.err'
    $PidFile = Join-Path $C3App '.c3.pid'
    $C3Port  = 8003

    if (-not (Test-Path -LiteralPath $Py)) {
        Write-Host "[ERROR] C3 venv not found at $Py" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path -LiteralPath $C3App)) {
        Write-Host "[ERROR] C3 app root not found at $C3App" -ForegroundColor Red
        return $false
    }
    if (-not (Test-PortFree $C3Port)) {
        Write-Host "[WARN] C3 port $C3Port already in use - skipping" -ForegroundColor Yellow
        return $false
    }

    $args = @('-m', 'uvicorn', 'src.api.main:app', '--host', '127.0.0.1',
              '--port', "$C3Port")

    $p = Start-Process -FilePath $Py -ArgumentList $args -WorkingDirectory $C3App `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -NoNewWindow
    $p.Id | Set-Content -LiteralPath $PidFile

    Write-Host "[OK] C3 started" -ForegroundColor Green
    Write-Host "     PID    : $($p.Id)"
    Write-Host "     URL    : http://127.0.0.1:$C3Port"
    Write-Host "     Docs   : http://127.0.0.1:$C3Port/docs"
    Write-Host "     Logs   : $OutLog"
    return $true
}


function Start-C4 {

    $Py      = Join-Path $C4App '.venv\Scripts\python.exe'
    $OutLog  = Join-Path $C4App 'c4_server.log'
    $ErrLog  = Join-Path $C4App 'c4_server.err'
    $PidFile = Join-Path $C4App '.c4.pid'
    $C4Port  = 8004

    if (-not (Test-Path -LiteralPath $Py)) {
        Write-Host "[ERROR] C4 venv not found at $Py" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path -LiteralPath $C4App)) {
        Write-Host "[ERROR] C4 app root not found at $C4App" -ForegroundColor Red
        return $false
    }
    if (-not (Test-PortFree $C4Port)) {
        Write-Host "[WARN] C4 port $C4Port already in use - skipping" -ForegroundColor Yellow
        return $false
    }

    $args = @('-m', 'uvicorn', 'src.api.main:app', '--host', '127.0.0.1',
              '--port', "$C4Port")

    $p = Start-Process -FilePath $Py -ArgumentList $args -WorkingDirectory $C4App `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -NoNewWindow
    $p.Id | Set-Content -LiteralPath $PidFile

    Write-Host "[OK] C4 started" -ForegroundColor Green
    Write-Host "     PID    : $($p.Id)"
    Write-Host "     URL    : http://127.0.0.1:$C4Port"
    Write-Host "     Docs   : http://127.0.0.1:$C4Port/docs"
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
    'C1'     { $startTargets += 'C1' }
    'C2'     { $startTargets += 'C2' }
    'C3'     { $startTargets += 'C3' }
    'C4'     { $startTargets += 'C4' }
    'Web'    { $startTargets += 'Web' }
    'Kali'   { $startTargets += 'Kali' }
    'Redis'  { $startTargets += 'Redis' }
    'Both'   { $startTargets += 'C1'; $startTargets += 'C2' }
    'All'    { $startTargets += 'C1'; $startTargets += 'C2'; $startTargets += 'C3'; $startTargets += 'C4'; $startTargets += 'Web' }
}

# Docker + Kali + Redis must be active before AEERE (C3) starts, or whenever
# explicitly requested. If a C3 prerequisite fails, C3 is NOT started.
$kaliOk = $true
$redisOk = $true
if ('C3' -in $startTargets -or 'Kali' -in $startTargets) {
    $kaliOk = Start-Kali
}
if ('C3' -in $startTargets -or 'Redis' -in $startTargets) {
    $redisOk = Start-Redis
}

if ('C3' -in $startTargets -and (-not $kaliOk -or -not $redisOk)) {
    Write-Host "[ERROR] C3 prerequisites failed (Docker/Kali/Redis) - skipping C3 start." -ForegroundColor Red
    $startTargets = @($startTargets | Where-Object { $_ -ne 'C3' })
}

foreach ($svc in $startTargets) {
    switch ($svc) {
        'C1'  { Start-C1 -PortNo $Port -UseReload:$Reload | Out-Null }
        'C2'  { Start-C2 | Out-Null }
        'C3'  { Start-C3 | Out-Null }
        'C4'  { Start-C4 | Out-Null }
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

if ('C3' -in $startTargets) {
    $ok = Wait-Healthy "http://127.0.0.1:8003/health" 60
    if ($ok) {
        Write-Host "[OK] C3 healthy at http://127.0.0.1:8003/health" -ForegroundColor Green
    } else {
        Write-Host "[WARN] C3 not healthy yet - check logs at $C3App\c3_server.log" -ForegroundColor Yellow
    }
}

if ('C4' -in $startTargets) {
    $ok = Wait-Healthy "http://127.0.0.1:8004/" 60
    if ($ok) {
        Write-Host "[OK] C4 healthy at http://127.0.0.1:8004/" -ForegroundColor Green
    } else {
        Write-Host "[WARN] C4 not healthy yet - check logs at $C4App\c4_server.log" -ForegroundColor Yellow
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