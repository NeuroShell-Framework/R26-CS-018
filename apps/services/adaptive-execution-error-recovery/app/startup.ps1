param(
    [switch]$Build = $false
)

$ErrorActionPreference = "Stop"

function Step {
    param([string]$msg)
    Write-Host "`n" -NoNewline
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}

# STEP 1: Check Python
Step "[1/7] Checking Python"
$pyver = python --version 2>&1
Write-Host "  $pyver" -ForegroundColor White

# STEP 2: Check Docker
Step "[2/7] Checking Docker"
$dockerOk = docker info 2>$null
if (-not $dockerOk) {
    Write-Host "  Docker not running, starting Docker Desktop..." -ForegroundColor Yellow
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -WindowStyle Hidden
    Write-Host "  Waiting for Docker to be ready..." -ForegroundColor Yellow
    $start = Get-Date
    $ready = $false
    while ((Get-Date).Subtract($start).TotalSeconds -lt 60) {
        Start-Sleep -Seconds 3
        $dockerOk = docker info 2>$null
        if ($dockerOk) {
            $ready = $true
            break
        }
        Write-Host "  Waiting..." -ForegroundColor DarkGray
    }
    if (-not $ready) {
        Write-Host "  ERROR: Docker did not start within 60 seconds" -ForegroundColor Red
        exit 1
    }
}
$dockerVer = docker version --format "{{.Server.Version}}" 2>$null
Write-Host "  Docker: $dockerVer" -ForegroundColor Green

# STEP 3: Check Redis
Step "[3/7] Checking Redis"
$redisRunning = docker ps --filter "name=neuroshell-redis" --format "{{.Names}}" 2>$null
if ($redisRunning -eq "neuroshell-redis") {
    Write-Host "  Redis container already running" -ForegroundColor Green
} else {
    $redisStopped = docker ps -a --filter "name=neuroshell-redis" --format "{{.Names}}" 2>$null
    if ($redisStopped -eq "neuroshell-redis") {
        Write-Host "  Starting stopped Redis container..." -ForegroundColor Yellow
        docker start neuroshell-redis | Out-Null
    } else {
        Write-Host "  Creating Redis container..." -ForegroundColor Yellow
        docker run -d --name neuroshell-redis -p 6379:6379 --restart unless-stopped redis:7-alpine | Out-Null
    }
    Start-Sleep -Seconds 2
}
$redisStatus = docker ps --filter "name=neuroshell-redis" --format "{{.Status}}"
Write-Host "  Redis: $redisStatus" -ForegroundColor Green

# STEP 4: Check Ollama
Step "[4/7] Checking Ollama"
$model = ollama list 2>$null | Select-String "qwen2.5-coder"
if (-not $model) {
    Write-Host "  WARNING: qwen2.5-coder not found. Run: ollama pull qwen2.5-coder:latest" -ForegroundColor Red
} else {
    Write-Host "  qwen2.5-coder model available" -ForegroundColor Green
}

# STEP 5: Check/build Kali image
Step "[5/7] Checking Kali image"
$kaliImage = docker images neuroshell-kali --format "{{.Repository}}" 2>$null
if ($kaliImage -eq "neuroshell-kali") {
    Write-Host "  Custom neuroshell-kali image found" -ForegroundColor Green
    $envContent = Get-Content .env
    $envContent = $envContent -replace 'KALI_IMAGE=.*', 'KALI_IMAGE=neuroshell-kali'
    Set-Content .env $envContent
} else {
    $hasKali = docker images kalilinux/kali-rolling --format "{{.Repository}}" 2>$null
    if ($hasKali) {
        Write-Host "  Using bare kalilinux/kali-rolling (no tools pre-installed)" -ForegroundColor Yellow
        Write-Host "  Tip: Run .\startup.ps1 -Build to create pre-installed image" -ForegroundColor Yellow
        $envContent = Get-Content .env
        $envContent = $envContent -replace 'KALI_IMAGE=.*', 'KALI_IMAGE=kalilinux/kali-rolling'
        Set-Content .env $envContent
    } else {
        Write-Host "  ERROR: No Kali image found" -ForegroundColor Red
        exit 1
    }
}

# STEP 6: Kill existing server
Step "[6/7] Restarting server"
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host "  Starting uvicorn on port 8003..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $scriptDir; .\.venv\Scripts\Activate.ps1; uvicorn src.api.main:app --host 0.0.0.0 --port 8003"

Write-Host "  Waiting for server to initialize..." -ForegroundColor Yellow
$serverReady = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8003/health" -ErrorAction Stop
        if ($resp.status -eq "healthy") {
            $serverReady = $true
            break
        }
    } catch {
        # Server not ready yet
    }
    Write-Host "  Waiting..." -ForegroundColor DarkGray
}

if ($serverReady) {
    Write-Host "  Server healthy!" -ForegroundColor Green
    Write-Host "  Docker: $($resp.docker)" -ForegroundColor Green
    Write-Host "  Redis: $($resp.redis)" -ForegroundColor Green
    Write-Host "  Model: $($resp.model)" -ForegroundColor Green
    Write-Host "  API: http://localhost:8003" -ForegroundColor Cyan
    Write-Host "  Docs: http://localhost:8003/docs" -ForegroundColor Cyan
} else {
    Write-Host "  ERROR: Server did not start within 60 seconds" -ForegroundColor Red
    exit 1
}

# STEP 7: Smoke test
Step "[7/7] Running smoke test"
try {
    $body = '{"command":"echo hello","tool":"echo","session_id":"smoke-001","intent_ref":"TEST","estimated_duration":"short"}'
    $result = Invoke-RestMethod -Uri "http://localhost:8003/execute" -Method Post -ContentType "application/json" -Body $body
    if ($result.status -eq "success") {
        $out = $result.stdout.Trim()
        Write-Host "  Smoke test PASSED: $out" -ForegroundColor Green
    } else {
        Write-Host "  Smoke test FAILED: status=$($result.status)" -ForegroundColor Red
    }
} catch {
    Write-Host "  Smoke test ERROR: $_" -ForegroundColor Red
}

Step "=== STARTUP COMPLETE ===" -ForegroundColor Green
