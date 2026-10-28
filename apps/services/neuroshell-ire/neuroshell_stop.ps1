<#
.SYNOPSIS
    Stop the NeuroShell services (C1 IRE, C2 Dynamic Planner, C3 AEERE,
    C4 AVAE, Web UI) by killing the PID-file process trees.

.DESCRIPTION
    For each service this reads the PID file (written by neuroshell_run.ps1)
    and kills the recorded process plus every descendant. This handles the
    .venv launcher shim case, where the real uvicorn runs in a child process
    that would otherwise be orphaned and keep the port bound.

    PID files:
        ./.uvicorn.pid                      (C1)
        ../dynamic-planner-rag/.c2.pid      (C2)
        ../adaptive-execution-error-recovery/app/.c3.pid  (C3)
        ../ai-vulnerability-analysis/app/.c4.pid          (C4)
        ../../web/.web.pid                  (Web)

    When 'All', 'Kali' or 'Redis' is targeted, the Docker containers
    'neuroshell-kali-active' and 'neuroshell-redis' are stopped and removed too.

    Use -Force to additionally kill anything still listening on the service
    ports even if its PID file is missing or the tree kill did not free a port.

.EXAMPLE
    .\neuroshell_stop.ps1                 # stop ALL services (+ Kali & Redis containers)
    .\neuroshell_stop.ps1 -Service C1     # stop only C1
    .\neuroshell_stop.ps1 -Service C1,C3  # stop C1 and C3
    .\neuroshell_stop.ps1 -Service Kali   # stop only the Kali container
    .\neuroshell_stop.ps1 -Service Redis  # stop only the Redis container
    .\neuroshell_stop.ps1 -Force          # stop all + force-free ports
#>
[CmdletBinding()]
param(
    [string[]]$Service = @('All'),
    [switch]$Force
)

$ErrorActionPreference = 'SilentlyContinue'

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

$Root    = Join-Path $ProjectRoot 'apps\services\neuroshell-ire'
$C2Root  = Join-Path $ProjectRoot 'apps\services\dynamic-planner-rag'
$C3App   = Join-Path $ProjectRoot 'apps\services\adaptive-execution-error-recovery\app'
$C4App   = Join-Path $ProjectRoot 'apps\services\ai-vulnerability-analysis\app'
$WebRoot = Join-Path $ProjectRoot 'apps\web'

$Services = @(
    [pscustomobject]@{ Name = 'C1';  PidFile = Join-Path $Root    '.uvicorn.pid';   Ports = @(8001) },
    [pscustomobject]@{ Name = 'C2';  PidFile = Join-Path $C2Root  '.c2.pid';        Ports = @(8002) },
    [pscustomobject]@{ Name = 'C3';  PidFile = Join-Path $C3App   '.c3.pid';        Ports = @(8003) },
    [pscustomobject]@{ Name = 'C4';  PidFile = Join-Path $C4App   '.c4.pid';        Ports = @(8004) },
    [pscustomobject]@{ Name = 'Web'; PidFile = Join-Path $WebRoot '.web.pid';       Ports = @(5173) }
)


function Get-Descendants([int]$ParentId) {
    $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId
    $desc = [System.Collections.Generic.List[int]]::new()
    $queue = [System.Collections.Generic.Queue[int]]::new()
    $queue.Enqueue($ParentId)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        foreach ($p in $all) {
            if ($p.ParentProcessId -eq $cur) {
                $desc.Add([int]$p.ProcessId)
                $queue.Enqueue([int]$p.ProcessId)
            }
        }
    }
    return $desc
}


function Stop-Tree([int]$ProcessId, [string]$Label) {
    $tree = Get-Descendants $ProcessId
    if ($tree.Count -gt 0) {
        foreach ($d in ($tree | Sort-Object -Descending)) {
            if (Get-Process -Id $d -ErrorAction SilentlyContinue) {
                try {
                    Stop-Process -Id $d -Force -ErrorAction Stop
                    Write-Host "     [killed] $Label descendant PID $d"
                } catch {
                    Write-Host "     [warn] could not kill $Label descendant PID $d : $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            Start-Sleep -Milliseconds 150
        }
    }
    if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
        for ($i = 0; $i -lt 3; $i++) {
            try {
                Stop-Process -Id $ProcessId -Force -ErrorAction Stop
                Write-Host "     [killed] $Label PID $ProcessId"
                break
            } catch {
                if ($i -eq 2) {
                    Write-Host "     [warn] could not kill $Label PID $ProcessId : $($_.Exception.Message)" -ForegroundColor Yellow
                } else {
                    Start-Sleep -Milliseconds 200
                }
            }
        }
    } else {
        Write-Host "     [skip] $Label PID $ProcessId is not running" -ForegroundColor Yellow
    }
}


function Test-PortsFree([int[]]$Ports) {
    $busy = @()
    foreach ($port in $Ports) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            $busy += $port
        }
    }
    return ($busy.Count -eq 0)
}


$targets = @()
if ($Service -contains 'All') {
    $targets = @($Services.Name)
} else {
    $targets = @($Service | Where-Object { $Services.Name -contains $_ -or $_ -eq 'Kali' -or $_ -eq 'Redis' })
    if ($targets.Count -eq 0) {
        Write-Host "[ERROR] Unknown service(s): $($Service -join ', ')" -ForegroundColor Red
        Write-Host "        Valid: $($Services.Name -join ', '), Kali, Redis, All"
        exit 1
    }
}

foreach ($name in ($targets | Where-Object { $_ -ne 'Kali' -and $_ -ne 'Redis' })) {
    $svc = $Services | Where-Object { $_.Name -eq $name }
    Write-Host "[..] Stopping $($svc.Name)..." -ForegroundColor Cyan

    $stopped = $false
    if (Test-Path -LiteralPath $svc.PidFile) {
        $pidValue = Get-Content -LiteralPath $svc.PidFile -Raw | ForEach-Object { $_.Trim() }
        if ($pidValue -match '^\d+$') {
            if (Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue) {
                Stop-Tree -ProcessId ([int]$pidValue) -Label $svc.Name
                $stopped = $true
            } else {
                Write-Host "     [skip] PID $pidValue is not running" -ForegroundColor Yellow
            }
        }
        Remove-Item -LiteralPath $svc.PidFile -ErrorAction SilentlyContinue
    }

    if ($Force -or -not $stopped) {
        foreach ($port in $svc.Ports) {
            $listeners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
            foreach ($conn in $listeners) {
                if ($conn.OwningProcess) {
                    Write-Host "     [found] $($svc.Name) listener on :$port is PID $($conn.OwningProcess)"
                    Stop-Tree -ProcessId ([int]$conn.OwningProcess) -Label "$($svc.Name)@$port"
                    $stopped = $true
                }
            }
        }
        if ($stopped) {
            $deadline = (Get-Date).AddSeconds(5)
            while (-not (Test-PortsFree $svc.Ports) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 250
                foreach ($port in $svc.Ports) {
                    $listeners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                    foreach ($conn in $listeners) {
                        if ($conn.OwningProcess) {
                            Stop-Tree -ProcessId ([int]$conn.OwningProcess) -Label "$($svc.Name)@$port"
                        }
                    }
                }
            }
        }
    }

    if ($stopped) {
        Write-Host "[OK] $($svc.Name) stopped" -ForegroundColor Green
    } else {
        Write-Host "[WARN] $($svc.Name) was not running" -ForegroundColor Yellow
    }
}

# ── Docker container teardown (Kali + Redis) ────────────────────────
$containerTargets = @()
if ('Kali' -in $targets)  { $containerTargets += 'neuroshell-kali-active' }
if ('Redis' -in $targets) { $containerTargets += 'neuroshell-redis' }

foreach ($cname in $containerTargets) {
    Write-Host "[..] Stopping Docker container '$cname'..." -ForegroundColor Cyan
    $id = (& docker ps -aq -f "name=$cname" 2>$null)
    if ($id) {
        & docker stop $cname *> $null
        if ($LASTEXITCODE -eq 0) {
            & docker rm $cname *> $null
            Write-Host "[OK] '$cname' stopped and removed" -ForegroundColor Green
        } else {
            Write-Host "[WARN] could not stop '$cname'" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] '$cname' not found - nothing to stop" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[OK] Done." -ForegroundColor Green