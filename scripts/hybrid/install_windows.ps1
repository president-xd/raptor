$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host ""
Write-Host "  ██████   █████  ██████  ████████  ██████  ██████  " -ForegroundColor Red
Write-Host "  ██   ██ ██   ██ ██   ██    ██    ██    ██ ██   ██ " -ForegroundColor Red
Write-Host "  ██████  ███████ ██████     ██    ██    ██ ██████  " -ForegroundColor Red
Write-Host "  ██   ██ ██   ██ ██         ██    ██    ██ ██   ██ " -ForegroundColor Red
Write-Host "  ██   ██ ██   ██ ██         ██     ██████  ██   ██ " -ForegroundColor Red
Write-Host ""
Write-Host "  Retrieval-Augmented Persistent Threat" -ForegroundColor DarkGray
Write-Host "  Orchestration and Reasoning            v1.0.0" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Infrastructure (Docker) ──────────────────────────────────────
Write-Host "[1/4] Starting Infrastructure (Docker)..." -ForegroundColor Yellow
Write-Host "       Neo4j · Weaviate · Elasticsearch · Redis" -ForegroundColor DarkGray
Set-Location $RootDir
docker-compose up -d neo4j weaviate elasticsearch redis

# ── 2. Wait for health ──────────────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Waiting for services to become healthy..." -ForegroundColor Yellow
$services = @("raptor-neo4j", "raptor-weaviate", "raptor-elastic", "raptor-redis")
$maxWait = 120
$elapsed = 0

foreach ($svc in $services) {
    $ready = $false
    while (-not $ready -and $elapsed -lt $maxWait) {
        $health = docker inspect --format='{{.State.Health.Status}}' $svc 2>$null
        if ($health -eq "healthy") {
            Write-Host "       [OK] $svc" -ForegroundColor Green
            $ready = $true
        } else {
            Start-Sleep -Seconds 3
            $elapsed += 3
            Write-Host "       ... waiting for $svc ($elapsed`s)" -ForegroundColor DarkGray
        }
    }
    if (-not $ready) {
        Write-Host "       [WARN] $svc did not become healthy within ${maxWait}s" -ForegroundColor Red
    }
}

# ── 3. Backend API ──────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Starting Backend API (FastAPI on :8000)..." -ForegroundColor Yellow
Start-Process -FilePath "python" -ArgumentList "-m uvicorn main:app --host 0.0.0.0 --port 8000" -WorkingDirectory "$RootDir\backend" -WindowStyle Normal

# ── 4. Frontend Dashboard ───────────────────────────────────────────
Write-Host "[4/4] Starting Frontend Dashboard (Vite on :3100)..." -ForegroundColor Yellow
Start-Process -FilePath "npm" -ArgumentList "run dev" -WorkingDirectory "$RootDir\frontend" -WindowStyle Normal

# ── Done ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RAPTOR is now running!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "  Dashboard:  http://localhost:3100" -ForegroundColor White
Write-Host "  API Docs:   http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Neo4j UI:   http://localhost:7474" -ForegroundColor DarkGray
Write-Host "  Weaviate:   http://localhost:8080" -ForegroundColor DarkGray
Write-Host "  Elastic:    http://localhost:9200" -ForegroundColor DarkGray
Write-Host "" -ForegroundColor White
Write-Host "  Mock Data:  $RootDir\data\mock\apt29_campaign.json" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
