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

Write-Host "Starting RAPTOR (Full Docker Deployment)..." -ForegroundColor Yellow
Set-Location $RootDir
docker-compose up -d

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RAPTOR is now running in Docker!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "  Dashboard:  http://localhost:3100" -ForegroundColor White
Write-Host "  API Docs:   http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Neo4j UI:   http://localhost:7474" -ForegroundColor DarkGray
Write-Host "  Weaviate:   http://localhost:8080" -ForegroundColor DarkGray
Write-Host "  Elastic:    http://localhost:9200" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
