$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ApiPort = if ($env:API_PORT) { $env:API_PORT } else { "8000" }
$FrontendPort = if ($env:FRONTEND_PORT) { $env:FRONTEND_PORT } else { "3100" }
$BackendOutLog = Join-Path $RootDir "backend\backend.log"
$BackendErrLog = Join-Path $RootDir "backend\backend.err.log"
$FrontendOutLog = Join-Path $RootDir "frontend\frontend.log"
$FrontendErrLog = Join-Path $RootDir "frontend\frontend.err.log"

function Fail($Message) {
    Write-Host ""
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

function Need-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Fail "$Name is required but was not found in PATH"
    }
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory = $RootDir) {
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            Fail "Command failed: $FilePath $($Arguments -join ' ')"
        }
    } finally {
        Pop-Location
    }
}

function ConvertTo-ArgumentString([string[]]$Arguments) {
    ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_ -replace '\\(?=\\*")', '$&$&' -replace '"', '\"') + '"'
        } else {
            $_
        }
    }) -join " "
}

function Test-Checked([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 20) {
    $stdout = New-TemporaryFile
    $stderr = New-TemporaryFile
    $process = [System.Diagnostics.Process]::new()
    try {
        $process.StartInfo.FileName = $FilePath
        $process.StartInfo.Arguments = ConvertTo-ArgumentString $Arguments
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        [void]$process.Start()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            return $false
        }
        return $process.ExitCode -eq 0
    } finally {
        if ($process) {
            $process.Dispose()
        }
        Remove-Item $stdout.FullName, $stderr.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Get-ComposeCommand {
    Need-Command "docker"

    if (-not (Test-Checked "docker" @("info"))) {
        Fail "Cannot access the Docker daemon. Start Docker Desktop, or rerun with RAPTOR_SKIP_INFRA=true if infrastructure is already running."
    }

    if (Test-Checked "docker" @("compose", "version")) {
        return @{ File = "docker"; Args = @("compose") }
    }

    if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
        if (Test-Checked "docker-compose" @("version")) {
            return @{ File = "docker-compose"; Args = @() }
        }
    }

    Fail "Docker is available, but neither 'docker compose' nor 'docker-compose' works"
}

function Get-DotEnvValue([string]$Name, [string]$DefaultValue) {
    $fromEnvironment = [Environment]::GetEnvironmentVariable($Name)
    if ($fromEnvironment) {
        return $fromEnvironment
    }

    $envPath = Join-Path $RootDir ".env"
    if (Test-Path $envPath) {
        $match = Get-Content $envPath | Where-Object { $_ -match "^\s*$([regex]::Escape($Name))\s*=" } | Select-Object -First 1
        if ($match) {
            return (($match -split "=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }

    return $DefaultValue
}

function Wait-ForContainerHealth([string]$ContainerName, [int]$TimeoutSeconds = 180) {
    Write-Host "Waiting for $ContainerName..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $health = (& docker inspect --format='{{.State.Health.Status}}' $ContainerName 2>$null)
            $inspectOk = $LASTEXITCODE -eq 0
        } finally {
            $ErrorActionPreference = $oldPreference
        }
        if ($inspectOk -and $health -eq "healthy") {
            Write-Host "  $ContainerName healthy" -ForegroundColor Green
            return
        }
        Start-Sleep -Seconds 2
    }
    Fail "$ContainerName did not become healthy. Check logs with: docker logs $ContainerName"
}

function Wait-ForHttp([string]$Name, [string]$Url, [System.Diagnostics.Process]$Process, [string[]]$Logs, [int]$TimeoutSeconds = 60) {
    Write-Host "Waiting for $Name at $Url..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Process -and $Process.HasExited) {
            Write-Host "$Name exited before becoming ready. Last log lines:" -ForegroundColor Red
            foreach ($log in $Logs) {
                if (Test-Path $log) {
                    Get-Content $log -Tail 80
                }
            }
            Fail "$Name failed to start"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                Write-Host "  $Name ready" -ForegroundColor Green
                return
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }

    Write-Host "$Name did not become ready. Last log lines:" -ForegroundColor Red
    foreach ($log in $Logs) {
        if (Test-Path $log) {
            Get-Content $log -Tail 80
        }
    }
    Fail "$Name failed to start on $Url"
}

function Stop-ExistingApps {
    $patterns = @(
        "uvicorn main:app",
        "vite.*--port $FrontendPort",
        "npm.*run dev"
    )
    foreach ($pattern in $patterns) {
        Get-CimInstance Win32_Process |
            Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}

function Stop-DockerAppContainers {
    if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
        return
    }
    if (-not (Test-Checked "docker" @("info") 5)) {
        return
    }

    foreach ($container in @("raptor-frontend", "raptor-backend")) {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & docker stop $container *> $null
        } finally {
            $ErrorActionPreference = $oldPreference
        }
    }
}

Write-Host ""
Write-Host "RAPTOR - Hybrid Local Deployment" -ForegroundColor Cyan
Write-Host "=========================================="
Write-Host ""

Need-Command "python"
Need-Command "npm.cmd"

Set-Location $RootDir
if (-not (Test-Path ".env")) {
    if (-not (Test-Path ".env.example")) {
        Fail ".env is missing and .env.example was not found"
    }
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

$ApiPort = Get-DotEnvValue "API_PORT" $ApiPort
$FrontendPort = Get-DotEnvValue "FRONTEND_PORT" $FrontendPort

if ($env:RAPTOR_SKIP_INFRA -eq "true") {
    Write-Host "[1/6] Skipping Infrastructure (RAPTOR_SKIP_INFRA=true)..." -ForegroundColor Yellow
    Write-Host "[2/6] Skipping container health checks..." -ForegroundColor Yellow
} else {
    $compose = Get-ComposeCommand
    Write-Host "[1/6] Starting Infrastructure (Docker)..." -ForegroundColor Yellow
    Invoke-Checked $compose.File ($compose.Args + @("up", "-d", "neo4j", "weaviate", "elasticsearch", "redis"))

    Write-Host "[2/6] Waiting for services to become healthy..." -ForegroundColor Yellow
    foreach ($container in @("raptor-neo4j", "raptor-weaviate", "raptor-elastic", "raptor-redis")) {
        Wait-ForContainerHealth $container
    }
}

Write-Host "[3/6] Checking Backend Python dependencies..." -ForegroundColor Yellow
$dependencyCheck = @'
import re
import sys
from importlib.metadata import PackageNotFoundError, distribution

try:
    from packaging.requirements import Requirement
except Exception:
    Requirement = None

missing = []
with open("requirements.txt", encoding="utf-8") as requirements:
    for raw in requirements:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        requirement = None
        if Requirement is not None:
            try:
                requirement = Requirement(line)
                name = requirement.name
            except Exception:
                name = re.split(r"[<>=;\s\[]", line, 1)[0]
        else:
            name = re.split(r"[<>=;\s\[]", line, 1)[0]
        if not name:
            continue
        try:
            installed = distribution(name)
        except PackageNotFoundError:
            missing.append(name)
            continue
        if requirement is not None and requirement.specifier and installed.version not in requirement.specifier:
            missing.append(f"{name} {installed.version} does not satisfy {requirement.specifier}")

if missing:
    print("Missing Python packages: " + ", ".join(sorted(set(missing))))
    sys.exit(1)
'@
Push-Location (Join-Path $RootDir "backend")
$dependencyScript = New-TemporaryFile
try {
    Set-Content -Path $dependencyScript.FullName -Value $dependencyCheck -Encoding UTF8
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & python $dependencyScript.FullName
    $dependenciesReady = $LASTEXITCODE -eq 0
} finally {
    $ErrorActionPreference = $oldPreference
    Remove-Item $dependencyScript.FullName -Force -ErrorAction SilentlyContinue
    Pop-Location
}
if (-not $dependenciesReady) {
    Invoke-Checked "python" @("-m", "pip", "install", "-r", "requirements.txt") (Join-Path $RootDir "backend")
}

Write-Host "[4/6] Installing Frontend dependencies..." -ForegroundColor Yellow
Invoke-Checked "npm.cmd" @("install") (Join-Path $RootDir "frontend")

Write-Host "[5/6] Starting Backend API (FastAPI on :$ApiPort)..." -ForegroundColor Yellow
Stop-ExistingApps
Stop-DockerAppContainers
foreach ($log in @($BackendOutLog, $BackendErrLog, $FrontendOutLog, $FrontendErrLog)) {
    if (Test-Path $log) {
        Remove-Item $log -Force
    }
}
$backend = Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", $ApiPort -WorkingDirectory (Join-Path $RootDir "backend") -WindowStyle Hidden -RedirectStandardOutput $BackendOutLog -RedirectStandardError $BackendErrLog -PassThru
Wait-ForHttp "Backend API" "http://localhost:$ApiPort/api/v1/health" $backend @($BackendOutLog, $BackendErrLog)

Write-Host "[6/6] Starting Frontend Dashboard (Vite on :$FrontendPort)..." -ForegroundColor Yellow
$frontend = Start-Process -FilePath "npm.cmd" -ArgumentList "run", "dev", "--", "--host", "0.0.0.0", "--port", $FrontendPort -WorkingDirectory (Join-Path $RootDir "frontend") -WindowStyle Hidden -RedirectStandardOutput $FrontendOutLog -RedirectStandardError $FrontendErrLog -PassThru
Wait-ForHttp "Frontend Dashboard" "http://localhost:$FrontendPort/" $frontend @($FrontendOutLog, $FrontendErrLog)

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RAPTOR is now running!" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:    http://localhost:$FrontendPort"
Write-Host "  API Docs:     http://localhost:$ApiPort/docs"
Write-Host "  Neo4j UI:     http://localhost:7474" -ForegroundColor DarkGray
Write-Host "  Weaviate:     http://localhost:8080" -ForegroundColor DarkGray
Write-Host "  Elastic:      http://localhost:9200" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Backend log:  $BackendOutLog"
Write-Host "  Frontend log: $FrontendOutLog"
Write-Host "  Mock Data:    $RootDir\data\mock\apt29_campaign.json" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
