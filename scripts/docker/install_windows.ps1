$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

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

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "Command failed: $FilePath $($Arguments -join ' ')"
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
        Fail "Cannot access the Docker daemon. Start Docker Desktop and rerun this script."
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

function Wait-ForHttp([string]$Name, [string]$Url, [int]$TimeoutSeconds = 90) {
    Write-Host "Waiting for $Name at $Url..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                Write-Host "  $Name ready" -ForegroundColor Green
                return
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    Fail "$Name failed to become ready at $Url"
}

function Stop-ExistingLocalApps([string]$ApiPort, [string]$FrontendPort) {
    $patterns = @(
        "uvicorn main:app.*--port $ApiPort",
        "vite.*--port $FrontendPort",
        "npm.*run dev"
    )
    foreach ($pattern in $patterns) {
        Get-CimInstance Win32_Process |
            Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host ""
Write-Host "RAPTOR - Full Docker Deployment" -ForegroundColor Cyan
Write-Host "=========================================="
Write-Host ""

Set-Location $RootDir

if (-not (Test-Path ".env")) {
    if (-not (Test-Path ".env.example")) {
        Fail ".env is missing and .env.example was not found"
    }
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

$compose = Get-ComposeCommand
$apiPort = Get-DotEnvValue "API_PORT" "8000"
$frontendPort = Get-DotEnvValue "FRONTEND_PORT" "3100"

Stop-ExistingLocalApps $apiPort $frontendPort

Write-Host "Starting RAPTOR (Full Docker Deployment)..." -ForegroundColor Yellow
Invoke-Checked $compose.File ($compose.Args + @("up", "-d", "--build"))

Write-Host ""
Write-Host "Waiting for Docker services to become ready..." -ForegroundColor Yellow
foreach ($container in @("raptor-neo4j", "raptor-weaviate", "raptor-elastic", "raptor-redis", "raptor-backend")) {
    Wait-ForContainerHealth $container
}
Wait-ForHttp "Frontend Dashboard" "http://localhost:$frontendPort/"
Wait-ForHttp "Backend API" "http://localhost:$apiPort/api/v1/health"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RAPTOR is now running in Docker!" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:  http://localhost:$frontendPort"
Write-Host "  API Docs:   http://localhost:$apiPort/docs"
Write-Host "  Neo4j UI:   http://localhost:7474" -ForegroundColor DarkGray
Write-Host "  Weaviate:   http://localhost:8080" -ForegroundColor DarkGray
Write-Host "  Elastic:    http://localhost:9200" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
