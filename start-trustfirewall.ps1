$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$backendDirectory = Join-Path $projectRoot 'backend'
$frontendDirectory = Join-Path $projectRoot 'frontend'
$venvDirectory = Join-Path $backendDirectory '.venv'
$pythonPath = Join-Path $venvDirectory 'Scripts\python.exe'
$backendPort = 8001
$frontendPort = 5173

$systemPython = Get-Command python -ErrorAction SilentlyContinue
if (-not $systemPython) {
    throw 'Python was not found. Install Python and make sure it is available on PATH.'
}

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) {
    throw 'npm was not found. Install Node.js and make sure npm is available on PATH.'
}

if (-not (Test-Path $pythonPath)) {
    Write-Host 'Creating the backend Python virtual environment...'
    & $systemPython.Source -m venv $venvDirectory
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the backend Python virtual environment.'
    }
}

Write-Host 'Checking and installing backend Python packages...'
& $pythonPath -m pip install --disable-pip-version-check -r (Join-Path $backendDirectory 'requirements.txt')
if ($LASTEXITCODE -ne 0) {
    throw 'Backend package installation failed.'
}

Write-Host 'Checking and installing frontend npm packages...'
Push-Location $frontendDirectory
try {
    & $npm.Source install --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) {
        throw 'Frontend package installation failed.'
    }
}
finally {
    Pop-Location
}

function Test-PortInUse([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect('127.0.0.1', $Port)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Wait-ForHttp([string]$Url, [string]$ServiceName, [int]$TimeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "$ServiceName did not become ready at $Url. Check its terminal window for errors."
}

$healthUrl = "http://127.0.0.1:$backendPort/health"
$backendReady = $false
try {
    $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
    $backendReady = $health.status -eq 'ok'
}
catch {
    $backendReady = $false
}

if (-not $backendReady) {
    if (Test-PortInUse $backendPort) {
        throw "Port $backendPort is already in use, but the TrustFirewall backend health check failed."
    }

    Write-Host "Starting backend at http://127.0.0.1:$backendPort ..."
    Start-Process -FilePath $pythonPath `
        -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--reload', '--host', '127.0.0.1', '--port', "$backendPort") `
        -WorkingDirectory $backendDirectory
    Wait-ForHttp $healthUrl 'Backend'
}
else {
    Write-Host "Backend is already running at http://127.0.0.1:$backendPort."
}

$frontendUrl = "http://127.0.0.1:$frontendPort/"
$frontendReady = $false
try {
    Invoke-WebRequest -Uri $frontendUrl -UseBasicParsing -TimeoutSec 2 | Out-Null
    $frontendReady = $true
}
catch {
    $frontendReady = $false
}

if (-not $frontendReady) {
    if (Test-PortInUse $frontendPort) {
        throw "Port $frontendPort is already in use, but the frontend did not respond."
    }

    Write-Host "Starting frontend at $frontendUrl ..."
    Start-Process -FilePath $env:ComSpec `
        -ArgumentList @('/c', "npm run dev -- --host 127.0.0.1 --port $frontendPort --strictPort") `
        -WorkingDirectory $frontendDirectory
    Wait-ForHttp $frontendUrl 'Frontend'
}
else {
    Write-Host "Frontend is already running at $frontendUrl."
}

Write-Host ''
Write-Host 'TrustFirewall is ready:'
Write-Host "  Frontend: $frontendUrl"
Write-Host "  Backend:  http://127.0.0.1:$backendPort"
