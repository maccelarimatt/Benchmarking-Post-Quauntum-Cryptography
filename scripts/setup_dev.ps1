
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ForceClone,
    [switch]$SkipNativeBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir '..')).Path
Push-Location -LiteralPath $repoRoot

function Ensure-Command {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' not found in PATH."
    }
}

function Ensure-GitClone {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$Force
    )

    if (Test-Path -LiteralPath $Destination) {
        if ($Force) {
            Write-Host "[setup] Removing existing '$Destination' (force requested)." -ForegroundColor Yellow
            Remove-Item -Recurse -Force -LiteralPath $Destination
        }
        else {
            Write-Host "[setup] Reusing existing '$Destination'." -ForegroundColor Cyan
            return
        }
    }

    Write-Host "[setup] Cloning $Url -> $Destination" -ForegroundColor Green
    git clone --depth 1 $Url $Destination
}

try {
    Write-Host "[setup] Repo root: $repoRoot" -ForegroundColor Cyan

    Ensure-Command -Name git
    Ensure-Command -Name python
    Ensure-Command -Name cmake

    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs-python.git' -Destination 'liboqs-python' -Force:$ForceClone
    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs.git' -Destination 'liboqs' -Force:$ForceClone

    $venvPath = Join-Path $repoRoot '.venv'
    $venvPython = Join-Path $venvPath 'Scripts\python.exe'

    if (-not (Test-Path -LiteralPath $venvPath)) {
        Write-Host "[setup] Creating virtual environment..." -ForegroundColor Green
        python -m venv .venv
    }
    else {
        Write-Host "[setup] Virtual environment already exists." -ForegroundColor Cyan
    }

    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Unable to locate virtualenv python at '$venvPython'."
    }

    Write-Host "[setup] Upgrading packaging tooling..." -ForegroundColor Green
    & $venvPython -m pip install --upgrade pip setuptools wheel

    Write-Host "[setup] Installing Python dependencies..." -ForegroundColor Green
    & $venvPython -m pip install -r requirements-dev.txt

    if (-not $SkipNativeBuild) {
        Write-Host "[setup] Configuring native CMake project..." -ForegroundColor Green
        & cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON

        Write-Host "[setup] Building native extension..." -ForegroundColor Green
        & cmake --build native/build
    }
    else {
        Write-Host "[setup] Skipping native build (flag set)." -ForegroundColor Yellow
    }

    Write-Host "[setup] Installing editable packages..." -ForegroundColor Green
    & $venvPython -m pip install -e libs/core
    & $venvPython -m pip install -e libs/adapters/native

    Write-Host "[setup] Installing development hooks..." -ForegroundColor Green
    & $venvPython -m pre-commit install

    Write-Host "`n[setup] Done. Activate the environment with:`n    .\\.venv\\Scripts\\Activate.ps1" -ForegroundColor Cyan
}
finally {
    Pop-Location
}
