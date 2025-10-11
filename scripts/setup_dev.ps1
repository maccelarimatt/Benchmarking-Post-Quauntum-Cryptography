
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

function Resolve-LegacyPath {
    param([Parameter(Mandatory)][string]$Name)

    $target = Join-Path $repoRoot $Name
    $legacy = Join-Path $scriptDir $Name
    if (-not (Test-Path -LiteralPath $target) -and (Test-Path -LiteralPath $legacy)) {
        Write-Host "[setup] Detected misplaced '$Name' under scripts/. Moving to repo root." -ForegroundColor Yellow
        Move-Item -LiteralPath $legacy -Destination $target
    }
}

Resolve-LegacyPath -Name 'liboqs'
Resolve-LegacyPath -Name 'liboqs-python'

$legacyVenv = Join-Path $scriptDir '.venv'
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.venv')) -and (Test-Path -LiteralPath $legacyVenv)) {
    Write-Host "[setup] Moving misplaced virtual environment from scripts/." -ForegroundColor Yellow
    Move-Item -LiteralPath $legacyVenv -Destination (Join-Path $repoRoot '.venv')
}

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
        [switch]$Force,
        [string]$Commit
    )

    if (Test-Path -LiteralPath $Destination) {
        if ($Force) {
            Write-Host "[setup] Removing existing '$Destination' (force requested)." -ForegroundColor Yellow
            Remove-Item -Recurse -Force -LiteralPath $Destination
        }
        else {
            Write-Host "[setup] Reusing existing '$Destination'." -ForegroundColor Cyan
            if ($Commit) {
                & git -C $Destination fetch --depth 1 origin $Commit --quiet *> $null
                & git -C $Destination checkout --force --quiet $Commit *> $null
            }
            return
        }
    }

    Write-Host "[setup] Cloning $Url -> $Destination" -ForegroundColor Green
    git clone --depth 1 $Url $Destination
    if ($Commit) {
        & git -C $Destination fetch --depth 1 origin $Commit --quiet *> $null
        & git -C $Destination checkout --force --quiet $Commit *> $null
    }
}

try {
    Write-Host "[setup] Repo root: $repoRoot" -ForegroundColor Cyan

    Ensure-Command -Name git
    Ensure-Command -Name python
    Ensure-Command -Name cmake

    $liboqsPythonCommit = 'f70842e3e338fa67af2eb6e72b35a4b23bad2e1c'
    $liboqsCommit = 'b02d0c9a30b2e60f8374a92928c9426d1256bf03'

    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs-python.git' -Destination 'liboqs-python' -Force:$ForceClone -Commit:$liboqsPythonCommit
    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs.git' -Destination 'liboqs' -Force:$ForceClone -Commit:$liboqsCommit

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

    $liboqsPythonPath = Join-Path $repoRoot 'liboqs-python'
    if (Test-Path -LiteralPath $liboqsPythonPath) {
        Write-Host "[setup] Installing liboqs-python bindings from local checkout..." -ForegroundColor Green
        & $venvPython -m pip install -v $liboqsPythonPath
    }
    else {
        Write-Host "[setup] WARNING: liboqs-python checkout not found; installing pinned PyPI 'liboqs-python==0.14.0'." -ForegroundColor Yellow
        & $venvPython -m pip install liboqs-python==0.14.0
    }
    & $venvPython -m pip show oqs *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[setup] Removing conflicting PyPI 'oqs' package..." -ForegroundColor Yellow
        & $venvPython -m pip uninstall -y oqs | Out-Null
    }

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
