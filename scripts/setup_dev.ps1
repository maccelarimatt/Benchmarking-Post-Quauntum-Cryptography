
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

function Install-Liboqs {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$InstallPath,
        [Parameter(Mandatory)][string]$VersionTag
    )

    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath | Out-Null
    }
    $installRoot = (Resolve-Path -LiteralPath $InstallPath).Path
    $sentinel = Join-Path $installRoot '.liboqs-version'
    $oqsDll = Join-Path $installRoot 'bin\oqs.dll'
    $needsBuild = $true

    if ((Test-Path -LiteralPath $oqsDll) -and (Test-Path -LiteralPath $sentinel)) {
        $installedVersion = Get-Content -Path $sentinel -ErrorAction SilentlyContinue
        if ($installedVersion -eq $VersionTag) {
            Write-Host "[setup] Reusing existing liboqs install ($VersionTag)." -ForegroundColor Cyan
            $needsBuild = $false
        }
    }

    if (-not $needsBuild) {
        return
    }

    Write-Host "[setup] Building liboqs ($VersionTag)..." -ForegroundColor Green

    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $installRoot | Out-Null

    $buildDir = Join-Path $SourcePath 'build-setup'
    if (Test-Path -LiteralPath $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }

    $configureArgs = @(
        '-S', $SourcePath,
        '-B', $buildDir,
        "-DCMAKE_INSTALL_PREFIX=$installRoot",
        '-DBUILD_SHARED_LIBS=ON',
        '-DOQS_BUILD_ONLY_LIB=ON',
        '-DOQS_DIST_BUILD=OFF',
        '-DOQS_MINIMAL_BUILD=OFF',
        '-DOQS_USE_OPENSSL=OFF',
        '-DOQS_ENABLE_KEM_ML_KEM=ON',
        '-DOQS_ENABLE_KEM_HQC=ON',
        '-DOQS_ENABLE_SIG_ML_DSA=ON',
        '-DOQS_ENABLE_SIG_FALCON=ON',
        '-DOQS_ENABLE_SIG_SPHINCS=ON',
        '-DOQS_ENABLE_SIG_STFL_XMSS=ON',
        '-DOQS_ENABLE_SIG_STFL_LMS=ON',
        '-DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON',
        '-DCMAKE_BUILD_TYPE=Release'
    )
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        $configureArgs += '-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE'
    }

    & cmake @configureArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure liboqs build."
    }

    $buildArgs = @('--build', $buildDir, '--config', 'Release')
    & cmake @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build liboqs."
    }

    $installArgs = @('--install', $buildDir, '--config', 'Release')
    & cmake @installArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install liboqs."
    }

    Set-Content -Path $sentinel -Value $VersionTag -Encoding ASCII
}

function Sync-LiboqsRuntime {
    param(
        [Parameter(Mandatory)][string]$InstallPath,
        [Parameter(Mandatory)][string]$VenvScriptsPath
    )

    $sourceDll = Join-Path $InstallPath 'bin\oqs.dll'
    if (-not (Test-Path -LiteralPath $sourceDll)) {
        Write-Host "[setup] WARNING: liboqs DLL not found at '$sourceDll'; skipping venv sync." -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path -LiteralPath $VenvScriptsPath)) {
        Write-Host "[setup] WARNING: Virtualenv Scripts directory not found at '$VenvScriptsPath'; skipping liboqs DLL copy." -ForegroundColor Yellow
        return
    }

    $destinationDll = Join-Path $VenvScriptsPath 'oqs.dll'
    Copy-Item -LiteralPath $sourceDll -Destination $destinationDll -Force
}

try {
    Write-Host "[setup] Repo root: $repoRoot" -ForegroundColor Cyan

    Ensure-Command -Name git
    Ensure-Command -Name python
    Ensure-Command -Name cmake

    $liboqsPythonCommit = 'f70842e3e338fa67af2eb6e72b35a4b23bad2e1c'
    $liboqsVersion = '0.14.0'
    $liboqsCommit = '94b421ebb82405c843dba4e9aa521a56ee5a333d'

    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs-python.git' -Destination 'liboqs-python' -Force:$ForceClone -Commit:$liboqsPythonCommit
    Ensure-GitClone -Url 'https://github.com/open-quantum-safe/liboqs.git' -Destination 'liboqs' -Force:$ForceClone -Commit:$liboqsCommit

    $liboqsSourcePath = Join-Path $repoRoot 'liboqs'
    $liboqsInstallPath = Join-Path $env:USERPROFILE '_oqs'
    Install-Liboqs -SourcePath $liboqsSourcePath -InstallPath $liboqsInstallPath -VersionTag $liboqsVersion

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

    Sync-LiboqsRuntime -InstallPath $liboqsInstallPath -VenvScriptsPath (Join-Path $venvPath 'Scripts')

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
    $oqsShowExitCode = 1
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue' # pip exits non-zero when the package is missing; ignore that here
        & $venvPython -m pip show oqs *> $null
        $oqsShowExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($oqsShowExitCode -eq 0) {
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
    & $venvPython -m pre_commit install

    Write-Host "`n[setup] Done. Activate the environment with:`n    .\\.venv\\Scripts\\Activate.ps1" -ForegroundColor Cyan
}
finally {
    Pop-Location
}
