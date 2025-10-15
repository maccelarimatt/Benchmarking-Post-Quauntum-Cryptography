#requires -Version 5.1
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir '..')).Path
$venvActivate = Join-Path $repoRoot '.venv\Scripts\Activate.ps1'

if (-not (Test-Path -LiteralPath $venvActivate)) {
    throw "Virtual environment activation script not found at '$venvActivate'. Run scripts\setup_dev.ps1 first."
}

. $venvActivate

$oqsRoots = @(
    Join-Path $env:USERPROFILE '_oqs',
    Join-Path $repoRoot '.local\oqs'
)

foreach ($root in $oqsRoots) {
    if (-not (Test-Path -LiteralPath $root)) {
        continue
    }

    $env:OQS_INSTALL_PATH = $root
    $binPath = Join-Path $root 'bin'
    if (Test-Path -LiteralPath $binPath) {
        if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $binPath })) {
            $env:PATH = "$binPath;$env:PATH"
        }
    }
    break
}
