.\.venv\Scripts\Activate.ps1

# Prefer native C backend if the DLL is present
$dllCandidates = @(
  'native/build/RelWithDebInfo/pqcbench_native.dll',
  'native/build/Release/pqcbench_native.dll',
  'native/build/Debug/pqcbench_native.dll'
)
foreach ($c in $dllCandidates) {
  try {
    $rp = Resolve-Path $c -ErrorAction SilentlyContinue
    if ($rp) {
      $env:PQCBENCH_NATIVE_LIB = $rp.Path
      break
    }
  } catch {}
}

run-rsa-oaep 
