#!/usr/bin/env bash
set -euo pipefail

# Build and install liboqs and liboqs-python from source
# with broad algorithm enablement (incl. HQC and XMSS/XMSSMT).
#
# Usage:
#   scripts/setup_oqs.sh [--prefix <install-prefix>] [--branch <liboqs-branch-or-tag>] [--python <python>]
#
# Defaults:
#   prefix:   .local/oqs
#   branch:   main (use a release tag like 0.10.0 for stability)
#   python:   python (must be 3.11+ as required by this repo)

PREFIX=".local/oqs"
LIBOQS_BRANCH="main"
PY=python
COMPAT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"; shift 2;;
    --branch)
      LIBOQS_BRANCH="$2"; shift 2;;
    --python)
      PY="$2"; shift 2;;
    --compat|--generic)
      COMPAT=1; shift 1;;
    *)
      echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

echo "[oqs-setup] Install prefix: $PREFIX"
echo "[oqs-setup] liboqs branch/tag: $LIBOQS_BRANCH"
echo "[oqs-setup] Python: $PY"
echo "[oqs-setup] Compat mode: ${COMPAT}"

# Basic checks
command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v cmake >/dev/null || { echo "cmake is required" >&2; exit 1; }
if command -v ninja >/dev/null; then
  GEN="-G Ninja"
  BUILD_CMD="ninja -v"
  INSTALL_CMD="ninja -v install"
else
  GEN=""
  BUILD_CMD="cmake --build . --config Release -- -j$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
  INSTALL_CMD="cmake --install ."
fi

# Ensure prefix dirs
mkdir -p "$PREFIX"
PREFIX_ABS=$(cd "$PREFIX" && pwd)

echo "[oqs-setup] Using absolute prefix: $PREFIX_ABS"

# On macOS, try to find OpenSSL via Homebrew
OPENSSL_HINT=""
if [[ "$(uname -s)" == "Darwin" ]]; then
  if command -v brew >/dev/null; then
    if brew --prefix openssl@3 >/dev/null 2>&1; then
      OPENSSL_PREFIX=$(brew --prefix openssl@3)
      OPENSSL_HINT="-DOPENSSL_ROOT_DIR=$OPENSSL_PREFIX -DOPENSSL_INCLUDE_DIR=$OPENSSL_PREFIX/include -DOPENSSL_LIBRARIES=$OPENSSL_PREFIX/lib"
      echo "[oqs-setup] Found OpenSSL at: $OPENSSL_PREFIX"
    fi
  fi
fi

WORKDIR=".build/oqs"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR"
pushd "$WORKDIR" >/dev/null

# 1) Build liboqs
if [[ ! -d liboqs ]]; then
  echo "[oqs-setup] Cloning liboqs..."
  git clone --depth 1 --branch "$LIBOQS_BRANCH" https://github.com/open-quantum-safe/liboqs.git
fi

pushd liboqs >/dev/null
rm -rf build && mkdir build && cd build
echo "[oqs-setup] Configuring liboqs (all algorithms enabled, OpenSSL on)..."
EXTRA_FLAGS=""
if [[ "$COMPAT" == "1" ]]; then
  EXTRA_FLAGS="-DOQS_OPT_TARGET=generic -DOQS_DIST_BUILD=ON"
fi
cmake $GEN \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX_ABS" \
  -DCMAKE_INSTALL_RPATH="$PREFIX_ABS/lib" \
  -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
  -DCMAKE_MACOSX_RPATH=ON \
  -DOQS_MINIMAL_BUILD=OFF \
  -DOQS_USE_OPENSSL=ON \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_ENABLE_KEM_KYBER=ON \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_ENABLE_KEM_HQC=ON \
  -DOQS_ENABLE_SIG_DILITHIUM=ON \
  -DOQS_ENABLE_SIG_ML_DSA=ON \
  -DOQS_ENABLE_SIG_FALCON=ON \
  -DOQS_ENABLE_SIG_SPHINCS=ON \
  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
  $EXTRA_FLAGS \
  $OPENSSL_HINT \
  ..

echo "[oqs-setup] Building liboqs..."
eval "$BUILD_CMD"
echo "[oqs-setup] Installing liboqs to $PREFIX_ABS ..."
eval "$INSTALL_CMD"
popd >/dev/null

# 2) Build/install liboqs-python (python bindings: package name 'oqs')
if [[ ! -d liboqs-python ]]; then
  echo "[oqs-setup] Cloning liboqs-python..."
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
fi

pushd liboqs-python >/dev/null
echo "[oqs-setup] Installing python bindings against $PREFIX_ABS ..."
# Help the build system find the just-installed liboqs
export CMAKE_PREFIX_PATH="$PREFIX_ABS:${CMAKE_PREFIX_PATH:-}"
export PKG_CONFIG_PATH="$PREFIX_ABS/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LDFLAGS="-L$PREFIX_ABS/lib ${LDFLAGS:-}"
export CPPFLAGS="-I$PREFIX_ABS/include ${CPPFLAGS:-}"

$PY -m pip install --upgrade pip setuptools wheel
$PY -m pip install -v .
popd >/dev/null

popd >/dev/null

cat <<EOF

[oqs-setup] Done.

Add these environment variables before running code so the dynamic loader finds liboqs:

  export CMAKE_PREFIX_PATH="$PREFIX_ABS:\${CMAKE_PREFIX_PATH:-}"
  export PKG_CONFIG_PATH="$PREFIX_ABS/lib/pkgconfig:\${PKG_CONFIG_PATH:-}"
  # macOS:
  export DYLD_LIBRARY_PATH="$PREFIX_ABS/lib:\${DYLD_LIBRARY_PATH:-}"
  # Linux:
  export LD_LIBRARY_PATH="$PREFIX_ABS/lib:\${LD_LIBRARY_PATH:-}"

You can also select parameter sets via env vars (examples):
  export PQCBENCH_KYBER_ALG=ML-KEM-1024
  export PQCBENCH_HQC_ALG=HQC-256
  export PQCBENCH_XMSSMT_ALG=XMSSMT-SHA2_20/2_256

EOF

# Print detected mechanisms for quick verification
echo "[oqs-setup] Verifying enabled mechanisms via python..."
$PY - <<'PY'
try:
    import oqs
    print("oqs module:", oqs.__file__)
    get_kem = getattr(oqs, 'get_enabled_kem_mechanisms', None) or getattr(oqs, 'get_enabled_KEM_mechanisms', None)
    get_sig = getattr(oqs, 'get_enabled_sig_mechanisms', None) or getattr(oqs, 'get_enabled_SIG_mechanisms', None)
    if get_kem:
        print("KEM:")
        for m in get_kem():
            print(" -", m)
    if get_sig:
        print("SIG:")
        for m in get_sig():
            print(" -", m)
    # Probe stateful signatures (XMSS/XMSSMT) by attempting instantiation
    try:
        st = getattr(oqs, 'StatefulSignature', None)
        if st is not None:
            names = [
                'XMSS-SHA2_20_256',
                'XMSSMT-SHA2_20/2_256',
                'XMSSMT-SHA2_20/4_256',
                'XMSS-SHAKE_20_256',
                'XMSSMT-SHAKE_20/2_256',
            ]
            found = []
            for n in names:
                try:
                    with st(n):
                        found.append(n)
                except Exception:
                    pass
            print('Stateful SIG (probe):')
            for n in found:
                print(' -', n)
    except Exception as e:
        print('Stateful SIG probe failed:', e)
except Exception as e:
    print("[verify] Failed to import oqs:", e)
PY
