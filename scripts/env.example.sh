#!/usr/bin/env bash
# Source this file after running scripts/setup_oqs.sh to configure your shell
# for runtime linking and convenient algorithm selection.

# Adjust if you used a different prefix
export OQS_PREFIX="$(pwd)/.local/oqs"

export CMAKE_PREFIX_PATH="$OQS_PREFIX:${CMAKE_PREFIX_PATH:-}"
export PKG_CONFIG_PATH="$OQS_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  export DYLD_LIBRARY_PATH="$OQS_PREFIX/lib:${DYLD_LIBRARY_PATH:-}"
else
  export LD_LIBRARY_PATH="$OQS_PREFIX/lib:${LD_LIBRARY_PATH:-}"
fi

# Optional: pick specific parameter sets if your liboqs build supports them
# export PQCBENCH_KYBER_ALG=ML-KEM-1024
# export PQCBENCH_HQC_ALG=HQC-256
# export PQCBENCH_DILITHIUM_ALG=ML-DSA-65
# export PQCBENCH_FALCON_ALG=Falcon-512
# export PQCBENCH_SPHINCS_ALG=SPHINCS+-SHA2-128f-simple
# export PQCBENCH_XMSSMT_ALG=XMSSMT-SHA2_20/2_256

echo "Environment configured for liboqs in $OQS_PREFIX"

