
#!/usr/bin/env bash
set -euo pipefail

FORCE_CLONE=0
SKIP_NATIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force-clone)
      FORCE_CLONE=1; shift;;
    --skip-native-build)
      SKIP_NATIVE=1; shift;;
    *)
      echo "Unknown option: $1" >&2
      exit 2;;
  esac
done

repo_root="$(cd -- "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$repo_root"

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' not found in PATH." >&2
    exit 1
  fi
}

ensure_git_clone() {
  local url="$1"
  local dest="$2"
  if [[ -d "$dest" ]]; then
    if [[ $FORCE_CLONE -eq 1 ]]; then
      echo "[setup] Removing existing '$dest' (force requested)."
      rm -rf "$dest"
    else
      echo "[setup] Reusing existing '$dest'."
      return
    fi
  fi
  echo "[setup] Cloning $url -> $dest"
  git clone --depth 1 "$url" "$dest"
}

echo "[setup] Repo root: $repo_root"

ensure_cmd git
ensure_cmd python
ensure_cmd cmake

ensure_git_clone "https://github.com/open-quantum-safe/liboqs-python.git" "liboqs-python"
ensure_git_clone "https://github.com/open-quantum-safe/liboqs.git" "liboqs"

if [[ ! -d .venv ]]; then
  echo "[setup] Creating virtual environment..."
  python -m venv .venv
else
  echo "[setup] Virtual environment already exists."
fi

source .venv/bin/activate

echo "[setup] Upgrading packaging tooling..."
python -m pip install --upgrade pip setuptools wheel

echo "[setup] Installing Python dependencies..."
pip install -r requirements-dev.txt

if [[ $SKIP_NATIVE -ne 1 ]]; then
  echo "[setup] Configuring native CMake project..."
  cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON

  echo "[setup] Building native extension..."
  cmake --build native/build
else
  echo "[setup] Skipping native build (flag set)."
fi

echo "[setup] Installing editable packages..."
pip install -e libs/core
pip install -e libs/adapters/native

echo "[setup] Installing development hooks..."
pre-commit install

cat <<'EOF'

[setup] Done.
Activate the environment with:

    source .venv/bin/activate

EOF
