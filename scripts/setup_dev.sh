
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

script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

relocate_legacy() {
  local name="$1"
  local legacy="$script_dir/$name"
  local target="$repo_root/$name"
  if [[ ! -e "$target" && -e "$legacy" ]]; then
    echo "[setup] Moving legacy '$name' from scripts/ into repo root."
    mv "$legacy" "$target"
  fi
}

relocate_legacy "liboqs"
relocate_legacy "liboqs-python"

if [[ ! -d "$repo_root/.venv" && -d "$script_dir/.venv" ]]; then
  echo "[setup] Moving legacy virtualenv from scripts/ into repo root."
  mv "$script_dir/.venv" "$repo_root/.venv"
fi

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' not found in PATH." >&2
    exit 1
  fi
}

ensure_git_clone() {
  local url="$1"
  local dest="$2"
  local commit="$3"
  if [[ -d "$dest" ]]; then
    if [[ $FORCE_CLONE -eq 1 ]]; then
      echo "[setup] Removing existing '$dest' (force requested)."
      rm -rf "$dest"
    else
      echo "[setup] Reusing existing '$dest'."
      if [[ -n "$commit" ]]; then
        git -C "$dest" fetch --depth 1 origin "$commit" --quiet >/dev/null 2>&1 || true
        git -C "$dest" checkout --force --quiet "$commit" >/dev/null 2>&1
      fi
      return
    fi
  fi
  echo "[setup] Cloning $url -> $dest"
  git clone --depth 1 "$url" "$dest"
  if [[ -n "$commit" ]]; then
    git -C "$dest" fetch --depth 1 origin "$commit" --quiet >/dev/null 2>&1 || true
    git -C "$dest" checkout --force --quiet "$commit" >/dev/null 2>&1
  fi
}

echo "[setup] Repo root: $repo_root"

ensure_cmd git
ensure_cmd python
ensure_cmd cmake

liboqs_python_commit="f70842e3e338fa67af2eb6e72b35a4b23bad2e1c"
liboqs_commit="b02d0c9a30b2e60f8374a92928c9426d1256bf03"

ensure_git_clone "https://github.com/open-quantum-safe/liboqs-python.git" "liboqs-python" "$liboqs_python_commit"
ensure_git_clone "https://github.com/open-quantum-safe/liboqs.git" "liboqs" "$liboqs_commit"

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

if [[ -d liboqs-python ]]; then
  echo "[setup] Installing liboqs-python bindings from local checkout..."
  pip install -v ./liboqs-python
else
  echo "[setup] WARNING: liboqs-python checkout not found; installing pinned PyPI 'liboqs-python==0.14.0'." >&2
  pip install liboqs-python==0.14.0
fi

if pip show oqs >/dev/null 2>&1; then
  echo "[setup] Removing conflicting PyPI 'oqs' package..."
  pip uninstall -y oqs >/dev/null
fi

if [[ $SKIP_NATIVE -ne 1 ]]; then
  echo "[setup] Configuring native CMake project..."
  cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON

  echo "[setup] Building native extension..."
  cmake --build native/build --target pqcbench_native

  echo "[setup] Building liboqs validation helpers (kat_kem/kat_sig/kat_sig_stfl)..."
  cmake --build native/build --target kat_kem kat_sig kat_sig_stfl vectors_kem vectors_sig >/dev/null
else
  echo "[setup] Skipping native build (flag set)."
fi

echo "[setup] Installing editable packages..."
pip install -e libs/core
pip install -e libs/adapters/native

cat <<'EOF'

[setup] Done.
Activate the environment with:

    source .venv/bin/activate

EOF
