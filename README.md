Here’s a drop-in **README.md** tailored to your repo layout. Just paste it at the repo root.

---

# Analysis of Post-Quantum Cryptography — Kyber (ML-KEM) Demo

This repo contains a small C demo that performs **hybrid encryption** using **ML-KEM-768 (Kyber-768)** from **liboqs**, deriving a shared secret and then encrypting arbitrary plaintext with **AES-256-GCM** (OpenSSL).

> **Note:** Kyber/ML-KEM is a **KEM** (key encapsulation), not a direct “encrypt plaintext” algorithm. We use it to derive a symmetric key, then encrypt with AES-GCM.

## Repository layout

```
.
├─ Application/                 # Python app (not used by this C demo)
│  ├─ static/
│  ├─ templates/
│  └─ main.py
└─ PQC Evaluation/              # CMake C demo using liboqs + OpenSSL
   ├─ CMakeLists.txt
   ├─ main.c
   └─ build/                    # created by CMake
```

## Prerequisites (Windows 10/11)

* **Visual Studio 2022** with “Desktop development with C++”
* **Git**
* **CMake** (bundled with VS is fine)
* **vcpkg** package manager

## One-time setup

Open **PowerShell** and run:

```powershell
# 1) Get vcpkg (if you don’t have it yet)
git clone https://github.com/microsoft/vcpkg $HOME\vcpkg
& $HOME\vcpkg\bootstrap-vcpkg.bat

# 2) Install libraries (MSVC ABI)
$HOME\vcpkg\vcpkg.exe install liboqs:x64-windows openssl:x64-windows
$HOME\vcpkg\vcpkg.exe integrate install   # optional, makes VS/MSBuild auto-find packages
```

## Build the C demo

```powershell
# From the repo root, cd into the C project folder (quotes because path has spaces)
cd ".\PQC Evaluation"

# Configure (generate Visual Studio build files)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$HOME\vcpkg\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows

# Compile
cmake --build build --config Release
```

## Run the demo

The binaries from vcpkg are DLLs; make sure Windows can find them:

```powershell
$env:PATH = "$HOME\vcpkg\installed\x64-windows\bin;$env:PATH"
.\build\Release\hello.exe "my secret message"
```

**Expected output (example):**

```
KEM ciphertext (to receiver): <hex...>
AES-GCM IV: <hex...>
AES-GCM tag: <hex...>
AES-GCM ciphertext: <hex...>
Recovered plaintext: my secret message
```

### Optional: avoid setting PATH each time

**A)** Add vcpkg’s bin to your user PATH permanently (one-time):

```powershell
[Environment]::SetEnvironmentVariable(
  "Path",
  $env:Path + ";$HOME\vcpkg\installed\x64-windows\bin",
  "User"
)
```

Open a new PowerShell window afterwards.

**B)** Or copy DLLs next to the exe at build time — append this to `CMakeLists.txt`:

```cmake
add_custom_command(TARGET hello POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$ENV{USERPROFILE}/vcpkg/installed/${VCPKG_TARGET_TRIPLET}/bin/oqs.dll"
    "$<TARGET_FILE_DIR:hello>"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$ENV{USERPROFILE}/vcpkg/installed/${VCPKG_TARGET_TRIPLET}/bin/libcrypto-3-x64.dll"
    "$<TARGET_FILE_DIR:hello>"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$ENV{USERPROFILE}/vcpkg/installed/${VCPKG_TARGET_TRIPLET}/bin/libssl-3-x64.dll"
    "$<TARGET_FILE_DIR:hello>"
)
```

## What the demo does

1. Generate an **ML-KEM-768** keypair (receiver).
2. **Encapsulate** to the public key to derive a 32-byte shared secret (sender).
3. Use that secret as an **AES-256-GCM** key to encrypt the provided plaintext.
4. **Decapsulate** with the secret key and decrypt; print the recovered plaintext.

You can switch algorithms by changing the strings in `main.c`:

* `"ML-KEM-512"`, `"ML-KEM-768"`, `"ML-KEM-1024"` for KEM,
* `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"` for signatures (if you add a SIG demo).

## Common pitfalls

* **Mixing toolchains:** This project uses **MSVC** (`x64-windows` triplet). If you compile with MSYS2/MinGW, install `liboqs:x64-mingw-dynamic` instead and adjust commands.
* **Spaces in paths:** Always quote paths in PowerShell, e.g. `cd ".\PQC Evaluation"`.
* **Missing DLLs at runtime:** Add vcpkg `bin` to PATH or copy DLLs beside the exe (see above).
* **First-time configure:** Only re-run the `cmake -S ... -B build ...` configure step when you change libraries or the generator; otherwise just `cmake --build ...`.

## Credits

* [Open Quantum Safe / liboqs](https://github.com/open-quantum-safe/liboqs)
* [OpenSSL](https://www.openssl.org/)
* Built with [vcpkg](https://github.com/microsoft/vcpkg) + MSVC on Windows

---

If you want, I can also drop in a VS Code task (`.vscode/tasks.json`) or a `CMakeUserPresets.json` so you can press a single build/run button.
