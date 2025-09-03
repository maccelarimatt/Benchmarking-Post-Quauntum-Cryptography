#!/usr/bin/env python3
# Fetches and stages cryptographic test vectors for your repo.
#
# Sources:
# - NIST ACVP (ML-KEM/ML-DSA final JSON vectors)
# - Project Wycheproof (RSA OAEP/PSS + other edge/negative tests)
# - PQClean (KATs for Kyber, Dilithium, Falcon, SPHINCS+, XMSSMT, HQC as available)
#
# Usage:
#   python fetch_vectors.py --dest ./data/vectors
#
# Notes:
# - This script downloads zip archives and extracts only the relevant folders/files.
# - You can safely re-run; existing files are skipped by default unless --force is used.
# - If you need to add or remove patterns, edit the PATTERNS dict below.

import argparse
import io
import os
import sys
import json
import zipfile
import hashlib
from pathlib import Path
from urllib.request import urlopen, Request


GITHUB_ZIPS = {
    "nist_acvp": "https://github.com/usnistgov/ACVP-Server/archive/refs/heads/master.zip",
    "wycheproof": "https://github.com/C2SP/wycheproof/archive/refs/heads/main.zip",
    "pqclean": "https://github.com/PQClean/PQClean/archive/refs/heads/master.zip",
}

# Folder/file patterns to extract from each archive.
# We keep patterns broad and then apply secondary filters to reduce noise.
PATTERNS = {
    "nist_acvp": {
        "folders": ["ACVP-Server-master/gen-val/json-files"],
        "files": [".json"],
    },
    "wycheproof": {
        "folders": ["wycheproof-main/testvectors_v1"],
        "files": [
            # RSA OAEP & PSS vectors + ML-KEM/ML-DSA if present
            "rsa_oaep", "rsa-oaep", "rsa_pss", "rsa-pss",
            "ml-kem", "ml_kem", "ml-dsa", "ml_dsa"
        ],
    },
    "pqclean": {
        "folders": [
            # Scheme directories; we keep all to allow downstream tools to locate KATs in-place
            "PQClean-master/crypto_kem/kyber",
            "PQClean-master/crypto_kem/hqc",
            "PQClean-master/crypto_sign/dilithium",
            "PQClean-master/crypto_sign/falcon",
            "PQClean-master/crypto_sign/sphincs",
            "PQClean-master/crypto_sign/xmssmt",
        ],
        "files": [".rsp", ".req", ".kat", ".txt"],
    },
}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def download_zip(url: str) -> bytes:
    print(f"[+] Downloading: {url}")
    req = Request(url, headers={"User-Agent": "vector-fetcher/1.0"})
    with urlopen(req) as resp:
        return resp.read()

def extract_selected(zip_bytes: bytes, dest_root: Path, patterns: dict) -> list:
    extracted = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            # Check folder prefix first
            if not any(info.filename.startswith(prefix) for prefix in patterns["folders"]):
                continue
            # Then filter by file types or name substrings
            if info.is_dir():
                # create directories as needed
                out_path = dest_root / info.filename
                out_path.mkdir(parents=True, exist_ok=True)
                continue

            name = info.filename.lower()
            if not any(token in name for token in patterns["files"]):
                continue

            out_path = dest_root / info.filename
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, out_path.open("wb") as dst:
                dst.write(src.read())
            extracted.append(out_path)
    return extracted

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default="./data/vectors", help="Destination root directory")
    ap.add_argument("--force", action="store_true", help="Re-download and overwrite")
    args = ap.parse_args()

    dest = Path(args.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    manifest = {"root": str(dest), "sources": {}}

    for key, url in GITHUB_ZIPS.items():
        archive_name = f"{key}.zip"
        cache_dir = dest / "_archives"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / archive_name

        if cache_path.exists() and not args.force:
            print(f"[=] Using cached archive: {cache_path}")
            data = cache_path.read_bytes()
        else:
            data = download_zip(url)
            cache_path.write_bytes(data)
            print(f"[+] Saved archive: {cache_path} ({len(data)} bytes)")

        src_dest = dest / key
        extracted = extract_selected(data, dest, PATTERNS[key])

        # Build a compact manifest for this source
        files_out = []
        for p in extracted:
            # Move files to a cleaner mirror path under dest/key/...
            # Keep subpath after the first matched folder prefix.
            rel = None
            for prefix in PATTERNS[key]["folders"]:
                p_norm = str(p).replace("\\\\", "/").replace("\\", "/")
                base_norm = str((dest / prefix)).replace("\\\\", "/").replace("\\", "/")
                if p_norm.startswith(base_norm):
                    rel = Path(p_norm[len(base_norm)+1:])
                    break
            if rel is None:
                # fallback: compute relative to dest
                rel = p.relative_to(dest)
            canonical = src_dest / rel
            canonical.parent.mkdir(parents=True, exist_ok=True)
            # Move (rename) into canonical path
            try:
                p.rename(canonical)
            except Exception:
                # If cross-device or already moved, copy contents
                canonical.write_bytes(Path(p).read_bytes())
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass

            files_out.append({
                "path": str(canonical),
                "sha256": sha256_file(canonical),
            })

        manifest["sources"][key] = {
            "zip": str(cache_path),
            "count": len(files_out),
            "files": files_out,
        }
        print(f"[+] {key}: extracted {len(files_out)} files")

    manifest_path = dest / "vector_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[\\u2713] Wrote manifest: {manifest_path}")

if __name__ == "__main__":
    main()