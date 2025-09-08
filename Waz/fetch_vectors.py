#!/usr/bin/env python3
# Fetches and stages cryptographic test vectors for your repo.
#
# Sources:
# - NIST ACVP (ML-KEM/ML-DSA final JSON vectors)
# - Project Wycheproof (RSA OAEP/PSS + other edge/negative tests)
# - Official submission KATs (Kyber, Dilithium, SPHINCS+)
#
# Usage:
#   python fetch_vectors.py --dest ./data/vectors
#
# Safe to re-run; archives cached under dest/_archives unless --force is used.

import argparse
import io
import os
import sys
import json
import zipfile
import tarfile
import hashlib
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlparse

# ----------------------------- Sources ---------------------------------------

GITHUB_ZIPS = {
    "nist_acvp": "https://github.com/usnistgov/ACVP-Server/archive/refs/heads/master.zip",
    "wycheproof": "https://github.com/C2SP/wycheproof/archive/refs/heads/main.zip",
    "pqclean": "https://github.com/PQClean/PQClean/archive/refs/heads/master.zip",

    # Official submission packages with KATs (Round 3 ZIPs)
    "kyber_submission_r3": "https://pq-crystals.org/kyber/data/kyber-submission-nist-round3.zip",
    "dilithium_submission_r3": "https://pq-crystals.org/dilithium/data/dilithium-submission-nist-round3.zip",
    # '+' must be URL-encoded as %2B
    "sphincsplus_submission_r3": "https://sphincs.org/data/sphincs%2B-round3-submission-nist.zip",
}

ACVP_ALGS = {"ML-KEM", "ML-DSA"}  # add "SLH-DSA" if desired

# Folder/file patterns (folder entries are substring fragments, not only prefixes)
PATTERNS = {
    "nist_acvp": {
        "folders": ["gen-val/json-files", "gen-val/json"],
        "files": [".json"],  # ACVP filtered by content later
    },
    "wycheproof": {
        "folders": ["testvectors_v1", "testvectors"],
        "files": ["rsa_oaep", "rsa-oaep", "rsa_pss", "rsa-pss", ".json"],
    },
    "pqclean": {
        "folders": [
            "crypto_kem/kyber",
            "crypto_kem/hqc",
            "crypto_sign/dilithium",
            "crypto_sign/falcon",
            "crypto_sign/sphincs",
            "crypto_sign/xmssmt",
        ],
        "files": [".rsp", ".req", ".kat", ".txt"],
    },
    "kyber_submission_r3": {
        "folders": ["KAT/kyber512", "KAT/kyber768", "KAT/kyber1024", "KAT", "kat"],
        "files": [".req", ".rsp"],
    },
    "dilithium_submission_r3": {
        "folders": ["KAT/dilithium2", "KAT/dilithium3", "KAT/dilithium5", "KAT", "kat"],
        "files": [".req", ".rsp"],
    },
    "sphincsplus_submission_r3": {
        "folders": ["KAT", "kat"],  # some packages lowercase
        "files": [".rsp", ".req"],
    },
}

# ----------------------------- Helpers ---------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def download_file(url: str) -> bytes:
    print(f"[+] Downloading: {url}")
    req = Request(url, headers={"User-Agent": "vector-fetcher/1.0"})
    with urlopen(req) as resp:
        return resp.read()

def _safe_member(name: str) -> bool:
    n = name.replace("\\", "/")
    return not (n.startswith("/") or ".." in n)

def _normalize(p: str | Path) -> str:
    return str(p).replace("\\\\", "/").replace("\\", "/")

def _filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = Path(path).name
    return name if name else "archive"

def _is_acvp_keep(data: bytes) -> bool:
    # Keep only ML-KEM / ML-DSA vectors by JSON content
    try:
        j = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return False
    alg = None
    if isinstance(j, dict):
        alg = j.get("algorithm") or (j.get("testGroups") or [{}])[0].get("algorithm")
    elif isinstance(j, list) and j and isinstance(j[0], dict):
        alg = j[0].get("algorithm")
    return isinstance(alg, str) and alg.upper() in ACVP_ALGS

def _acvp_params(path: Path) -> tuple[str | None, str | None]:
    """
    Return (algorithm, level) like ('ML-KEM','512') or ('ML-DSA','3') if found.
    ACVP often uses parameterSet values like 'ML-KEM-512' or 'ML-DSA-65'.
    For ML-DSA, map 44→2, 65→3, 87→5.
    """
    try:
        j = json.loads(path.read_text("utf-8", errors="ignore"))
    except Exception:
        return None, None

    def _collect_strings(obj) -> list[str]:
        out = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    out.extend(_collect_strings(v))
                else:
                    out.append(f"{k}:{v}")
        elif isinstance(obj, list):
            for it in obj:
                out.extend(_collect_strings(it))
        return out

    # Algorithm
    alg = (j.get("algorithm") or "").upper()
    if not alg and isinstance(j, dict):
        tgs = j.get("testGroups") or []
        if tgs and isinstance(tgs[0], dict):
            alg = (tgs[0].get("algorithm") or "").upper()
    if alg not in {"ML-KEM", "ML-DSA"}:
        return None, None

    # Gather candidate strings to search for parameter names
    cand = []
    if isinstance(j, dict):
        if "parameterSet" in j: cand.append(str(j["parameterSet"]))
        if "revision" in j: cand.append(str(j["revision"]))
        if "mode" in j: cand.append(str(j["mode"]))
        for g in j.get("testGroups", []):
            for k in ("parameterSet", "name", "revision", "mode"):
                if k in g:
                    cand.append(str(g[k]))
    # Also scan all stringy fields as a fallback
    cand.extend(_collect_strings(j))
    text = " ".join(cand).lower()

    # Try explicit patterns first: "ml-kem-512", "ml-dsa-44", etc.
    level = None
    if alg == "ML-KEM":
        for kem in ("512", "768", "1024"):
            if f"ml-kem-{kem}" in text or f"mlkem{kem}" in text or f" {kem}" in text or text.endswith(kem):
                level = kem
                break
    elif alg == "ML-DSA":
        if "ml-dsa-44" in text or "dilithium2" in text or "level 2" in text:
            level = "2"
        elif "ml-dsa-65" in text or "dilithium3" in text or "level 3" in text:
            level = "3"
        elif "ml-dsa-87" in text or "dilithium5" in text or "level 5" in text:
            level = "5"
        else:
            import re
            m = re.search(r"ml[-_]dsa[-_](\d{2})", text)
            if m:
                mapping = {"44": "2", "65": "3", "87": "5"}
                level = mapping.get(m.group(1))

    return (alg, level)

def _contains_any_fragment(path_str: str, fragments: list[str]) -> bool:
    low = path_str.lower()
    return any(frag.lower() in low for frag in fragments)

def _first_fragment_relative(path_str: str, fragments: list[str]) -> Path | None:
    """Find first folder fragment inside path and return relative Path after it."""
    norm = path_str.replace("\\", "/")
    low = norm.lower()
    for frag in fragments:
        f = frag.replace("\\", "/")
        idx = low.find(f.lower())
        if idx >= 0:
            start = idx + len(f)
            # strip leading slashes after fragment
            while start < len(norm) and norm[start] in ("/", "\\"):
                start += 1
            return Path(norm[start:])
    return None

# -------------------------- Archive iteration --------------------------------

def iter_archive_members(archive_bytes: bytes):
    """Yield tuples (kind, name, reader) for each member.
       kind: 'file' or 'dir'; name: path string; reader(): -> bytes"""
    # Try ZIP first
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            for info in z.infolist():
                name = info.filename
                if info.is_dir():
                    yield ("dir", name, None)
                else:
                    def _reader(info=info, z=z):
                        with z.open(info) as src:
                            return src.read()
                    yield ("file", name, _reader)
            return
    except zipfile.BadZipFile:
        pass
    # Fall back to TAR(.gz)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as t:
            for m in t.getmembers():
                name = m.name
                if m.isdir():
                    yield ("dir", name, None)
                elif m.isfile():
                    def _reader(m=m, t=t):
                        f = t.extractfile(m)
                        return f.read() if f else b""
                    yield ("file", name, _reader)
            return
    except tarfile.ReadError:
        raise RuntimeError("Unsupported archive format (not ZIP/TAR).")

# ---------------------------- Extraction -------------------------------------

def extract_selected(source_key: str, archive_bytes: bytes, dest_root: Path, patterns: dict) -> list[Path]:
    """Extract matching files for a given source into dest_root/<source_key>/..."""
    extracted: list[Path] = []
    pat = PATTERNS[source_key]
    folder_frags = pat["folders"]
    file_tokens = pat["files"]

    for kind, name, reader in iter_archive_members(archive_bytes):
        if not _safe_member(name):
            continue
        # We only care about entries containing any of our folder fragments
        if not _contains_any_fragment(name, folder_frags):
            continue
        if kind == "dir":
            continue

        name_l = name.lower()
        if not any(tok in name_l for tok in file_tokens):
            continue

        data = reader() if reader else b""

        # ACVP: filter by JSON content
        if source_key == "nist_acvp":
            if not _is_acvp_keep(data):
                continue

        # Build canonical relative path (strip everything up to the matched fragment)
        rel = _first_fragment_relative(name, folder_frags) or Path(Path(name).name)
        canonical = dest_root / source_key / rel
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_bytes(data)
        extracted.append(canonical)

    return extracted

# ---------------------------- Requirements -----------------------------------

REQUIREMENTS = {
    "acvp": {
        "ML-KEM": ("512", "768", "1024"),
        "ML-DSA": ("2", "3", "5"),
    },
    "wycheproof": {
        # any presence of these families satisfies
        "need": ["rsa_oaep", "rsa-oaep", "rsa_pss", "rsa-pss"],
    },
    # For KATs we key by filename tokens (since paths vary)
    "kats": {
        "kyber_submission_r3": {
            "require_tokens_anywhere": ["kyber512", "kyber768", "kyber1024"],
            "must_contain": ["pqckemkat", "pqckemkat"],  # case-insensitive check
        },
        "dilithium_submission_r3": {
            "require_tokens_anywhere": ["dilithium2", "dilithium3", "dilithium5"],
            "must_contain": ["pqcsignkat"],
        },
        "sphincsplus_submission_r3": {
            "require_any_kat_file": True,
        },
    },
}

# ------------------------ Backfill (targeted) --------------------------------

def backfill_missing_vectors(dest: Path, manifest: dict) -> list[dict]:
    """
    Find specific missing items by re-scanning full archives (not just pattern
    subtrees) and extracting only the needed files into a _backfill/ area.
    Returns list of manifest entries [{"source": ..., "path": ..., "sha256": ...}, ...]
    """
    added: list[dict] = []

    by_src = {src: [Path(f["path"]) for f in meta["files"]]
              for src, meta in manifest["sources"].items()}

    # ---------------- ACVP backfill: find missing levels by content ----------------
    acvp_needed = {"ML-KEM": set(REQUIREMENTS["acvp"]["ML-KEM"]),
                   "ML-DSA": set(REQUIREMENTS["acvp"]["ML-DSA"])}
    for p in by_src.get("nist_acvp", []):
        alg, lvl = _acvp_params(p)
        if alg in acvp_needed and lvl in acvp_needed[alg]:
            acvp_needed[alg].discard(lvl)

    if any(acvp_needed.values()):
        arc_path = Path(manifest["sources"]["nist_acvp"]["archive"])
        data = arc_path.read_bytes()
        # brute-force scan of every JSON in the archive
        for kind, name, reader in iter_archive_members(data):
            if kind != "file" or not name.lower().endswith(".json"):
                continue
            if not _safe_member(name):
                continue
            blob = reader()
            if not _is_acvp_keep(blob):
                continue
            # write temp to inspect params
            rel = Path(name).name  # use basename
            out = dest / "nist_acvp" / "_backfill" / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(blob)
            alg, lvl = _acvp_params(out)
            # keep only those solving missing needs
            keep = alg in acvp_needed and lvl in acvp_needed.get(alg, set())
            if keep:
                added.append({"source": "nist_acvp", "path": str(out), "sha256": sha256_file(out)})
                acvp_needed[alg].discard(lvl)
            else:
                try:
                    out.unlink()
                except Exception:
                    pass
            # stop early if complete
            if not acvp_needed["ML-KEM"] and not acvp_needed["ML-DSA"]:
                break

    # ---------------- Kyber KAT backfill ------------------------------------------
    def _backfill_kat_generic(src_key: str, tokens: list[str], must_any: list[str] | None,
                              filename_predicate) -> None:
        missing = set(tok.lower() for tok in tokens)
        names = [Path(p).name.lower() for p in by_src.get(src_key, [])]
        for tok in list(missing):
            if any(tok in n for n in names):
                missing.discard(tok)
        if not missing:
            return
        arc_path = Path(manifest["sources"][src_key]["archive"])
        data = arc_path.read_bytes()
        for kind, name, reader in iter_archive_members(data):
            if kind != "file":
                continue
            base = Path(name).name.lower()
            if not any(base.endswith(ext) for ext in (".req", ".rsp")):
                continue
            if must_any and not any(m in base for m in must_any):
                continue
            # if predicate(base) returns a token matched, keep it
            matched_tok = filename_predicate(base, missing)
            if not matched_tok:
                continue
            blob = reader()
            out = dest / src_key / "_backfill" / Path(name).name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(blob)
            added.append({"source": src_key, "path": str(out), "sha256": sha256_file(out)})
            missing.discard(matched_tok)
            if not missing:
                break

    # Kyber: look for PQCkemKAT_*kyber{512,768,1024}.*
    def _kyber_pred(base: str, missing: set[str]) -> str | None:
        for tok in list(missing):
            if "pqckemkat" in base and tok in base:
                return tok
        return None

    # Dilithium: look for PQCsignKAT_*dilithium{2,3,5}.*
    def _dilithium_pred(base: str, missing: set[str]) -> str | None:
        for tok in list(missing):
            if "pqcsignkat" in base and tok in base:
                return tok
        return None

    _backfill_kat_generic(
        "kyber_submission_r3",
        REQUIREMENTS["kats"]["kyber_submission_r3"]["require_tokens_anywhere"],
        REQUIREMENTS["kats"]["kyber_submission_r3"]["must_contain"],
        _kyber_pred,
    )
    _backfill_kat_generic(
        "dilithium_submission_r3",
        REQUIREMENTS["kats"]["dilithium_submission_r3"]["require_tokens_anywhere"],
        REQUIREMENTS["kats"]["dilithium_submission_r3"]["must_contain"],
        _dilithium_pred,
    )

    # SPHINCS+ backfill is not strictly needed here (your run already found many),
    # but this shows how you'd enforce "at least one .rsp/.req":
    if REQUIREMENTS["kats"]["sphincsplus_submission_r3"].get("require_any_kat_file", False):
        files = by_src.get("sphincsplus_submission_r3", [])
        if not any(p.suffix.lower() in (".rsp", ".req") for p in files):
            arc_path = Path(manifest["sources"]["sphincsplus_submission_r3"]["archive"])
            data = arc_path.read_bytes()
            for kind, name, reader in iter_archive_members(data):
                if kind != "file":
                    continue
                if not Path(name).suffix.lower() in (".rsp", ".req"):
                    continue
                blob = reader()
                out = dest / "sphincsplus_submission_r3" / "_backfill" / Path(name).name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(blob)
                added.append({"source": "sphincsplus_submission_r3", "path": str(out), "sha256": sha256_file(out)})
                break

    return added

# ------------------------ Validation -----------------------------------------

def validate_completeness(root: Path, manifest: dict) -> list[str]:
    errs: list[str] = []

    # index files by source
    by_src = {src: [Path(f["path"]) for f in meta["files"]]
              for src, meta in manifest["sources"].items()}

    # ---- ACVP: levels by JSON content ----
    acvp_files = by_src.get("nist_acvp", [])
    seen = {"ML-KEM": set(), "ML-DSA": set()}
    for p in acvp_files:
        alg, lvl = _acvp_params(p)
        if alg in seen and lvl:
            seen[alg].add(lvl)
    for alg, levels in REQUIREMENTS["acvp"].items():
        for lvl in levels:
            if lvl not in seen.get(alg, set()):
                errs.append(f"ACVP missing {alg} level {lvl} JSON.")

    # ---- Wycheproof presence checks ----
    wyc = [pp.name.lower() for pp in by_src.get("wycheproof", [])]
    if not any(("rsa_oaep" in n) or ("rsa-oaep" in n) for n in wyc):
        errs.append("Wycheproof missing RSA-OAEP vectors.")
    if not any(("rsa_pss" in n) or ("rsa-pss" in n) for n in wyc):
        errs.append("Wycheproof missing RSA-PSS vectors.")

    # ---- KATs from submission packages (filename-based checks) ----
    for src_key, rule in REQUIREMENTS["kats"].items():
        files = by_src.get(src_key, [])
        names = [p.name.lower() for p in files]
        if not files:
            errs.append(f"KAT source missing: {src_key}")
            continue

        if "must_contain" in rule:
            for tok in rule["must_contain"]:
                if not any(tok.lower() in n for n in names):
                    errs.append(f"{src_key}: expected at least one file containing '{tok}'")

        if "require_tokens_anywhere" in rule:
            for tok in rule["require_tokens_anywhere"]:
                if not any(tok.lower() in n for n in names):
                    errs.append(f"KATs missing in {src_key}: {tok}")

        if rule.get("require_any_kat_file"):
            if not any(n.endswith(".rsp") or n.endswith(".req") for n in names):
                errs.append("SPHINCS+ KATs missing (no .rsp/.req files found).")

    return errs

# ------------------------------- Main ----------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default="./data/vectors", help="Destination root directory")
    ap.add_argument("--force", action="store_true", help="Re-download and overwrite")
    args = ap.parse_args()

    dest = Path(args.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    cache_dir = dest / "_archives"
    cache_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"root": str(dest), "sources": {}}

    # 1) Fetch & extract per PATTERNS
    for key, url in GITHUB_ZIPS.items():
        archive_name = _filename_from_url(url)
        cache_path = cache_dir / f"{key}__{archive_name}"

        if cache_path.exists() and not args.force:
            print(f"[=] Using cached archive: {cache_path}")
            data = cache_path.read_bytes()
        else:
            data = download_file(url)
            cache_path.write_bytes(data)
            print(f"[+] Saved archive: {cache_path} ({len(data)} bytes)")

        extracted = extract_selected(key, data, dest, PATTERNS[key])

        files_out = [{
            "path": str(p),
            "sha256": sha256_file(p),
        } for p in extracted]

        manifest["sources"][key] = {
            "archive": str(cache_path),
            "count": len(files_out),
            "files": files_out,
        }
        print(f"[+] {key}: extracted {len(files_out)} files")

    # 2) Backfill any missing ACVP levels & KAT param-sets
    added = backfill_missing_vectors(dest, manifest)
    for item in added:
        src = item["source"]
        manifest["sources"][src]["files"].append({"path": item["path"], "sha256": item["sha256"]})
        manifest["sources"][src]["count"] = len(manifest["sources"][src]["files"])

    # 3) Write manifest and validate
    manifest_path = dest / "vector_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[✓] Wrote manifest: {manifest_path}")

    errors = validate_completeness(dest, manifest)
    if errors:
        print("\n[!] Vector set is INCOMPLETE:")
        for e in errors:
            print("   -", e)
        sys.exit(2)
    else:
        print("[✓] Vector set is COMPLETE per project requirements.")

if __name__ == "__main__":
    main()
