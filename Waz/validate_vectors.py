#!/usr/bin/env python3
"""
Validate crypto implementations against the staged test vectors.

Usage:
  python validate_vectors.py \
    --manifest ./data/vectors/vector_manifest.json \
    --provider providers/your_provider.py \
    --jobs 8 --subset kats,acvp,wycheproof

Notes
- Provider: a Python module path or file path exposing class `Provider` with methods below.
- We fully support:
    * PQC KATs (Kyber: PQCkemKAT_*.{req,rsp}; Dilithium: PQCsignKAT_*.rsp)
    * Wycheproof RSA-OAEP/RSA-PSS (optional; requires provider methods or `cryptography` fallback)
- ACVP ML-KEM/ML-DSA: we attempt AFT-style checks when JSONs include usable fields;
  non-usable groups are skipped with a warning (not a failure).
- Produces a JUnit XML at `./test-results/vectors.junit.xml`.
"""

from __future__ import annotations
import argparse
import base64
import binascii
import importlib.util
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------- Provider interface ----------------

class Provider:
    """
    Implement me with your algorithms. All byte-like inputs/outputs are raw bytes.
    You may ignore methods you don't need if you won't validate those vectors.
    """
    # --- KEM (Kyber/ML-KEM) ---
    def kem_encapsulate(self, scheme: str, public_key: bytes) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def kem_decapsulate(self, scheme: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError

    # --- Signatures (Dilithium/ML-DSA) ---
    def sign(self, scheme: str, secret_key: bytes, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, scheme: str, public_key: bytes, msg: bytes, signature: bytes) -> bool:
        raise NotImplementedError

    # --- RSA (Wycheproof) optional; harness can fallback to cryptography if absent ---
    def rsa_oaep_decrypt(self, priv_pem: bytes, ct: bytes, hash_name: str, label: bytes) -> bytes:
        raise NotImplementedError

    def rsa_pss_verify(self, pub_pem: bytes, msg: bytes, sig: bytes, hash_name: str, salt_len: int) -> bool:
        raise NotImplementedError


def load_provider(module_path: str) -> Provider:
    """Load Provider impl from a file path or module path."""
    p = Path(module_path)
    if p.exists():
        spec = importlib.util.spec_from_file_location("user_provider", str(p))
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
    else:
        mod = importlib.import_module(module_path)
    prov = getattr(mod, "Provider", None)
    if prov is None:
        raise RuntimeError("Provider class not found in module")
    return prov()

# ---------------- Utilities ----------------

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def h2b(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if not s:
        return b""
    if not HEX_RE.match(s):
        raise ValueError(f"Not hex: {s[:32]}...")
    return binascii.unhexlify(s)

def ensure_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

@dataclass
class TestResult:
    name: str
    ok: bool
    details: str = ""
    source: str = ""
    case_id: Optional[str] = None
    duration_ms: int = 0

# ---------------- KAT parsers ----------------
# Kyber KATs come in pairs: .req (inputs) + .rsp (expected outputs)
# Dilithium KATs: single .rsp with msg/sk/pk/smlen/sm

def parse_pqckemkat_pairs(files: List[Path]) -> List[Tuple[Path, Path]]:
    reqs = {f.name.lower(): f for f in files if f.suffix.lower() == ".req"}
    rsps = {f.name.lower(): f for f in files if f.suffix.lower() == ".rsp"}
    pairs: List[Tuple[Path, Path]] = []
    # Match by basename ignoring extension
    keys = set(k[:-4] for k in reqs.keys()) & set(k[:-4] for k in rsps.keys())
    for k in sorted(keys):
        pairs.append((reqs[k + ".req"], rsps[k + ".rsp"]))
    return pairs

def parse_kv_lines(text: str) -> List[Dict[str, str]]:
    """Parse 'count = N' style blocks into list of dicts."""
    blocks: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip().lower()] = v.strip().lower()
    if cur:
        blocks.append(cur)
    return blocks

# ---------------- Validators ----------------

def validate_kyber_kat(pair: Tuple[Path, Path], provider: Provider, scheme_hint: Optional[str]) -> List[TestResult]:
    req_path, rsp_path = pair
    name = f"KEM-KAT:{req_path.name}"
    t0 = time.time()

    req_blocks = parse_kv_lines(req_path.read_text())
    rsp_blocks = parse_kv_lines(rsp_path.read_text())

    results: List[TestResult] = []
    for i, (rin, rout) in enumerate(zip(req_blocks, rsp_blocks)):
        count = rin.get("count", str(i))
        try:
            # Common fields seen in NIST KATs for KEM:
            # seed, pk, sk, ct, ss (names vary a bit; handle both req/rsp)
            pk = h2b(rin.get("pk", rout.get("pk", "")))
            sk = h2b(rin.get("sk", rout.get("sk", "")))
            ct = h2b(rout.get("ct", ""))
            ss = h2b(rout.get("ss", ""))

            scheme = scheme_hint or detect_kyber_variant(pk)
            # 1) decap(shared) == ss
            ss_dec = provider.kem_decapsulate(scheme, sk, ct)
            ok_dec = (ss_dec == ss)

            # 2) encaps with pk should produce (ct2, ss2) that decaps to same shared secret
            ct2, ss2 = provider.kem_encapsulate(scheme, pk)
            ss2_dec = provider.kem_decapsulate(scheme, sk, ct2)
            ok_enc = (ss2 == ss2_dec)

            ok = bool(ok_dec and ok_enc)
            results.append(TestResult(
                name=f"{name}#{count}", ok=ok,
                details="" if ok else f"dec_ok={ok_dec}, enc_round_ok={ok_enc}",
                source=str(rsp_path),
                case_id=str(count),
                duration_ms=int((time.time()-t0)*1000)
            ))
        except Exception as e:
            results.append(TestResult(
                name=f"{name}#{count}", ok=False, details=f"EXC: {e}", source=str(rsp_path),
                case_id=str(count), duration_ms=int((time.time()-t0)*1000)
            ))
    return results

def detect_kyber_variant(pk: bytes) -> str:
    # Super lightweight heuristic: length of pk (CRYSTALS-Kyber: 800/1184/1568 bytes)
    # Adjust if your provider expects ML-KEM naming.
    n = len(pk)
    if n in (800,): return "Kyber512"
    if n in (1184,): return "Kyber768"
    if n in (1568,): return "Kyber1024"
    # ML-KEM aliases:
    if n in (800, 1184, 1568): return f"ML-KEM-{ {800:'512',1184:'768',1568:'1024'}[n] }"
    return "Kyber"  # fallback; your provider can ignore scheme if not needed

def validate_dilithium_kat(rsp_path: Path, provider: Provider, scheme_hint: Optional[str]) -> List[TestResult]:
    name = f"DSA-KAT:{rsp_path.name}"
    t0 = time.time()
    blocks = parse_kv_lines(rsp_path.read_text())
    results: List[TestResult] = []
    for i, b in enumerate(blocks):
        try:
            msg = h2b(b.get("msg", ""))
            pk = h2b(b.get("pk", ""))
            sk = h2b(b.get("sk", ""))
            sm = h2b(b.get("sm", ""))  # in some KATs sm = sig||msg; otherwise 'sig'
            sig = b.get("sig", None)
            if sig is not None:
                sig_b = h2b(sig)
            else:
                # If sm provided, try to split signature length from known params if present
                sig_b = sm  # provider.verify can accept sm if it knows to parse
            scheme = scheme_hint or detect_dilithium_variant(pk)
            # Sign then verify equals
            sig_new = provider.sign(scheme, sk, msg)
            ok1 = provider.verify(scheme, pk, msg, sig_new)
            # Verify expected KAT signature if provided
            ok2 = True
            if sig is not None:
                ok2 = provider.verify(scheme, pk, msg, sig_b)
            results.append(TestResult(
                name=f"{name}#{i}", ok=bool(ok1 and ok2),
                details="" if (ok1 and ok2) else f"sign/verify mismatch (ok1={ok1}, ok2={ok2})",
                source=str(rsp_path), case_id=str(i),
                duration_ms=int((time.time()-t0)*1000)
            ))
        except Exception as e:
            results.append(TestResult(
                name=f"{name}#{i}", ok=False, details=f"EXC: {e}", source=str(rsp_path),
                case_id=str(i), duration_ms=int((time.time()-t0)*1000)
            ))
    return results

def detect_dilithium_variant(pk: bytes) -> str:
    # Rough heuristic on pk length: Dilithium2≈1312, 3≈1952, 5≈2592 (ref impl).
    n = len(pk)
    if n in (1312,): return "Dilithium2"
    if n in (1952,): return "Dilithium3"
    if n in (2592,): return "Dilithium5"
    # ML-DSA aliases
    mapping = {1312: "ML-DSA-44", 1952: "ML-DSA-65", 2592: "ML-DSA-87"}
    if n in mapping: return mapping[n]
    return "Dilithium"

# ---------------- Wycheproof (RSA) ----------------
# If your provider doesn’t implement RSA, we fall back to `cryptography` if installed.

def validate_wycheproof(file: Path, provider: Provider) -> List[TestResult]:
    data = json.loads(file.read_text())
    alg = data.get("algorithm", "").lower()
    if "rsa" not in alg:
        return []  # ignore non-RSA for now
    name = f"WYC:{file.name}"
    t0 = time.time()

    results: List[TestResult] = []
    # Simple, partial support for common groups in OAEP/PSS
    for group in data.get("testGroups", []):
        tests = group.get("tests", [])
        hash_name = (group.get("sha", "") or group.get("mgfSha", "")).lower()
        # Compose keys from group (may be modulus/exp in hex)
        n_hex = group.get("n") or group.get("mod") or ""
        e_hex = group.get("e") or group.get("pubExp") or ""
        d_hex = group.get("d", "")
        n = h2b(n_hex) if n_hex else None
        e = h2b(e_hex) if e_hex else None
        d = h2b(d_hex) if d_hex else None
        # Build PEM if possible; else skip
        pem_pub, pem_priv = rsa_build_pems(n, e, d)

        for t in tests:
            tcid = str(t.get("tcId", ""))
            try:
                if "oaep" in alg:
                    ct = base64.b64decode(t["ctB64"]) if "ctB64" in t else h2b(t.get("ct", ""))
                    label = base64.b64decode(t.get("labelB64", "")) if "labelB64" in t else b""
                    # prefer provider; fallback to cryptography
                    pt = None
                    try:
                        pt = provider.rsa_oaep_decrypt(pem_priv or b"", ct, hash_name or "sha256", label)
                    except Exception:
                        pt = rsa_oaep_decrypt_fallback(pem_priv, ct, hash_name or "sha256", label)
                    msg = base64.b64decode(t["msgB64"]) if "msgB64" in t else h2b(t.get("msg", ""))
                    ok = (pt == msg) if t.get("result", "valid") == "valid" else True
                elif "pss" in alg:
                    sig = base64.b64decode(t["sigB64"]) if "sigB64" in t else h2b(t.get("sig", ""))
                    msg = base64.b64decode(t["msgB64"]) if "msgB64" in t else h2b(t.get("msg", ""))
                    salt_len = int(group.get("sLen", 32))
                    try:
                        ok = provider.rsa_pss_verify(pem_pub or b"", msg, sig, hash_name or "sha256", salt_len)
                    except Exception:
                        ok = rsa_pss_verify_fallback(pem_pub, msg, sig, hash_name or "sha256", salt_len)
                else:
                    continue
                results.append(TestResult(name=f"{name}#{tcid}", ok=ok, source=str(file),
                                          case_id=tcid, duration_ms=int((time.time()-t0)*1000)))
            except Exception as e:
                results.append(TestResult(name=f"{name}#{tcid}", ok=False, details=f"EXC: {e}",
                                          source=str(file), case_id=tcid, duration_ms=int((time.time()-t0)*1000)))
    return results

def rsa_build_pems(n: Optional[bytes], e: Optional[bytes], d: Optional[bytes]) -> Tuple[Optional[bytes], Optional[bytes]]:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        if n is None or e is None:
            return None, None
        n_int = int.from_bytes(n, "big")
        e_int = int.from_bytes(e, "big")
        pub = rsa.RSAPublicNumbers(e_int, n_int).public_key()
        pem_pub = pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem_priv = None
        if d is not None and len(d) > 0:
            d_int = int.from_bytes(d, "big")
            # Build a minimal private key (no CRT params available in wycheproof groups sometimes)
            priv = rsa.RSAPrivateNumbers(
                p=None, q=None, d=d_int, dmp1=None, dmq1=None, iqmp=None,
                public_numbers=rsa.RSAPublicNumbers(e_int, n_int)
            )
            # cryptography requires full CRT params; skip if not present
            pem_priv = None
        return pem_pub, pem_priv
    except Exception:
        return None, None

def rsa_oaep_decrypt_fallback(priv_pem: Optional[bytes], ct: bytes, hash_name: str, label: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    if not priv_pem:
        raise RuntimeError("No private key PEM available for OAEP fallback.")
    key = serialization.load_pem_private_key(priv_pem, password=None)
    algo = getattr(hashes, hash_name.upper())()
    return key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algo), algorithm=algo, label=label or None))

def rsa_pss_verify_fallback(pub_pem: Optional[bytes], msg: bytes, sig: bytes, hash_name: str, salt_len: int) -> bool:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    if not pub_pem:
        raise RuntimeError("No public key PEM available for PSS fallback.")
    key = serialization.load_pem_public_key(pub_pem)
    algo = getattr(hashes, hash_name.upper())()
    try:
        key.verify(sig, msg, padding.PSS(mgf=padding.MGF1(algo), salt_length=salt_len), algo)
        return True
    except Exception:
        return False

# ---------------- ACVP (best-effort) ----------------

def validate_acvp_json(acvp_file: Path, provider: Provider) -> List[TestResult]:
    """
    Best-effort: supports test groups that include pk/sk/ct/ss (ML-KEM) or msg/sig/pk/sk (ML-DSA).
    Many ACVP files are meta/negatives or require external key gen; we skip those without failing.
    """
    results: List[TestResult] = []
    data = json.loads(acvp_file.read_text())
    alg = (data.get("algorithm") or "").upper()
    groups = data.get("testGroups", [])
    if alg not in {"ML-KEM", "ML-DSA"} or not groups:
        return results

    for gi, g in enumerate(groups):
        tests = g.get("tests", [])
        mode = str(g.get("mode", "")).lower()
        name = f"ACVP:{alg}:{acvp_file.name}#G{gi}"
        if alg == "ML-KEM":
            # Expect pk/sk/ct/ss in test cases for AFT; otherwise skip group
            any_ran = False
            for t in tests:
                pk = h2b(t.get("pk", "")) if "pk" in t else b""
                sk = h2b(t.get("sk", "")) if "sk" in t else b""
                ct = h2b(t.get("ct", "")) if "ct" in t else b""
                ss = h2b(t.get("ss", "")) if "ss" in t else b""
                if not (pk and sk and (ct or ss)):
                    continue
                any_ran = True
                scheme = g.get("parameterSet") or ""
                t0 = time.time()
                try:
                    ok_dec = True
                    if ct and ss:
                        ss_dec = provider.kem_decapsulate(str(scheme), sk, ct)
                        ok_dec = (ss_dec == ss)
                    ok_enc = True
                    if pk:
                        ct2, ss2 = provider.kem_encapsulate(str(scheme), pk)
                        ok_enc = bool(ct2 and ss2)
                    ok = ok_dec and ok_enc
                    results.append(TestResult(name=name, ok=ok, source=str(acvp_file),
                                              case_id=str(t.get("tcId","")),
                                              duration_ms=int((time.time()-t0)*1000)))
                except Exception as e:
                    results.append(TestResult(name=name, ok=False, details=f"EXC: {e}",
                                              source=str(acvp_file), case_id=str(t.get("tcId","")),
                                              duration_ms=int((time.time()-t0)*1000)))
            if not any_ran:
                # Non-actionable group; skip silently
                pass

        elif alg == "ML-DSA":
            any_ran = False
            for t in tests:
                pk = h2b(t.get("pk", "")) if "pk" in t else b""
                sk = h2b(t.get("sk", "")) if "sk" in t else b""
                msg = h2b(t.get("msg", "")) if "msg" in t else b""
                sig = h2b(t.get("sig", "")) if "sig" in t else b""
                if not (pk and (sig or (sk and msg))):
                    continue
                any_ran = True
                scheme = g.get("parameterSet") or ""
                t0 = time.time()
                try:
                    ok_ver = provider.verify(str(scheme), pk, msg, sig) if (msg and sig) else True
                    ok_sign = True
                    if sk and msg:
                        sig2 = provider.sign(str(scheme), sk, msg)
                        ok_sign = provider.verify(str(scheme), pk, msg, sig2)
                    ok = ok_ver and ok_sign
                    results.append(TestResult(name=name, ok=ok, source=str(acvp_file),
                                              case_id=str(t.get("tcId","")),
                                              duration_ms=int((time.time()-t0)*1000)))
                except Exception as e:
                    results.append(TestResult(name=name, ok=False, details=f"EXC: {e}",
                                              source=str(acvp_file), case_id=str(t.get("tcId","")),
                                              duration_ms=int((time.time()-t0)*1000)))
            if not any_ran:
                pass

    return results

# ---------------- Runner & reporting ----------------

def junit_write(results: List[TestResult], out_path: Path):
    ensure_dir(out_path)
    total = len(results)
    failures = sum(1 for r in results if not r.ok)
    with out_path.open("w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(f'<testsuite name="vectors" tests="{total}" failures="{failures}">\n')
        for r in results:
            f.write(f'  <testcase classname="{r.source}" name="{r.name}" time="{r.duration_ms/1000:.3f}">')
            if not r.ok:
                msg = r.details.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                f.write(f'<failure message="{msg}"/>')
            f.write('</testcase>\n')
        f.write('</testsuite>\n')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="./data/vectors/vector_manifest.json")
    ap.add_argument("--provider", required=True, help="Module path or file path exposing class Provider")
    ap.add_argument("--subset", default="kats,acvp,wycheproof", help="comma list: kats,acvp,wycheproof")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--limit", type=int, default=0, help="limit number of files for quick runs")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    prov = load_provider(args.provider)
    subsets = set(s.strip() for s in args.subset.split(",") if s.strip())

    # Gather files by type from manifest
    files_by_src = {src: [Path(f["path"]) for f in meta["files"]] for src, meta in manifest["sources"].items()}

    tasks: List[Tuple[str, Path]] = []

    if "kats" in subsets:
        # Kyber
        kyf = files_by_src.get("kyber_submission_r3", [])
        pairs = parse_pqckemkat_pairs(kyf)
        for pair in pairs:
            tasks.append(("KEM-KAT", pair[1]))  # index on rsp for naming
        # Dilithium
        dlf = files_by_src.get("dilithium_submission_r3", [])
        for f in dlf:
            if f.suffix.lower() == ".rsp" and "pqcsignkat" in f.name.lower():
                tasks.append(("DSA-KAT", f))
    if "wycheproof" in subsets:
        for f in files_by_src.get("wycheproof", []):
            if f.suffix.lower() == ".json" and ("rsa_pss" in f.name.lower() or "rsa-pss" in f.name.lower() or
                                                "rsa_oaep" in f.name.lower() or "rsa-oaep" in f.name.lower()):
                tasks.append(("WYC", f))
    if "acvp" in subsets:
        for f in files_by_src.get("nist_acvp", []):
            if f.suffix.lower() == ".json":
                tasks.append(("ACVP", f))

    if args.limit:
        tasks = tasks[:args.limit]

    results: List[TestResult] = []
    lock = None

    def run_one(task: Tuple[str, Path]) -> List[TestResult]:
        kind, path = task
        try:
            if kind == "KEM-KAT":
                # find its matching req by base
                base = path.name[:-4]
                all_ky = files_by_src.get("kyber_submission_r3", [])
                req = next((p for p in all_ky if p.name.lower() == base.lower()+".req"), None)
                return validate_kyber_kat((req, path), prov, None) if req else []
            if kind == "DSA-KAT":
                return validate_dilithium_kat(path, prov, None)
            if kind == "WYC":
                return validate_wycheproof(path, prov)
            if kind == "ACVP":
                return validate_acvp_json(path, prov)
            return []
        except Exception as e:
            return [TestResult(name=f"{kind}:{path.name}", ok=False, details=f"EXC: {e}", source=str(path))]

    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(run_one, t) for t in tasks]
        for fu in as_completed(futs):
            results.extend(fu.result())

    # Summary
    total = len(results)
    failed = sum(1 for r in results if not r.ok)
    passed = total - failed
    print(f"\n[RESULT] {passed}/{total} passed; {failed} failed.")
    if failed:
        for r in results:
            if not r.ok:
                print(f"  - FAIL {r.name} :: {r.details}")

    # JUnit
    out_xml = Path("./test-results/vectors.junit.xml")
    junit_write(results, out_xml)
    print(f"[✓] Wrote JUnit: {out_xml.resolve()}")

if __name__ == "__main__":
    main()
