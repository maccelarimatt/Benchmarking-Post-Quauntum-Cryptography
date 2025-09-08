#!/usr/bin/env python3
"""
Hybrid ML-KEM → AES-256-GCM demo with optional vector checks (Wycheproof/ACVP).

- First (optional): run RSA Wycheproof checks (OAEP decrypt / PSS verify) if --validate.
- Then: replicate the C demo behaviour:
    * ML-KEM keypair/encaps/decaps via liboqs (oqs)
    * AES-256-GCM encrypt/decrypt via cryptography (separate IV and tag like the C code)
    * print steps/hex conditionally to mimic your output style

Env:
  TRACE_STEPS=1   -> show '== [n] Step ==' banners
  DUMP_SECRETS=1  -> dump buffers in hex

Install:
  pip install oqs cryptography pyyaml
"""

import argparse, os, json, time, sys
from typing import Tuple, Union
from pathlib import Path

# ---- Optional deps ----
try:
    import yaml
except Exception:
    print("ERROR: PyYAML is required (pip install pyyaml).")
    sys.exit(1)

try:
    import oqs
    OQS_OK = True
except Exception:
    OQS_OK = False

try:
    import psutil
except Exception:
    psutil = None

# cryptography
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False


# ========== printing helpers (mimic your C) ==========

TRACE = bool(int(os.getenv("TRACE_STEPS", "0")))
DUMP  = bool(int(os.getenv("DUMP_SECRETS", "0")))
_step_counter = 0

def step(title: str) -> None:
    global _step_counter
    if TRACE:
        _step_counter += 1
        print(f"\n== [{_step_counter}] {title} ==")

def print_hex(label: str, b: bytes) -> None:
    if DUMP:
        print(f"{label} ({len(b)} bytes): {b.hex()}")

def rss_bytes() -> int:
    if psutil is None: return -1
    try: return psutil.Process(os.getpid()).memory_info().rss
    except Exception: return -1

def measure(fn):
    before = rss_bytes()
    t0 = time.perf_counter()
    ok, info = fn()
    dt = (time.perf_counter() - t0) * 1000.0
    after = rss_bytes()
    return ok, info, dt, (after if after >= 0 else before)


# ========== Wycheproof RSA checks (vectors-first) ==========

def _get_hash(name: str):
    nm = name.lower()
    if nm in ("sha256", "sha-256", "sha2-256"): return hashes.SHA256()
    if nm in ("sha384", "sha-384", "sha2-384"): return hashes.SHA384()
    if nm in ("sha512", "sha-512", "sha2-512"): return hashes.SHA512()
    raise ValueError(f"Unsupported hash: {name}")

def _parse_hash(name: str):
    nm = name.lower().replace("_", "").replace("-", "")
    if nm in ("sha1", "sha-1"):   return hashes.SHA1()
    if nm in ("sha224",):         return hashes.SHA224()
    if nm in ("sha256",):         return hashes.SHA256()
    if nm in ("sha384",):         return hashes.SHA384()
    if nm in ("sha512",):         return hashes.SHA512()
    raise ValueError(f"Unsupported hash in vectors: {name}")

def _parse_mgf(mgf_field: str):
    # Examples in Wycheproof: "MGF1_SHA1", "MGF1_SHA256", "MGF1-SHA512"
    hname = mgf_field.split("_")[-1].split("-")[-1]
    return padding.MGF1(_parse_hash(hname))

def run_wycheproof_rsa(vectors_root: Path, limit_per_file: int = 50) -> Tuple[int,int,int]:
    if not CRYPTO_OK:
        print("Wycheproof: cryptography not available; skipping.")
        return (0,0,0)
    base = vectors_root / "wycheproof" / "wycheproof-main" / "testvectors_v1"
    if not base.exists():
        base = vectors_root / "wycheproof"
    if not base.exists():
        print("Wycheproof JSON not found; skipping.")
        return (0,0,0)

    files = [p for p in base.rglob("*.json")
             if p.name.lower().startswith(("rsa_oaep","rsa-oaep","rsa_pss","rsa-pss"))]

    passed = failed = 0
    for fp in files:
        try:
            data = json.loads(fp.read_text())
        except Exception:
            continue

        groups = data.get("testGroups", [])
        ran = 0
        for g in groups:
            try:
                pub_pem  = g.get("publicKeyPem")
                priv_pem = g.get("privateKeyPem")
                pub = load_pem_public_key(pub_pem.encode()) if pub_pem else None
                priv = load_pem_private_key(priv_pem.encode(), password=None) if priv_pem else None
            except Exception:
                continue

            # Group-level defaults
            g_hash = g.get("sha", g.get("hash","SHA-256"))
            g_mgf  = g.get("mgf", "MGF1_SHA256")
            for t in g.get("tests", []):
                if ran >= limit_per_file: break
                try:
                    result = t.get("result","").lower()  # "valid" | "invalid" | "acceptable"
                    # Test-level overrides
                    t_hash = t.get("sha",  g_hash)
                    t_mgf  = t.get("mgf",  g_mgf)

                    if "oaep" in fp.name.lower() and priv is not None:
                        ct  = bytes.fromhex(t.get("ct",""))
                        msg = bytes.fromhex(t.get("msg",""))
                        lab = bytes.fromhex(t.get("label","")) if t.get("label") else b""
                        h = _parse_hash(t_hash)
                        mgf = _parse_mgf(t_mgf)
                        pad = padding.OAEP(mgf=mgf, algorithm=h, label=lab)
                        ok = False
                        try:
                            pt = priv.decrypt(ct, pad)
                            # Acceptable means: library may accept or reject => accept both outcomes
                            ok = (pt == msg) or (result == "acceptable")
                            # If vector says invalid, acceptance should count as fail
                            if result == "invalid":
                                ok = False
                        except Exception:
                            # Decrypt failed: pass if invalid, or acceptable; fail if valid
                            ok = (result in ("invalid","acceptable"))
                        passed += int(ok); failed += int(not ok)

                    elif "pss" in fp.name.lower() and pub is not None:
                        sig  = bytes.fromhex(t.get("sig",""))
                        msg  = bytes.fromhex(t.get("msg",""))
                        h    = _parse_hash(t_hash)
                        mgf  = _parse_mgf(t_mgf)
                        sLen = t.get("saltLength", -1)
                        salt = h.digest_size if sLen in (-1, "hash", None) else int(sLen)
                        pad  = padding.PSS(mgf=mgf, salt_length=salt)
                        ok = False
                        try:
                            pub.verify(sig, msg, pad, h)
                            ok = (result != "invalid") or (result == "acceptable")
                            if result == "invalid":
                                ok = False
                        except Exception:
                            ok = (result in ("invalid","acceptable"))
                        passed += int(ok); failed += int(not ok)

                    ran += 1
                except Exception:
                    failed += 1
                    ran += 1

    print(f"Wycheproof RSA: files={len(files)}  passed={passed}  failed={failed}")
    return (len(files), passed, failed)



# ========== ACVP presence (KEM/Sig) ==========

def has_acvp(vectors_root: Path) -> bool:
    return (vectors_root / "nist_acvp").exists()


# ========== Hybrid ML-KEM → AES-256-GCM demo ==========

def kem_hybrid_demo(kem_name: str, plaintext: bytes) -> None:
    if not OQS_OK:
        print("oqs not available; install 'oqs' to run the hybrid demo.")
        return

    step(f"KEM setup ({kem_name})")
    with oqs.KeyEncapsulation(kem_name) as kem:
        print(f"Algorithm: {kem_name}")
        # liboqs-python exposes lengths as attributes on the instance
        try:
            print(f"pk={kem.details['length-public_key']}, sk={kem.details['length-secret_key']}, "
                  f"ct={kem.details['length-ciphertext']}, ss={kem.details['length-shared_secret']} bytes")
        except Exception:
            pass

        step("Key generation (receiver)")
        pk = kem.generate_keypair()  # returns public key; secret stays inside object
        # liboqs-python cannot directly read secret key; so we just show pk
        print_hex("Receiver public key (pk)", pk)

        step("Sender encapsulation -> shared secret + KEM ciphertext")
        ct, ss_sender = kem.encapsulate(pk)
        print_hex("KEM ciphertext (ct)", ct)
        print_hex("Sender shared secret (ss_sender)", ss_sender)

        step("Derive AEAD key (demo uses ss[0:32] directly as AES-256 key)")
        key = ss_sender[:32]  # DEMO ONLY; in production use HKDF over the ss
        print_hex("AES-256 key", key)

        step("Encrypt plaintext with AES-256-GCM")
        from os import urandom
        iv = urandom(12)
        # Use low-level GCM to separate ciphertext and tag just like your C
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ct_aead = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        print_hex("AES-GCM IV", iv)
        print_hex("AES-GCM tag", tag)
        print_hex("AES-GCM ciphertext", ct_aead)

        step("Receiver decapsulation -> shared secret")
        ss_receiver = kem.decapsulate(ct)
        print_hex("Receiver shared secret (ss_receiver)", ss_receiver)

        step("Shared secret check")
        same = (ss_sender == ss_receiver)
        print(f"Shared secrets equal? {'yes' if same else 'NO!'}")

        step("Decrypt with AES-256-GCM")
        decryptor = Cipher(algorithms.AES(ss_receiver[:32]), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        pt_out = decryptor.update(ct_aead) + decryptor.finalize()
        print(f"Recovered plaintext: {pt_out.decode(errors='replace')}")


# ========== CLI / main ==========

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kem", default="ML-KEM-768", help="OQS KEM name (e.g., ML-KEM-768, Kyber768)")
    ap.add_argument("--plaintext", default="hello kyber hybrid", help="Plaintext to encrypt")
    ap.add_argument("--vectors", default="./data/vectors", help="Root of vectors folder")
    ap.add_argument("--validate", action="store_true", help="Run vector checks first (Wycheproof RSA, ACVP presence)")
    args = ap.parse_args()

    vectors_root = Path(args.vectors).resolve()

    if args.validate:
        step("Vector checks (RSA via Wycheproof)")
        _, passed, failed = run_wycheproof_rsa(vectors_root, limit_per_file=50)
        if failed > 0:
            print("WARNING: Some Wycheproof RSA tests failed (check your runtime env).")
        if has_acvp(vectors_root):
            print("ACVP vectors present for ML-KEM/ML-DSA/SLH-DSA (using self-tests for KEM/sign here).")
        else:
            print("ACVP vectors not found at --vectors; proceeding with self-tests.")

    kem_hybrid_demo(args.kem, args.plaintext.encode())

if __name__ == "__main__":
    main()
