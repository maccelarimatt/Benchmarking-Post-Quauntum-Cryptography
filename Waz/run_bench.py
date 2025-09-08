
# Small benchmark/validation harness for the Investigation Project.
# python3 run_bench.py --matrix test_matrix.yaml --vectors ./data/vectors --out results.csv


# - Reads ./test_matrix.yaml (or --matrix).
# - Iterates algorithms/ops, repeats, and RSA OAEP message-lengths from the matrix.
# - Uses:
#     * cryptography  for RSA-OAEP / RSA-PSS
#     * oqs (liboqs)  for ML-KEM / ML-DSA / SLH-DSA (SPHINCS+) if available
# - Writes CSV: algo,op,param_set,trial,elapsed_ms,mem_bytes,ok,skip_reason

# Vectors:
# - ACVP/Wycheproof JSON reading is scaffolded; enable --validate to attempt vector-based checks
#   (requires oqs and cryptography). By default the harness runs "self-KAT" (round-trip) tests.

# Note: Keep this intentionally small and readable. Tweak OQS_ALGO_MAP for your environment.


import argparse
import csv
import json
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Union, Tuple


# Optional deps
try:
    import psutil
except Exception:
    psutil = None

try:
    import yaml  # PyYAML
except Exception as e:
    print("ERROR: PyYAML is required (pip install pyyaml).")
    raise

# cryptography for RSA
CRYPTO_OK = True
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
except Exception:
    CRYPTO_OK = False

# oqs (liboqs) for PQC
OQS_OK = True
try:
    import oqs
except Exception:
    OQS_OK = False


# ---- Helpers ----

# ---- liboqs-python compatibility helpers ----
def enabled_kems():
    if hasattr(oqs, "get_enabled_kem_mechanisms"):
        return oqs.get_enabled_kem_mechanisms()
    elif hasattr(oqs, "get_enabled_kems"):
        return oqs.get_enabled_kems()
    return []

def enabled_sigs():
    if hasattr(oqs, "get_enabled_sig_mechanisms"):
        return oqs.get_enabled_sig_mechanisms()
    elif hasattr(oqs, "get_enabled_sigs"):
        return oqs.get_enabled_sigs()
    return []

def kem_roundtrip(algo_name: str):
    if not OQS_OK:
        return False, "oqs_not_available"
    oqs_name = OQS_ALGO_MAP.get(algo_name, algo_name)
    if oqs_name not in enabled_kems():
        return False, f"kem_not_enabled:{oqs_name}"
    with oqs.KeyEncapsulation(oqs_name) as kem:
        public_key = kem.generate_keypair()
        # liboqs-python compatibility: old vs new method names
        if hasattr(kem, "encapsulate") and hasattr(kem, "decapsulate"):
            ct, ss_enc = kem.encapsulate(public_key)
            ss_dec = kem.decapsulate(ct)
        else:
            ct, ss_enc = kem.encap_secret(public_key)
            ss_dec = kem.decap_secret(ct)
        ok = (ss_enc == ss_dec)
        return ok, "" if ok else "kem_mismatch"



def rss_bytes() -> int:
    if psutil is None:
        return -1
    try:
        return psutil.Process(os.getpid()).memory_info().rss
    except Exception:
        return -1


def measure(fn):
    #"""Measure elapsed ms and current RSS around fn()."""
    before_mem = rss_bytes()
    t0 = time.perf_counter()
    ok, info = fn()
    t1 = time.perf_counter()
    after_mem = rss_bytes()
    elapsed_ms = (t1 - t0) * 1000.0
    mem_b = after_mem if after_mem >= 0 else before_mem
    return ok, info, elapsed_ms, mem_b


def get_hash(name: str):
    name = name.lower()
    if name in ("sha256", "sha-256", "sha2-256"):
        return hashes.SHA256()
    if name in ("sha384", "sha-384", "sha2-384"):
        return hashes.SHA384()
    if name in ("sha512", "sha-512", "sha2-512"):
        return hashes.SHA512()
    raise ValueError(f"Unsupported hash: {name}")


# Mapping from matrix algorithm names to liboqs IDs.
OQS_ALGO_MAP = {
    # KEM
    "ML-KEM-512":  "ML-KEM-512",
    "ML-KEM-768":  "ML-KEM-768",
    "ML-KEM-1024": "ML-KEM-1024",
    "Kyber512": "Kyber512",
    "Kyber768": "Kyber768",
    "Kyber1024": "Kyber1024",
    "HQC-128": "HQC-128-1-cca2",
    "HQC-192": "HQC-192-1-cca2",
    "HQC-256": "HQC-256-1-cca2",

    # Signatures (Dilithium / ML-DSA). Many liboqs builds accept both naming forms.
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "Dilithium2": "Dilithium2",
    "Dilithium3": "Dilithium3",
    "Dilithium5": "Dilithium5",

    # SPHINCS+ (SLH-DSA) — adjust to your liboqs build (simple/robust naming can vary)
    "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s-simple",
    "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s-simple",
    "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s-simple",

    # XMSS (stateful) — optional; many builds skip
    "XMSS-SHA2_20/2_256": "XMSS-SHA2_20/2_256",
}


from dataclasses import dataclass

@dataclass
class BenchRow:
    algo: str
    op: str
    param_set: str
    trial: int
    elapsed_ms: float
    mem_bytes: int
    ok: bool
    skip_reason: str = ""

    def to_list(self):
        return [self.algo, self.op, self.param_set, self.trial,
                f"{self.elapsed_ms:.3f}", self.mem_bytes, int(self.ok), self.skip_reason]


# ---- RSA ops with cryptography ----

def rsa_keygen(nbits: int):
    key = rsa.generate_private_key(public_exponent=65537, key_size=nbits, backend=default_backend())
    return key

def rsa_oaep_encrypt(pubkey, msg: bytes, hash_name: str, label: bytes):
    h = get_hash(hash_name)
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=label)
    ct = pubkey.encrypt(msg, pad)
    return ct

def rsa_oaep_decrypt(privkey, ct: bytes, hash_name: str, label: bytes):
    h = get_hash(hash_name)
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=label)
    pt = privkey.decrypt(ct, pad)
    return pt

def rsa_pss_sign(privkey, msg: bytes, hash_name: str, salt_len: Union[str, int]):
    h = get_hash(hash_name)
    if salt_len == "hashLen":
        salt_length = h.digest_size
    else:
        salt_length = int(salt_len)
    pad = padding.PSS(mgf=padding.MGF1(h), salt_length=salt_length)
    sig = privkey.sign(msg, pad, h)
    return sig

def rsa_pss_verify(pubkey, msg: bytes, sig: bytes, hash_name: str, salt_len: Union[str, int]):
    h = get_hash(hash_name)
    if salt_len == "hashLen":
        salt_length = h.digest_size
    else:
        salt_length = int(salt_len)
    pad = padding.PSS(mgf=padding.MGF1(h), salt_length=salt_length)
    pubkey.verify(sig, msg, pad, h)


# ---- PQC ops with oqs ----


def sig_roundtrip(algo_name: str):
    if not OQS_OK:
        return False, "oqs_not_available"
    oqs_name = OQS_ALGO_MAP.get(algo_name, algo_name)
    if oqs_name not in enabled_sigs(): 
        return False, f"sig_not_enabled:{oqs_name}"
    with oqs.Signature(oqs_name) as sig:
        public_key = sig.generate_keypair()
        msg = os.urandom(64)
        signature = sig.sign(msg)
        ok = sig.verify(msg, signature, public_key)
        return bool(ok), "" if ok else "sig_verify_fail"


# ---- ACVP / Wycheproof stubs ----

def acvp_available(vectors_root: Path) -> bool:
    return (vectors_root / "nist_acvp").exists()

def wycheproof_available(vectors_root: Path) -> bool:
    return (vectors_root / "wycheproof").exists()

def run_acvp_sample(algo: str, op: str, vectors_root: Path) -> Tuple[bool, str]:
    """
    Minimal placeholder: prove we can find relevant files.
    Extend this to parse and validate per-test-case.
    """
    root = vectors_root / "nist_acvp"
    hits = list(root.rglob("*.json"))
    if not hits:
        return False, "no_acvp_json_found"
    return True, f"acvp_files:{len(hits)}"

def run_wycheproof_sample(op: str, vectors_root: Path) -> Tuple[bool, str]:
    root = vectors_root / "wycheproof" / "wycheproof-main" / "testvectors_v1"
    if not root.exists():
        root = vectors_root / "wycheproof"
    hits = list(root.rglob("*.json"))
    if not hits:
        return False, "no_wycheproof_json_found"
    return True, f"wycheproof_files:{len(hits)}"


# ---- Main runner ----

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", default="test_matrix.yaml")
    ap.add_argument("--vectors", default="./data/vectors")
    ap.add_argument("--out", default="results.csv")
    ap.add_argument("--algo", default=None, help="Filter to one algo name (as in matrix)")
    ap.add_argument("--ops", default=None, help="Comma list to filter ops (e.g., keygen,sign,verify)")
    ap.add_argument("--validate", action="store_true", help="Attempt vector-based checks (ACVP/Wycheproof)")
    args = ap.parse_args()

    random.seed(42)
    vectors_root = Path(args.vectors).resolve()
    matrix = yaml.safe_load(open(args.matrix, "r"))

    repeats = int(matrix.get("bench", {}).get("repeats", 30))
    warmup = int(matrix.get("bench", {}).get("warmup", 3))

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    csvf = open(out_path, "w", newline="")
    writer = csv.writer(csvf)
    writer.writerow(["algo","op","param_set","trial","elapsed_ms","mem_bytes","ok","skip_reason"])

    # Optional filters
    filter_ops = set([s.strip() for s in args.ops.split(",")]) if args.ops else None

    # --- RSA ---
    rsa_algos = matrix.get("algorithms", {}).get("rsa", {})
    if rsa_algos:
        if args.algo is None or args.algo.upper().startswith("RSA"):
            # OAEP
            oaep = rsa_algos.get("oaep", {})
            if oaep:
                for nbits in oaep.get("moduli", []):
                    for hname in oaep.get("hashes", []):
                        for label in oaep.get("label", [""]):
                            # keygen once for this param-set
                            if not CRYPTO_OK:
                                for trial in range(repeats):
                                    row = BenchRow("RSA-OAEP", "keygen", f"{nbits}-{hname}-label:{label}", trial, 0.0, -1, False, "cryptography_not_available")
                                    writer.writerow(row.to_list())
                                continue

                            key = None
                            ok, info, elapsed_ms, mem_b = measure(lambda: (True, rsa_keygen(nbits)))
                            if hasattr(info, "public_key"):
                                key = info
                                ok = True
                                skip = ""
                            else:
                                ok = False
                                skip = "rsa_keygen_failed"
                            writer.writerow(BenchRow("RSA-OAEP","keygen",f"{nbits}-{hname}-label:{label}",0,elapsed_ms,mem_b,ok,skip).to_list())

                            pub = key.public_key() if key else None
                            # Warmups
                            for _ in range(warmup):
                                if key:
                                    msg = os.urandom(32)
                                    _ = rsa_oaep_decrypt(key, rsa_oaep_encrypt(pub, msg, hname, label.encode()), hname, label.encode())

                            # message lengths per matrix
                            msg_lens = oaep.get("message_lengths", {}).get(str(nbits), {}).get(hname, [32, 64])
                            for mlen in msg_lens:
                                for trial in range(1, repeats+1):
                                    def do():
                                        if not key:
                                            return False, "no_key"
                                        msg = os.urandom(mlen)
                                        ct = rsa_oaep_encrypt(pub, msg, hname, label.encode())
                                        pt = rsa_oaep_decrypt(key, ct, hname, label.encode())
                                        return (pt == msg), ""
                                    ok, info, elapsed_ms, mem_b = measure(do)
                                    writer.writerow(BenchRow("RSA-OAEP", f"encrypt+decrypt", f"{nbits}-{hname}-mlen:{mlen}-label:{label}", trial, elapsed_ms, mem_b, ok, info).to_list())

                            # Optional: Wycheproof file presence check
                            if args.validate:
                                ok, reason = run_wycheproof_sample("oaep", vectors_root)
                                writer.writerow(BenchRow("RSA-OAEP","wycheproof",f"{nbits}-{hname}",0,0.0,-1,ok,reason).to_list())

            # PSS
            pss = rsa_algos.get("pss", {})
            if pss:
                for nbits in pss.get("moduli", []):
                    for hname in pss.get("hashes", []):
                        for salt_len in pss.get("salt_len", ["hashLen"]):
                            if not CRYPTO_OK:
                                for trial in range(repeats):
                                    writer.writerow(BenchRow("RSA-PSS","keygen",f"{nbits}-{hname}-salt:{salt_len}",trial,0.0,-1,False,"cryptography_not_available").to_list())
                                continue

                            # keygen once
                            ok, info, elapsed_ms, mem_b = measure(lambda: (True, rsa_keygen(nbits)))
                            key = info if hasattr(info, "public_key") else None
                            writer.writerow(BenchRow("RSA-PSS","keygen",f"{nbits}-{hname}-salt:{salt_len}",0,elapsed_ms,mem_b, key is not None, "" if key else "rsa_keygen_failed").to_list())
                            pub = key.public_key() if key else None

                            # warmups
                            for _ in range(warmup):
                                if key:
                                    msg = os.urandom(64)
                                    sig = rsa_pss_sign(key, msg, hname, salt_len)
                                    rsa_pss_verify(pub, msg, sig, hname, salt_len)

                            for trial in range(1, repeats+1):
                                def do():
                                    if not key:
                                        return False, "no_key"
                                    msg = os.urandom(64)
                                    sig = rsa_pss_sign(key, msg, hname, salt_len)
                                    rsa_pss_verify(pub, msg, sig, hname, salt_len)
                                    return True, ""
                                ok, info, elapsed_ms, mem_b = measure(do)
                                writer.writerow(BenchRow("RSA-PSS","sign+verify",f"{nbits}-{hname}-salt:{salt_len}", trial, elapsed_ms, mem_b, ok, info).to_list())

                            if args.validate:
                                ok, reason = run_wycheproof_sample("pss", vectors_root)
                                writer.writerow(BenchRow("RSA-PSS","wycheproof",f"{nbits}-{hname}",0,0.0,-1,ok,reason).to_list())

    # --- KEMs ---
    for kem in matrix.get("algorithms", {}).get("kems", []):
        name = kem.get("name")
        if args.algo and args.algo != name:
            continue
        # Warmup
        if OQS_OK:
            kem_roundtrip(name)
        for trial in range(1, repeats+1):
            ok, info, elapsed_ms, mem_b = measure(lambda: kem_roundtrip(name))
            writer.writerow(BenchRow(name,"keygen+encaps+decaps",name,trial,elapsed_ms,mem_b,ok,info).to_list())

        if args.validate and acvp_available(Path(args.vectors)):
            ok, reason = run_acvp_sample(name, "kem", Path(args.vectors))
            writer.writerow(BenchRow(name,"acvp",name,0,0.0,-1,ok,reason).to_list())

    # --- Signatures ---
    for sig in matrix.get("algorithms", {}).get("signatures", []):
        name = sig.get("name")
        if args.algo and args.algo != name:
            continue
        # Warmup
        if OQS_OK:
            sig_roundtrip(name)
        for trial in range(1, repeats+1):
            ok, info, elapsed_ms, mem_b = measure(lambda: sig_roundtrip(name))
            writer.writerow(BenchRow(name,"keygen+sign+verify",name,trial,elapsed_ms,mem_b,ok,info).to_list())

        if args.validate and acvp_available(Path(args.vectors)):
            ok, reason = run_acvp_sample(name, "sig", Path(args.vectors))
            writer.writerow(BenchRow(name,"acvp",name,0,0.0,-1,ok,reason).to_list())

    csvf.close()
    print(f"[✓] Wrote: {out_path}")

if __name__ == "__main__":
    main()
