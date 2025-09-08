# oqs_compat.py
import re

def _first_working_sig(oqs, candidates):
    """
    Try to construct oqs.Signature with any of the candidate names.
    Return (name, signer_instance) on success, else (None, None).
    """
    for name in candidates:
        try:
            s = oqs.Signature(name)
            return name, s
        except Exception:
            continue
    return None, None

def _first_working_kem(oqs, candidates):
    """
    Try to construct oqs.KeyEncapsulation with any candidate.
    Return (name, kem_instance) or (None, None).
    """
    for name in candidates:
        try:
            k = oqs.KeyEncapsulation(name)
            return name, k
        except Exception:
            continue
    return None, None

# --- ACVP → liboqs name mappers ---

def map_mldsa_to_oqs(acvp_param):
    """
    ACVP ML-DSA (FIPS 204) names commonly look like:
      ML-DSA-44, ML-DSA-65, ML-DSA-87
    Map to Dilithium{2,3,5}.
    """
    if not acvp_param:
        return []
    m = re.search(r"ML-DSA-(\d+)", acvp_param)
    if not m:
        return [acvp_param]  # try raw
    code = int(m.group(1))
    dmap = {44: "Dilithium2", 65: "Dilithium3", 87: "Dilithium5"}
    cand = dmap.get(code)
    return [acvp_param, cand] if cand else [acvp_param]

def map_slh_dsa_to_oqs(acvp_param):
    """
    ACVP SLH-DSA (FIPS 205) names look like:
      SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-192f-robust, etc.
    liboqs uses SPHINCS+ names like:
      SPHINCS+-SHA2-128s-simple / -robust, etc.
    We’ll infer -simple vs -robust from the ACVP string if present; default to -simple.
    """
    if not acvp_param:
        return []
    base = acvp_param.upper()
    # Extract hash family, size, s/f, and robustness
    # Examples in ACVP: SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-256f-robust
    m = re.match(r"SLH-DSA-(SHA2|SHAKE)-(\d+)([sf])(?:-(SIMPLE|ROBUST))?", base)
    cands = []
    if m:
        family = m.group(1)  # SHA2 or SHAKE
        size = m.group(2)    # 128/192/256
        sf = m.group(3)      # s or f
        robust = m.group(4) or "SIMPLE"
        oqs_name = f"SPHINCS+-{family}-{size}{sf.lower()}-{robust.lower()}"
        cands.append(oqs_name)
    # Also try both simple/robust variants just in case
    for robust in ("simple", "robust"):
        for family in ("SHA2", "SHAKE"):
            cands.append(f"SPHINCS+-{family}-128s-{robust}")
            cands.append(f"SPHINCS+-{family}-128f-{robust}")
            cands.append(f"SPHINCS+-{family}-192s-{robust}")
            cands.append(f"SPHINCS+-{family}-192f-{robust}")
            cands.append(f"SPHINCS+-{family}-256s-{robust}")
            cands.append(f"SPHINCS+-{family}-256f-{robust}")
    # Finally, also include the raw ACVP name to try
    cands.append(acvp_param)
    # Deduplicate while preserving order
    seen, uniq = set(), []
    for x in cands:
        if x and x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def map_fndsa_to_oqs(acvp_param):
    """
    ACVP FN-DSA (Falcon) often encoded as Falcon-512/Falcon-1024 or FN-DSA-512/1024.
    """
    if not acvp_param:
        return []
    up = acvp_param.upper()
    cands = []
    m = re.search(r"(FALCON|FN-DSA)[-_]?(\d+)", up)
    if m:
        size = m.group(2)
        cands.append(f"Falcon-{size}")
    # Try both Falcon sizes regardless
    cands += ["Falcon-512", "Falcon-1024", acvp_param]
    return list(dict.fromkeys(cands))

def map_mlkem_to_oqs(acvp_param):
    """
    ACVP ML-KEM-512/768/1024 → liboqs names commonly `Kyber512/768/1024`,
    though newer liboqs may also provide ML-KEM-* aliases. Try both.
    """
    if not acvp_param:
        return []
    m = re.search(r"ML[-_]KEM[-_]?(\d+)", acvp_param.upper())
    cands = []
    if m:
        lvl = m.group(1)
        cands += [f"ML-KEM-{lvl}", f"Kyber{lvl}"]
    # Also try the common three directly
    cands += ["Kyber512", "Kyber768", "Kyber1024", acvp_param]
    return list(dict.fromkeys(cands))
