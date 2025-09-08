# test_rsa_pss.py
import json
import time
import statistics
from typing import Optional, Callable

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from acvp_fetch import read_json, pick_one_rel

# -------------------- helpers: parsing --------------------
def _b64url_to_int(s: str) -> Optional[int]:
    try:
        import base64
        pad = "=" * (-len(s) % 4)
        data = base64.urlsafe_b64decode(s + pad)
        return int.from_bytes(data, "big")
    except Exception:
        return None

def _as_int_any(val) -> Optional[int]:
    """
    Parse an ACVP integer that might be:
      - native int
      - hex string (no 0x)
      - decimal string
      - JWK base64url string
    """
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        # try hex
        try:
            return int(s, 16)
        except Exception:
            pass
        # try decimal
        try:
            return int(s, 10)
        except Exception:
            pass
        # try base64url (JWK)
        b64i = _b64url_to_int(s.replace(" ", ""))
        if b64i is not None:
            return b64i
    return None

def _hex_bytes(obj, *keys):
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str):
            try:
                return bytes.fromhex(v)
            except Exception:
                pass
    return None

def _first_present(*vals):
    for v in vals:
        if v is not None:
            return v
    return None

# -------------------- SHA / SHAKE hash factories --------------------
def _shake_len_bytes_default(name_upper: str) -> int:
    if "SHAKE-128" in name_upper:
        return 16  # 128-bit output
    if "SHAKE-256" in name_upper:
        return 32  # 256-bit output
    return 32

def _extract_hash_len_bytes_from_group_or_test(group, test) -> Optional[int]:
    # ACVP sometimes exposes digest length as bits; normalize to bytes.
    for src in (test, group):
        if not isinstance(src, dict):
            continue
        for k in ("hashLen", "dLen", "outputLen", "digestLen"):
            v = src.get(k)
            if isinstance(v, int) and v > 0:
                return v // 8 if v > 64 else v
    return None

def _hash_maker_from_acvp(name: str, group=None, test=None) -> Callable[[], hashes.HashAlgorithm]:
    """
    Return a zero-arg function that constructs the correct HashAlgorithm.
    Handles SHA1/2/3 and SHAKE (with a digest length).
    """
    n = (name or "").strip().upper().replace(" ", "")
    # SHAKE requires explicit output length
    if n.startswith("SHAKE-128"):
        dlen = _extract_hash_len_bytes_from_group_or_test(group, test) or _shake_len_bytes_default(n)
        return lambda: hashes.SHAKE128(dlen)
    if n.startswith("SHAKE-256"):
        dlen = _extract_hash_len_bytes_from_group_or_test(group, test) or _shake_len_bytes_default(n)
        return lambda: hashes.SHAKE256(dlen)

    table = {
        "SHA-1": hashes.SHA1, "SHA1": hashes.SHA1,
        "SHA2-224": hashes.SHA224, "SHA-224": hashes.SHA224,
        "SHA2-256": hashes.SHA256, "SHA-256": hashes.SHA256,
        "SHA2-384": hashes.SHA384, "SHA-384": hashes.SHA384,
        "SHA2-512": hashes.SHA512, "SHA-512": hashes.SHA512,
        "SHA2-512/224": hashes.SHA512_224, "SHA-512/224": hashes.SHA512_224,
        "SHA2-512/256": hashes.SHA512_256, "SHA-512/256": hashes.SHA512_256,
        "SHA3-224": hashes.SHA3_224,
        "SHA3-256": hashes.SHA3_256,
        "SHA3-384": hashes.SHA3_384,
        "SHA3-512": hashes.SHA3_512,
    }
    if n in table:
        cls = table[n]
        return lambda: cls()
    n2 = n.replace("-", "").replace("/", "")
    for k, v in table.items():
        if k.replace("-", "").replace("/", "") == n2:
            return lambda: v()
    raise ValueError(f"Unsupported/unknown hashAlg: {name!r}")

# -------------------- vector loading (robust) --------------------
def load_rsa_pss_vectors():
    """
    ACVP layout typically:
      gen-val/json-files/RSA-SigGen-FIPS186-5/expectedResults.json
      gen-val/json-files/RSA-SigVer-FIPS186-5/prompt.json
    Filenames may not mention 'pss'; we'll filter by contents.
    """
    try:
        siggen = read_json(pick_one_rel("**/RSA-SigGen-FIPS186-5/**", "expectedresults"))
    except Exception:
        siggen = {"testGroups": []}
    try:
        sigver = read_json(pick_one_rel("**/RSA-SigVer-FIPS186-5/**", "prompt"))
    except Exception:
        sigver = {"testGroups": []}
    return siggen, sigver

# -------------------- pull keys from test/group/jwk --------------------
def _group_key_dict(group):
    # Some files nest under 'key' or 'jwk'
    key = group.get("key") or {}
    jwk = group.get("jwk") or {}
    # Flatten a unified view; prefer direct group fields
    return {
        "n": _first_present(group.get("n"), key.get("n"), jwk.get("n")),
        "e": _first_present(group.get("e"), key.get("e"), jwk.get("e")),
        "d": _first_present(group.get("d"), key.get("d"), jwk.get("d")),
        "p": _first_present(group.get("p"), key.get("p"), jwk.get("p")),
        "q": _first_present(group.get("q"), key.get("q"), jwk.get("q")),
        "dmp1": _first_present(group.get("dmp1"), key.get("dmp1")),
        "dmq1": _first_present(group.get("dmq1"), key.get("dmq1")),
        "iqmp": _first_present(group.get("iqmp"), key.get("iqmp")),
    }

def _merged_key_fields(group, test):
    gk = _group_key_dict(group)
    # Prefer test fields; fall back to group/key/jwk
    return {
        "n": _first_present(test.get("n"), gk["n"]),
        "e": _first_present(test.get("e"), gk["e"]),
        "d": _first_present(test.get("d"), gk["d"]),
        "p": _first_present(test.get("p"), gk["p"]),
        "q": _first_present(test.get("q"), gk["q"]),
        "dmp1": _first_present(test.get("dmp1"), gk["dmp1"]),
        "dmq1": _first_present(test.get("dmq1"), gk["dmq1"]),
        "iqmp": _first_present(test.get("iqmp"), gk["iqmp"]),
    }

def _build_private_key_from(group, test):
    f = _merged_key_fields(group, test)
    n = _as_int_any(f["n"])
    e = _as_int_any(f["e"])
    d = _as_int_any(f["d"])
    p = _as_int_any(f["p"])
    q = _as_int_any(f["q"])
    if n is None or e is None or d is None:
        return None, "Missing n/e/d"
    if p is None or q is None:
        return None, "Missing p/q (cannot construct private key)"
    dmp1 = _as_int_any(f["dmp1"]) or rsa.rsa_crt_dmp1(d, p)
    dmq1 = _as_int_any(f["dmq1"]) or rsa.rsa_crt_dmq1(d, q)
    iqmp = _as_int_any(f["iqmp"]) or rsa.rsa_crt_iqmp(p, q)
    try:
        priv = rsa.RSAPrivateNumbers(
            p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
        ).private_key()
        return priv, None
    except Exception as ex:
        return None, f"Private key construction failed: {ex}"

def _build_public_key_from(group, test):
    f = _merged_key_fields(group, test)
    n = _as_int_any(f["n"])
    e = _as_int_any(f["e"])
    if n is None or e is None:
        return None, "Missing n/e"
    try:
        return rsa.RSAPublicNumbers(e, n).public_key(), None
    except Exception as ex:
        return None, f"Public key construction failed: {ex}"

def _salt_len_from(group, test):
    v = _first_present(test.get("saltLen"), group.get("saltLen"))
    return v if isinstance(v, int) and v >= 0 else None

# -------------------- padding builders --------------------
def _pss_padding_for_verify(hash_maker, salt_len):
    sl = salt_len if (isinstance(salt_len, int) and salt_len >= 0) else padding.PSS.AUTO
    return padding.PSS(mgf=padding.MGF1(hash_maker()), salt_length=sl)

def _pss_padding_for_sign(hash_maker, salt_len):
    sl = salt_len if (isinstance(salt_len, int) and salt_len >= 0) else padding.PSS.MAX_LENGTH
    return padding.PSS(mgf=padding.MGF1(hash_maker()), salt_length=sl)

# -------------------- main --------------------
def run_tests():
    results = []
    siggen_vectors, sigver_vectors = load_rsa_pss_vectors()

    # -------- SigGen --------
    for group in siggen_vectors.get("testGroups", []):
        hash_alg = group.get("hashAlg") or "SHA2-256"

        for test in group.get("tests", []):
            # per-test override
            test_hash_alg = test.get("hashAlg") or hash_alg
            hash_maker = _hash_maker_from_acvp(test_hash_alg, group, test)
            pss_pad = _pss_padding_for_sign(hash_maker, _salt_len_from(group, test))

            tc_id = test.get("tcId")
            message = _hex_bytes(test, "message", "msg") or b""
            sig_expected = _hex_bytes(test, "signature", "sig")

            entry = {
                "Algorithm": "RSA-PSS",
                "Operation": "SigGen",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }

            try:
                priv, reason = _build_private_key_from(group, test)
                if priv is None:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No private key for SigGen: {reason}"
                    results.append(entry)
                    continue

                times = []
                sig0 = None
                for i in range(30):
                    t0 = time.time()
                    sig = priv.sign(message, pss_pad, hash_maker())
                    t1 = time.time()
                    times.append(t1 - t0)
                    if sig0 is None:
                        sig0 = sig
                entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                entry["StdDev(s)"] = round(statistics.pstdev(times), 6)

                if sig_expected is not None:
                    if sig0 != sig_expected:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Signature mismatch (PSS randomized unless salt fixed)"
                else:
                    pub = priv.public_key()
                    try:
                        pub.verify(sig0, message, pss_pad, hash_maker())
                    except Exception:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Self-verification failed"

            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"

            results.append(entry)

    # -------- SigVer --------
    for group in sigver_vectors.get("testGroups", []):
        hash_alg = group.get("hashAlg") or "SHA2-256"

        for test in group.get("tests", []):
            test_hash_alg = test.get("hashAlg") or hash_alg
            hash_maker = _hash_maker_from_acvp(test_hash_alg, group, test)
            pss_pad = _pss_padding_for_verify(hash_maker, _salt_len_from(group, test))

            tc_id = test.get("tcId")
            message = _hex_bytes(test, "message", "msg") or b""
            signature = _hex_bytes(test, "signature", "sig") or b""
            expected = bool(test.get("testPassed"))

            entry = {
                "Algorithm": "RSA-PSS",
                "Operation": "SigVer",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }
            try:
                pub, reason = _build_public_key_from(group, test)
                if pub is None:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No public key for SigVer: {reason}"
                    results.append(entry)
                    continue

                times, ok = [], False
                for _ in range(30):
                    t0 = time.time()
                    try:
                        pub.verify(signature, message, pss_pad, hash_maker())
                        ok = True
                    except Exception:
                        ok = False
                    t1 = time.time()
                    times.append(t1 - t0)

                entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                entry["StdDev(s)"] = round(statistics.pstdev(times), 6)
                if ok != expected:
                    entry["Result"] = "FAIL"
                    entry["Discrepancy"] = f"Verification result mismatch (expected {expected})"

            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"

            results.append(entry)

    return results
