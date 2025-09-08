# test_rsa_oaep.py
import json
import time
import statistics

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from acvp_fetch import read_json, pick_one_rel

# -------------------- ACVP hash mapping --------------------
def _hash_from_acvp(name: str):
    n = (name or "").strip().upper().replace(" ", "")
    table = {
        "SHA-1": hashes.SHA1,
        "SHA1": hashes.SHA1,

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
        return table[n]
    n2 = n.replace("-", "").replace("/", "")
    for k, v in table.items():
        if k.replace("-", "").replace("/", "") == n2:
            return v
    raise ValueError(f"Unsupported/unknown hashAlg from ACVP: {name!r}")

# -------------------- helpers --------------------
def _as_int(val):
    """Parse an ACVP integer field that might be hex string or already an int."""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        # allow raw decimal or hex-encoded string without 0x
        try:
            return int(s, 16)
        except Exception:
            try:
                return int(s, 10)
            except Exception:
                pass
    raise ValueError(f"Cannot parse integer from value: {val!r}")

def _hex_bytes(obj, *keys):
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str):
            try:
                return bytes.fromhex(v)
            except Exception:
                pass
    return None

def _load_vectors():
    """
    Prefer expectedResults (contains plaintext/ciphertext) and fall back to prompt if needed.
    KTS-IFC is the ACVP algorithm that covers RSA-OAEP KTS.
    """
    try:
        return read_json(pick_one_rel("**/KTS-IFC*/**/*", "expectedresults"))
    except Exception:
        # Older drops or different naming may use KAS-IFC*
        try:
            return read_json(pick_one_rel("**/KAS-IFC*/**/*", "expectedresults"))
        except Exception:
            # last resort: prompt (fewer fields; many tests will be SKIP)
            try:
                return read_json(pick_one_rel("**/KTS-IFC*/**/*", "prompt"))
            except Exception:
                return {"testGroups": []}

def _build_private_key_from_components(test):
    """
    Build an RSA private key using cryptography's RSAPrivateNumbers.
    Requires p and q. If p/q missing, return (None, reason).
    """
    n = _as_int(test.get("n"))
    e = _as_int(test.get("e"))
    d = _as_int(test.get("d"))
    p = _as_int(test.get("p"))
    q = _as_int(test.get("q"))

    if n is None or e is None:
        return None, "Missing n/e"
    if d is None:
        return None, "Missing d"
    if p is None or q is None:
        # cryptography cannot construct a private key from (n,e,d) alone
        return None, "Missing p/q (cannot construct private key)"

    # optional CRT values
    dmp1 = _as_int(test.get("dmp1"))
    dmq1 = _as_int(test.get("dmq1"))
    iqmp = _as_int(test.get("iqmp"))

    if dmp1 is None:
        dmp1 = rsa.rsa_crt_dmp1(d, p)
    if dmq1 is None:
        dmq1 = rsa.rsa_crt_dmq1(d, q)
    if iqmp is None:
        iqmp = rsa.rsa_crt_iqmp(p, q)

    priv_nums = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    try:
        return priv_nums.private_key(), None
    except Exception as ex:
        return None, f"Private key construction failed: {ex}"

def _build_public_key_from_components(test):
    n = _as_int(test.get("n"))
    e = _as_int(test.get("e"))
    if n is None or e is None:
        return None, "Missing n/e"
    try:
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub, None
    except Exception as ex:
        return None, f"Public key construction failed: {ex}"

def _oaep_from_group(group):
    hash_alg = group.get("hashAlg") or "SHA2-256"
    mgf_hash = group.get("mgfAlg") or hash_alg
    label_hex = group.get("label")  # often absent
    label_bytes = bytes.fromhex(label_hex) if isinstance(label_hex, str) else None

    hash_cls = _hash_from_acvp(hash_alg)
    mgf_hash_cls = _hash_from_acvp(mgf_hash)

    return padding.OAEP(
        mgf=padding.MGF1(algorithm=mgf_hash_cls()),
        algorithm=hash_cls(),
        label=label_bytes,
    )

# -------------------- main --------------------
def run_tests():
    results = []
    vectors = _load_vectors()

    for group in vectors.get("testGroups", []):
        oaep = _oaep_from_group(group)
        tests = group.get("tests", [])

        for test in tests:
            tc_id = test.get("tcId")
            # ACVP expectedResults typically provide cipherText for decrypt checks, and sometimes plainText.
            pt_vec = _hex_bytes(test, "plainText", "pt")
            ct_vec = _hex_bytes(test, "cipherText", "ct")

            entry = {
                "Algorithm": "RSA-OAEP",
                "Operation": "",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }

            try:
                # Prefer decryption tests (deterministic check). Requires private key with p/q.
                if ct_vec is not None:
                    entry["Operation"] = "Decryption"
                    private_key, reason = _build_private_key_from_components(test)
                    if private_key is None:
                        entry["Result"] = "SKIP"
                        entry["Discrepancy"] = f"Cannot build private key: {reason}"
                        results.append(entry)
                        continue

                    # time 30x
                    times, last_pt = [], None
                    for _ in range(30):
                        t0 = time.time()
                        last_pt = private_key.decrypt(ct_vec, oaep)
                        t1 = time.time()
                        times.append(t1 - t0)
                    entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                    entry["StdDev(s)"] = round(statistics.pstdev(times), 6)

                    if pt_vec is not None and last_pt != pt_vec:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Plaintext mismatch after decryption"

                # Otherwise, if only pt is provided (encryption KAT): skip exact match (OAEP randomized).
                elif pt_vec is not None:
                    entry["Operation"] = "Encryption"
                    # We could build a public key and encrypt, but we cannot reproduce ACVP ciphertext without the internal seed.
                    pub, reason = _build_public_key_from_components(test)
                    if pub is None:
                        entry["Result"] = "SKIP"
                        entry["Discrepancy"] = f"Cannot build public key for encryption: {reason}"
                        results.append(entry)
                        continue
                    # Timing-only encryption (no byte-for-byte compare)
                    times = []
                    for _ in range(30):
                        t0 = time.time()
                        _ = pub.encrypt(pt_vec, oaep)
                        t1 = time.time()
                        times.append(t1 - t0)
                    entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                    entry["StdDev(s)"] = round(statistics.pstdev(times), 6)
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = "OAEP encryption randomized; exact ciphertext cannot be matched"

                else:
                    # Nothing actionable in this test record
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = "No cipherText/plainText fields present"

            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"

            results.append(entry)

    return results
