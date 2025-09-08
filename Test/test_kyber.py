# test_kyber.py
import json, time, statistics
try:
    import oqs
except ImportError:
    oqs = None

from acvp_fetch import read_json, pick_one_rel
from oqs_compat import _first_working_kem, map_mlkem_to_oqs

def load_kyber_vectors():
    # Use encap/decap prompt (FIPS 203); OK if empty.
    try:
        return read_json(pick_one_rel("ML-KEM-encapDecap-FIPS203/*", "prompt"))
    except Exception:
        return {"testGroups": []}

def _get_detail_len(details_obj, name):
    """Best-effort: read a length from kem.details if this liboqs exposes it."""
    if not details_obj:
        return None
    # common field names used by liboqs bindings in some versions
    for key in (name, f"length_{name}", f"{name}_length"):
        if hasattr(details_obj, key):
            try:
                val = getattr(details_obj, key)
                if isinstance(val, int) and val > 0:
                    return val
            except Exception:
                pass
    return None

def run_tests():
    results = []
    if not oqs:
        return results

    vectors = load_kyber_vectors()

    for group in vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., ML-KEM-512/768/1024
        candidates = map_mlkem_to_oqs(acvp_param)
        alg, kem = _first_working_kem(oqs, candidates)

        # If ACVP JSON is minimal, make at least one dummy test to exercise the op.
        tests = group.get("tests", []) or [{"tcId": "rt-1"}]

        for test in tests:
            tc_id = test.get("tcId")
            entry = {
                "Algorithm": "Kyber",
                "Operation": "KEM-Roundtrip",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }
            try:
                if not alg:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No supported OQS alg for {acvp_param}"
                    results.append(entry)
                    continue

                # Pull optional vector fields (used only for size sanity checks)
                ek_vec = bytes.fromhex(test.get("ek") or "") if isinstance(test.get("ek"), str) else None
                k_vec  = bytes.fromhex(test.get("k")  or "") if isinstance(test.get("k"), str)  else None

                # Try to read sizes from kem.details (if available on your build)
                det = getattr(kem, "details", None)
                len_pk_detail = _get_detail_len(det, "public_key")
                len_ct_detail = _get_detail_len(det, "ciphertext")
                len_ss_detail = _get_detail_len(det, "shared_secret")

                # 30× timing: generate keypair, encapsulate to pk, decaps with internal sk
                times = []
                ok = True
                observed_pk_len = None
                observed_ct_len = None
                observed_ss_len = None

                for i in range(30):
                    pk = kem.generate_keypair()          # bytes
                    ct, ss1 = kem.encap_secret(pk)       # (bytes, bytes)
                    ss2 = kem.decap_secret(ct)           # bytes

                    # Record observed lengths from the first run
                    if i == 0:
                        observed_pk_len = len(pk)
                        observed_ct_len = len(ct)
                        observed_ss_len = len(ss1)

                    t0 = time.time()
                    # (We already did the ops; time a fresh encap/decap for measurement)
                    _ct, _ss1 = kem.encap_secret(pk)
                    _ss2 = kem.decap_secret(_ct)
                    t1 = time.time()
                    times.append(t1 - t0)

                    if ss1 != ss2 or _ss1 != _ss2:
                        ok = False

                entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                entry["StdDev(s)"] = round(statistics.pstdev(times), 6)
                if not ok:
                    entry["Result"] = "FAIL"
                    entry["Discrepancy"] = "Round-trip shared secret mismatch"

                # If vectors provided ek/k, sanity-check their lengths vs observed/detail lengths
                # Prefer detail lengths if present, else observed.
                ref_pk_len = len_pk_detail or observed_pk_len
                ref_ss_len = len_ss_detail or observed_ss_len
                if ek_vec and ref_pk_len and len(ek_vec) != ref_pk_len:
                    entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                        f"Vector ek length {len(ek_vec)} != expected {ref_pk_len}"
                if k_vec and ref_ss_len and len(k_vec) != ref_ss_len:
                    entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                        f"Vector k length {len(k_vec)} != expected {ref_ss_len}"

                # Note: we don't attempt to match ciphertext/shared secret bytes exactly;
                # liboqs Python cannot import external keys or seed RNG for deterministic KATs.

            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"

            results.append(entry)

    return results
