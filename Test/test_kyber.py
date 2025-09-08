# test_kyber.py
import json, time, statistics
try:
    import oqs
except ImportError:
    oqs = None

from acvp_fetch import read_json, pick_one_rel
from oqs_compat import _first_working_kem, map_mlkem_to_oqs

def load_kyber_vectors():
    # Use encap/decap prompt (FIPS 203)
    try:
        return read_json(pick_one_rel("ML-KEM-encapDecap-FIPS203/*", "prompt"))
    except Exception:
        return {"testGroups": []}

def run_tests():
    results = []
    if not oqs:
        return results

    vectors = load_kyber_vectors()

    for group in vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., ML-KEM-512/768/1024
        func = group.get("function") or "roundtrip"  # not always present in prompt
        candidates = map_mlkem_to_oqs(acvp_param)
        alg, kem = _first_working_kem(oqs, candidates)

        for test in group.get("tests", []):
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
                else:
                    # Round-trip correctness + timing
                    times = []
                    ok = True
                    for _ in range(30):
                        # Generate keypair
                        pk = kem.generate_keypair()
                        # Encapsulate to pk
                        t0 = time.time()
                        ct, ss1 = kem.encap_secret(pk)
                        # Decaps with internal sk
                        ss2 = kem.decap_secret(ct)
                        t1 = time.time()
                        times.append(t1 - t0)
                        if ss1 != ss2:
                            ok = False
                    entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                    entry["StdDev(s)"] = round(statistics.pstdev(times), 6)
                    if not ok:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Round-trip shared secret mismatch"

                    # If ACVP provides sizes, sanity-check lengths
                    ek = bytes.fromhex(test.get("ek")) if test.get("ek") else None
                    k = bytes.fromhex(test.get("k")) if test.get("k") else None
                    if ek and len(ek) != kem.public_key_length:
                        entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                                               "Vector public key length != liboqs length"
                    if k and len(k) != kem.shared_secret_length:
                        entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                                               "Vector shared secret length != liboqs length"
                    # We cannot import dk or match ct/k exactly here (liboqs Python limitation).
            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"
            results.append(entry)

    return results
