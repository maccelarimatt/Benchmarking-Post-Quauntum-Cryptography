# test_dilithium.py
import json, time, statistics
try:
    import oqs
except ImportError:
    oqs = None

from acvp_fetch import read_json, pick_one_rel
from oqs_compat import _first_working_sig, map_mldsa_to_oqs

def load_dilithium_vectors():
    # ML-DSA (FIPS 204) — use expectedResults for SigGen, prompt for SigVer
    try:
        siggen = read_json(pick_one_rel("ML-DSA-sigGen-FIPS204/*", "expectedresults"))
    except Exception:
        siggen = {"testGroups": []}
    try:
        sigver = read_json(pick_one_rel("ML-DSA-sigVer-FIPS204/*", "prompt"))
    except Exception:
        sigver = {"testGroups": []}
    return siggen, sigver

def run_tests():
    results = []
    if not oqs:
        return results  # no liboqs: nothing to run

    siggen_vectors, sigver_vectors = load_dilithium_vectors()

    # -------- SigGen --------
    for group in siggen_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., ML-DSA-65
        candidates = map_mldsa_to_oqs(acvp_param)
        alg, signer = _first_working_sig(oqs, candidates)

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            msg = bytes.fromhex(test.get("message") or "")
            sig_expected = bytes.fromhex(test.get("signature")) if test.get("signature") else None
            entry = {
                "Algorithm": "Dilithium",
                "Operation": "SigGen",
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
                    pk = signer.generate_keypair()
                    times, first_sig = [], None
                    for i in range(30):
                        t0 = time.time()
                        sig = signer.sign(msg)
                        t1 = time.time()
                        times.append(t1 - t0)
                        if i == 0:
                            first_sig = sig
                    entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                    entry["StdDev(s)"] = round(statistics.pstdev(times), 6)

                    # If deterministic KAT is provided, compare exact bytes
                    if sig_expected and first_sig != sig_expected:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Signature mismatch (KAT)"
                    # Always verify correctness
                    if not signer.verify(msg, first_sig, pk):
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = "Signature invalid (verification failed)"
            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"
            results.append(entry)

    # -------- SigVer --------
    for group in sigver_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")
        candidates = map_mldsa_to_oqs(acvp_param)
        alg, verifier = _first_working_sig(oqs, candidates)

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            pk = bytes.fromhex(test.get("pk") or "")
            msg = bytes.fromhex(test.get("message") or "")
            sig = bytes.fromhex(test.get("signature") or "")
            expected = bool(test.get("testPassed"))
            entry = {
                "Algorithm": "Dilithium",
                "Operation": "SigVer",
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
                    times, ok = [], False
                    for _ in range(30):
                        t0 = time.time()
                        try:
                            ok = verifier.verify(msg, sig, pk)
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
