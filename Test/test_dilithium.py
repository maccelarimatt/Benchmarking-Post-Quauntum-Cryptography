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

def _get_hex_bytes(obj, *keys):
    for k in keys:
        if k in obj and isinstance(obj[k], str):
            try:
                return bytes.fromhex(obj[k])
            except Exception:
                pass
    return None

def _discover_sig_alg_by_verify(msg, sig, pk):
    """
    Try a set of likely Dilithium names until .verify() returns True.
    Works even if group['parameterSet'] is missing.
    """
    if not oqs:
        return None, None
    candidates = [
        # canonical liboqs names
        "Dilithium2", "Dilithium3", "Dilithium5",
        # ACVP-style names (some liboqs builds may accept these aliases)
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    ]
    for name in candidates:
        try:
            s = oqs.Signature(name)
            if s.verify(msg, sig, pk):
                return name, s
        except Exception:
            continue
    return None, None

def run_tests():
    results = []
    if not oqs:
        return results  # no liboqs: nothing to run

    siggen_vectors, sigver_vectors = load_dilithium_vectors()

    # -------- SigGen --------
    for group in siggen_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # may be None in expectedResults
        # We'll try mapping first; if that fails, we'll discover via (pk,sig) verification.
        mapped_candidates = map_mldsa_to_oqs(acvp_param) if acvp_param else []

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            msg = _get_hex_bytes(test, "message") or b""

            # expectedResults usually carry pk + signature from the ACVP oracle
            pk_vec  = _get_hex_bytes(test, "pk", "publicKey")
            sig_vec = _get_hex_bytes(test, "signature", "sig")

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
                alg = None
                signer = None

                # (A) Try mapped candidates if we have a parameterSet
                if mapped_candidates:
                    alg, signer = _first_working_sig(oqs, mapped_candidates)

                # (B) If still unknown and we have (pk,sig), auto-discover by verifying
                if (not alg) and pk_vec and sig_vec:
                    alg, signer = _discover_sig_alg_by_verify(msg, sig_vec, pk_vec)

                if not alg or not signer:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No supported OQS alg for {acvp_param}"
                    results.append(entry)
                    continue

                # 1) Validate oracle pair, if present
                if pk_vec and sig_vec:
                    try:
                        ok = signer.verify(msg, sig_vec, pk_vec)
                        if not ok:
                            entry["Result"] = "FAIL"
                            entry["Discrepancy"] = "Vector signature does not verify with vector public key"
                    except Exception as verr:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = f"Verification exception on vector signature: {verr}"
                else:
                    entry["Discrepancy"] = "No pk/signature in expectedResults; timing-only run"

                # 2) Time actual signing (fresh keypair; cannot import vector sk in liboqs)
                times = []
                try:
                    pk_runtime = signer.generate_keypair()
                    first_sig = None
                    for _ in range(30):
                        t0 = time.time()
                        s = signer.sign(msg)
                        t1 = time.time()
                        times.append(t1 - t0)
                        if first_sig is None:
                            first_sig = s
                    entry["AvgTime(s)"] = round(statistics.mean(times), 6)
                    entry["StdDev(s)"] = round(statistics.pstdev(times), 6)

                    # sanity verify our own signature
                    try:
                        if not signer.verify(msg, first_sig, pk_runtime):
                            entry["Result"] = "FAIL"
                            entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                                                   "Self-sign sanity verify failed"
                    except Exception as verr2:
                        entry["Result"] = "FAIL"
                        entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                                               f"Self-sign verification exception: {verr2}"
                except Exception as sign_ex:
                    entry["Result"] = "FAIL"
                    entry["Discrepancy"] = (entry["Discrepancy"] + "; " if entry["Discrepancy"] else "") + \
                                           f"Signing exception: {sign_ex}"

            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"

            results.append(entry)

    # -------- SigVer --------
    for group in sigver_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")
        candidates = map_mldsa_to_oqs(acvp_param) if acvp_param else ["Dilithium2","Dilithium3","Dilithium5"]
        alg, verifier = _first_working_sig(oqs, candidates)

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            pk = _get_hex_bytes(test, "pk", "publicKey") or b""
            msg = _get_hex_bytes(test, "message") or b""
            sig = _get_hex_bytes(test, "signature", "sig") or b""
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
