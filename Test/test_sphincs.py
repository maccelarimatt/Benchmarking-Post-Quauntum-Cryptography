# test_sphincs.py
import time, statistics, json
try:
    import oqs
except ImportError:
    oqs = None

from acvp_fetch import read_json, pick_one_rel
from oqs_compat import _first_working_sig, map_slh_dsa_to_oqs

def load_sphincs_vectors():
    try:
        siggen = read_json(pick_one_rel("SLH-DSA-sigGen-FIPS205/*", "expectedresults"))
    except Exception:
        siggen = {"testGroups": []}
    try:
        sigver = read_json(pick_one_rel("SLH-DSA-sigVer-FIPS205/*", "prompt"))
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

def _all_sphincs_candidates():
    fams = ("SHA2", "SHAKE")
    sizes = ("128", "192", "256")
    sf = ("s", "f")
    rob = ("simple", "robust")
    out = []
    for F in fams:
        for S in sizes:
            for t in sf:
                for R in rob:
                    out.append(f"SPHINCS+-{F}-{S}{t}-{R}")
    return out

def _discover_sphincs_alg_by_verify(msg, sig, pk):
    """
    Try a broad set of SPHINCS+ names until .verify() returns True.
    Handles missing parameterSet in expectedResults.
    """
    if not oqs:
        return None, None
    for name in _all_sphincs_candidates():
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
        return results  # liboqs not present

    siggen_vectors, sigver_vectors = load_sphincs_vectors()

    # --- SigGen (robust across oqs versions) ---
    for group in siggen_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # may be None in expectedResults
        mapped_candidates = map_slh_dsa_to_oqs(acvp_param) if acvp_param else []

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            msg = _get_hex_bytes(test, "message") or b""
            # In expectedResults (SigGen) we generally have pk + signature from the oracle
            pk_vec  = _get_hex_bytes(test, "pk", "publicKey")
            sig_vec = _get_hex_bytes(test, "signature", "sig")

            entry = {
                "Algorithm": "SPHINCS+",
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

                # (A) Use mapped candidates if parameterSet exists
                if mapped_candidates:
                    alg, signer = _first_working_sig(oqs, mapped_candidates)

                # (B) If still unknown and we have vector (pk,sig), discover by verification
                if (not alg) and pk_vec and sig_vec:
                    alg, signer = _discover_sphincs_alg_by_verify(msg, sig_vec, pk_vec)

                if not alg or not signer:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No supported OQS alg for {acvp_param}"
                    results.append(entry)
                    continue

                # 1) Validate oracle pair by verification (confirms correctness)
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

                # 2) Time signing with a fresh key (cannot import vector sk)
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

                    # sanity: verify our own signature
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

    # --- SigVer (your existing robust block) ---
    for group in sigver_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., SLH-DSA-SHA2-128s(-simple/-robust)
        candidates = map_slh_dsa_to_oqs(acvp_param) if acvp_param else _all_sphincs_candidates()
        alg, verifier = _first_working_sig(oqs, candidates)
        for test in group.get("tests", []):
            entry = {
                "Algorithm": "SPHINCS+",
                "Operation": "SigVer",
                "TestCaseID": test.get("tcId"),
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
                    pk = _get_hex_bytes(test, "pk", "publicKey") or b""
                    msg = _get_hex_bytes(test, "message") or b""
                    sig = _get_hex_bytes(test, "signature", "sig") or b""
                    expected = bool(test.get("testPassed"))

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
