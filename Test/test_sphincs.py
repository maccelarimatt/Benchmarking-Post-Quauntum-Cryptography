# file: test_sphincs.py

# Load SPHINCS+ test vectors
# def load_sphincs_vectors():
#     try:
#         import urllib.request
#         siggen_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/SLH-DSA/SLH-DSA-SigGen.json"
#         sigver_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/SLH-DSA/SLH-DSA-SigVer.json"
#         with urllib.request.urlopen(siggen_url) as f1:
#             siggen = json.loads(f1.read().decode('utf-8'))
#         with urllib.request.urlopen(sigver_url) as f2:
#             sigver = json.loads(f2.read().decode('utf-8'))
#     except Exception:
#         try:
#             with open("sphincs_siggen.json", "r") as f:
#                 siggen = json.load(f)
#             with open("sphincs_sigver.json", "r") as f:
#                 sigver = json.load(f)
#         except FileNotFoundError:
#             siggen = {"testGroups": []}
#             sigver = {"testGroups": []}
#     return siggen, sigver

# test_sphincs.py
from acvp_fetch import read_json, pick_one_rel

def load_sphincs_vectors():
    siggen = read_json(pick_one_rel("SLH-DSA-sigGen-FIPS205/*", "expectedresults"))
    sigver = read_json(pick_one_rel("SLH-DSA-sigVer-FIPS205/*", "prompt"))
    return siggen, sigver

# test_sphincs.py
import time, statistics, json
try:
    import oqs
except ImportError:
    oqs = None

from oqs_compat import _first_working_sig, map_slh_dsa_to_oqs

def run_tests():
    results = []
    if not oqs:
        # mark whole file as SKIP gracefully
        return results

    siggen_vectors, sigver_vectors = load_sphincs_vectors()
    
    # --- SigGen (robust across oqs versions) ---
    for group in siggen_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., SLH-DSA-SHA2-128s(-simple/-robust)
        candidates = map_slh_dsa_to_oqs(acvp_param)
        alg, signer = _first_working_sig(oqs, candidates)   # signer object does sign() and verify()

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            msg = bytes.fromhex(test.get("message") or "")
            # In expectedResults (SigGen) we typically get pk + signature from the oracle
            pk_vec = bytes.fromhex(test.get("pk") or "") if "pk" in test else None
            sig_vec = bytes.fromhex(test.get("signature") or "") if "signature" in test else None

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
                if not alg:
                    entry["Result"] = "SKIP"
                    entry["Discrepancy"] = f"No supported OQS alg for {acvp_param}"
                    results.append(entry)
                    continue

                # 1) Validate the ACVP-provided (pk, signature) pair by verifying it.
                #    This confirms functional correctness for the SigGen vector.
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
                    # If vector doesn't include pk/signature, we can't validate deterministically.
                    entry["Discrepancy"] = "No pk/signature in expectedResults; timing-only run"

                # 2) Time actual signing (with a fresh keypair; we cannot import vector sk in liboqs).
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

                    # sanity: ensure our produced signature verifies under our runtime pk
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


    # --- SigVer example patch (do similarly for SigGen) ---
    for group in sigver_vectors.get("testGroups", []):
        acvp_param = group.get("parameterSet")  # e.g., SLH-DSA-SHA2-128s(-simple/-robust)
        candidates = map_slh_dsa_to_oqs(acvp_param)
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
                    pk = bytes.fromhex(test.get("pk") or "")
                    msg = bytes.fromhex(test.get("message") or "")
                    sig = bytes.fromhex(test.get("signature") or "")
                    expected = bool(test.get("testPassed"))

                    # time 30x
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

# def run_tests():
#     results = []
#     siggen_vectors, sigver_vectors = load_sphincs_vectors()
#     # SPHINCS+ SigGen
#     for group in siggen_vectors.get("testGroups", []):
#         param = group.get("parameterSet")  # e.g., "SLH_DSA_SHA2_128F"
#         for test in group.get("tests", []):
#             tc_id = test.get("tcId")
#             message = bytes.fromhex(test.get("message")) if test.get("message") else b""
#             sig_expected = bytes.fromhex(test.get("signature")) if test.get("signature") else None
#             result_entry = {
#                 "Algorithm": "SPHINCS+",
#                 "Operation": "SigGen",
#                 "TestCaseID": tc_id,
#                 "Result": "PASS",
#                 "AvgTime(s)": 0.0,
#                 "StdDev(s)": 0.0,
#                 "Discrepancy": ""
#             }
#             try:
#                 if oqs and param in oqs.get_enabled_sigs():
#                     signer = oqs.Signature(param)
#                     pk = signer.generate_keypair()
#                     run_times = []
#                     signature = None
#                     for i in range(30):
#                         start = time.time()
#                         sig_bytes = signer.sign(message)
#                         end = time.time()
#                         run_times.append(end - start)
#                         if i == 0:
#                             signature = sig_bytes
#                     result_entry["AvgTime(s)"] = round(statistics.mean(run_times), 6)
#                     result_entry["StdDev(s)"] = round(statistics.pstdev(run_times), 6)
#                     if sig_expected:
#                         if signature != sig_expected:
#                             result_entry["Result"] = "FAIL"
#                             result_entry["Discrepancy"] = "Signature mismatch"
#                     if not signer.verify(message, signature, pk):
#                         result_entry["Result"] = "FAIL"
#                         result_entry["Discrepancy"] = "Signature invalid"
#                 else:
#                     result_entry["Result"] = "SKIP"
#                     result_entry["Discrepancy"] = "LibOQS not available for SPHINCS+"
#             except Exception as ex:
#                 result_entry["Result"] = "FAIL"
#                 result_entry["Discrepancy"] = f"Exception: {ex}"
#             results.append(result_entry)
#     # SPHINCS+ SigVer
#     for group in sigver_vectors.get("testGroups", []):
#         param = group.get("parameterSet")
#         for test in group.get("tests", []):
#             tc_id = test.get("tcId")
#             pk = bytes.fromhex(test.get("pk")) if test.get("pk") else None
#             message = bytes.fromhex(test.get("message")) if test.get("message") else b""
#             signature = bytes.fromhex(test.get("signature")) if test.get("signature") else None
#             expected_result = test.get("testPassed")
#             result_entry = {
#                 "Algorithm": "SPHINCS+",
#                 "Operation": "SigVer",
#                 "TestCaseID": tc_id,
#                 "Result": "PASS",
#                 "AvgTime(s)": 0.0,
#                 "StdDev(s)": 0.0,
#                 "Discrepancy": ""
#             }
#             try:
#                 if oqs and param in oqs.get_enabled_sigs():
#                     verifier = oqs.Signature(param)
#                     run_times = []
#                     verified = False
#                     for i in range(30):
#                         start = time.time()
#                         try:
#                             verified = verifier.verify(message, signature, pk)
#                         except Exception:
#                             verified = False
#                         end = time.time()
#                         run_times.append(end - start)
#                     result_entry["AvgTime(s)"] = round(statistics.mean(run_times), 6)
#                     result_entry["StdDev(s)"] = round(statistics.pstdev(run_times), 6)
#                     if verified != expected_result:
#                         result_entry["Result"] = "FAIL"
#                         result_entry["Discrepancy"] = f"Verification result mismatch (expected {expected_result})"
#                 else:
#                     result_entry["Result"] = "SKIP"
#                     result_entry["Discrepancy"] = "LibOQS not available for SPHINCS+"
#             except Exception as ex:
#                 result_entry["Result"] = "FAIL"
#                 result_entry["Discrepancy"] = f"Exception: {ex}"
#             results.append(result_entry)
#     return results
