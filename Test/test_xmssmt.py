# file: test_xmssmt.py

import json
import time
import statistics

# Load XMSSMT test vectors (if available)
def load_xmssmt_vectors():
    try:
        import urllib.request
        siggen_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/XMSSMT/XMSSMT-SigGen.json"
        sigver_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/XMSSMT/XMSSMT-SigVer.json"
        with urllib.request.urlopen(siggen_url) as f1:
            siggen = json.loads(f1.read().decode('utf-8'))
        with urllib.request.urlopen(sigver_url) as f2:
            sigver = json.loads(f2.read().decode('utf-8'))
    except Exception:
        try:
            with open("xmssmt_siggen.json", "r") as f:
                siggen = json.load(f)
            with open("xmssmt_sigver.json", "r") as f:
                sigver = json.load(f)
        except FileNotFoundError:
            siggen = {"testGroups": []}
            sigver = {"testGroups": []}
    return siggen, sigver

def run_tests():
    results = []
    siggen_vectors, sigver_vectors = load_xmssmt_vectors()
    # XMSSMT SigGen
    for group in siggen_vectors.get("testGroups", []):
        param = group.get("parameterSet")  # e.g., "XMSSMT-SHA2_20d2_256"
        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            message = bytes.fromhex(test.get("message")) if test.get("message") else b""
            sig_expected = bytes.fromhex(test.get("signature")) if test.get("signature") else None
            result_entry = {
                "Algorithm": "XMSSMT",
                "Operation": "SigGen",
                "TestCaseID": tc_id,
                "Result": "SKIP",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": "XMSSMT not supported in liboqs"
            }
            # Placeholder: No implementation available, mark as skipped.
            results.append(result_entry)
    # XMSSMT SigVer
    for group in sigver_vectors.get("testGroups", []):
        param = group.get("parameterSet")
        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            result_entry = {
                "Algorithm": "XMSSMT",
                "Operation": "SigVer",
                "TestCaseID": tc_id,
                "Result": "SKIP",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": "XMSSMT not supported in liboqs"
            }
            results.append(result_entry)
    return results
