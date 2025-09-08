# test_hqc.py
import json, time, statistics, re
try:
    import oqs
except ImportError:
    oqs = None

from acvp_fetch import read_json, pick_one_rel
from oqs_compat import _first_working_kem

def _map_hqc_to_oqs(acvp_param: str):
    # ACVP: "HQC-128/192/256"; liboqs: "HQC-128"/"HQC-192"/"HQC-256"
    if not acvp_param:
        return []
    up = acvp_param.upper()
    cands = []
    m = re.search(r"HQC[-_]?(\d+)", up)
    if m:
        lvl = m.group(1)
        cands.append(f"HQC-{lvl}")
    cands += ["HQC-128", "HQC-192", "HQC-256", acvp_param]
    # dedupe
    seen, out = set(), []
    for x in cands:
        if x and x not in seen:
            seen.add(x); out.append(x)
    return out

def load_hqc_vectors():
    # Some ACVP-Server drops may not include HQC yet; handle gracefully
    try:
        return read_json(pick_one_rel("HQC*/**", "prompt"))
    except Exception:
        return {"testGroups": []}

def run_tests():
    results = []
    if not oqs:
        return results

    vectors = load_hqc_vectors()
    # If no groups found, still attempt a basic round-trip per common params
    groups = vectors.get("testGroups", [])
    if not groups:
        groups = [{"parameterSet": "HQC-128", "tests": [{"tcId": "basic-128"}]},
                  {"parameterSet": "HQC-192", "tests": [{"tcId": "basic-192"}]},
                  {"parameterSet": "HQC-256", "tests": [{"tcId": "basic-256"}]}]

    for group in groups:
        acvp_param = group.get("parameterSet")
        candidates = _map_hqc_to_oqs(acvp_param)
        alg, kem = _first_working_kem(oqs, candidates)

        for test in group.get("tests", []):
            tc_id = test.get("tcId")
            entry = {
                "Algorithm": "HQC",
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
                    times, ok = [], True
                    for _ in range(30):
                        pk = kem.generate_keypair()
                        t0 = time.time()
                        ct, ss1 = kem.encap_secret(pk)
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
            except Exception as ex:
                entry["Result"] = "FAIL"
                entry["Discrepancy"] = f"Exception: {ex}"
            results.append(entry)

    return results
