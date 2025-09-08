# file: test_rsa_pss.py

import json
import time
import statistics
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Helper: load RSA-PSS test vectors from NIST ACVP JSON (SigGen and SigVer)
# def load_rsa_pss_vectors():
#     """
#     Load RSA PSS test cases from NIST ACVP JSON files.
#     Returns separate lists for SigGen and SigVer cases.
#     """
#     try:
#         import urllib.request
#         # URLs for RSA Signature Generation and Verification test vector JSON (FIPS186-5 RSA-PSS)
#         siggen_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/RSA-SigGen-FIPS186-5/rsa_siggen_pss.json"
#         sigver_url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/RSA-SigVer-FIPS186-5/rsa_sigver_pss.json"
#         with urllib.request.urlopen(siggen_url) as f1:
#             siggen_data = f1.read().decode('utf-8')
#         with urllib.request.urlopen(sigver_url) as f2:
#             sigver_data = f2.read().decode('utf-8')
#         siggen_vectors = json.loads(siggen_data)
#         sigver_vectors = json.loads(sigver_data)
#     except Exception:
#         # Fallback to local files if URL fetch fails
#         with open("rsa_pss_siggen.json", "r") as f:
#             siggen_vectors = json.load(f)
#         with open("rsa_pss_sigver.json", "r") as f:
#             sigver_vectors = json.load(f)
#     return siggen_vectors, sigver_vectors

# test_rsa_pss.py
from acvp_fetch import read_json, pick_one_rel

def load_rsa_pss_vectors():
    siggen = read_json(pick_one_rel("RSA-SigGen-FIPS186-5/*", "pss", "expectedresults"))
    sigver = read_json(pick_one_rel("RSA-SigVer-FIPS186-5/*", "pss", "prompt"))
    return siggen, sigver

# --- digest mapping for ACVP -> cryptography ---
from cryptography.hazmat.primitives import hashes

def _hash_from_acvp(name: str):
    """
    Map ACVP 'hashAlg' strings to cryptography.hazmat.primitives.hashes classes.
    Examples:
      'SHA-1' -> hashes.SHA1
      'SHA2-256' -> hashes.SHA256
      'SHA2-512/224' -> hashes.SHA512_224
      'SHA3-256' -> hashes.SHA3_256
    """
    n = (name or "").strip().upper().replace(" ", "")
    table = {
        "SHA-1": hashes.SHA1,
        "SHA1": hashes.SHA1,

        "SHA2-224": hashes.SHA224,
        "SHA-224": hashes.SHA224,
        "SHA2-256": hashes.SHA256,
        "SHA-256": hashes.SHA256,
        "SHA2-384": hashes.SHA384,
        "SHA-384": hashes.SHA384,
        "SHA2-512": hashes.SHA512,
        "SHA-512": hashes.SHA512,

        # FIPS 180-4 truncated variants
        "SHA2-512/224": hashes.SHA512_224,
        "SHA-512/224": hashes.SHA512_224,
        "SHA2-512/256": hashes.SHA512_256,
        "SHA-512/256": hashes.SHA512_256,

        # SHA-3 family
        "SHA3-224": hashes.SHA3_224,
        "SHA3-256": hashes.SHA3_256,
        "SHA3-384": hashes.SHA3_384,
        "SHA3-512": hashes.SHA3_512,
    }
    # normalize keys like 'SHA2-256' or 'SHA-256'
    if n in table:
        return table[n]
    # last-resort: strip hyphens/slashes and try again
    n2 = n.replace("-", "").replace("/", "")
    for k, v in table.items():
        if k.replace("-", "").replace("/", "") == n2:
            return v
    raise ValueError(f"Unsupported/unknown hashAlg from ACVP: {name!r}")


def run_tests():
    """Run RSA-PSS signing and verification tests and return results list."""
    results = []
    siggen_vectors, sigver_vectors = load_rsa_pss_vectors()
    # Process signature generation test groups
    for group in siggen_vectors.get("testGroups", []):
        mod = group.get("modulo")       # key modulus size in bits
        hash_alg = group.get("hashAlg") # e.g., "SHA2-256"
        salt_len = group.get("saltLen") # salt length in bytes
        tests = group.get("tests", [])
        # Set hash algorithm
        hash_cls = _hash_from_acvp(hash_alg)
        # Iterate test cases for signature generation
        for test in tests:
            tc_id = test.get("tcId")
            message_hex = test.get("message")
            # RSA key components (n, e, and private key info)
            n_hex = test.get("n")
            e_hex = test.get("e")
            d_hex = test.get("d") if test.get("d") else None  # ACVP GDT may require generating key; here assume provided
            sig_expected_hex = test.get("signature")  # expected signature (if provided)
            result_entry = {
                "Algorithm": "RSA-PSS",
                "Operation": "SigGen",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }
            try:
                # Construct RSA key from given components
                n = int(n_hex, 16)
                e = int(e_hex, 16)
                if d_hex:
                    d = int(d_hex, 16)
                    # If p, q provided, use them for key construction; otherwise, fallback
                    p = int(test.get("p"), 16) if test.get("p") else None
                    q = int(test.get("q"), 16) if test.get("q") else None
                    if p and q:
                        dmp1 = int(test.get("dmp1"), 16) if test.get("dmp1") else rsa.rsa_crt_dmp1(d, p)
                        dmq1 = int(test.get("dmq1"), 16) if test.get("dmq1") else rsa.rsa_crt_dmq1(d, q)
                        iqmp = int(test.get("iqmp"), 16) if test.get("iqmp") else rsa.rsa_crt_iqmp(p, q)
                        private_numbers = rsa.RSAPrivateNumbers(
                            p, q, d, dmp1, dmq1, iqmp, 
                            public_numbers=rsa.RSAPublicNumbers(e, n)
                        )
                        private_key = private_numbers.private_key()
                    else:
                        # Without p and q, use public numbers only (cannot sign without d fully)
                        private_key = rsa.RSAPrivateNumbers(
                            p=2, q=2, d=d, dmp1=0, dmq1=0, iqmp=0,
                            public_numbers=rsa.RSAPublicNumbers(e, n)
                        ).private_key()
                else:
                    # If no private exponent, skip this test (can't sign without d)
                    result_entry["Result"] = "SKIP"
                    result_entry["Discrepancy"] = "No private key provided for SigGen"
                    results.append(result_entry)
                    continue
                message = bytes.fromhex(message_hex)
                # Set up PSS padding with specified salt length
                pss_padding = padding.PSS(
                    mgf=padding.MGF1(hash_cls()),
                    salt_length=salt_len if (isinstance(salt_len, int) and salt_len >= 0) else padding.PSS.MAX_LENGTH
                )
                # Time signature generation 30 times
                run_times = []
                signatures = []
                for i in range(30):
                    start = time.time()
                    sig_bytes = private_key.sign(message, pss_padding, hash_algo())
                    end = time.time()
                    run_times.append(end - start)
                    signatures.append(sig_bytes)
                avg_time = statistics.mean(run_times)
                std_time = statistics.pstdev(run_times)
                result_entry["AvgTime(s)"] = round(avg_time, 6)
                result_entry["StdDev(s)"] = round(std_time, 6)
                # If an expected signature is provided in test vector (for KAT), compare bit-for-bit
                if sig_expected_hex:
                    expected_sig = bytes.fromhex(sig_expected_hex)
                    # Use the first signature generated (all should be equally valid, but PSS is random unless salt controlled)
                    if signatures[0] != expected_sig:
                        # If signatures don't match expected exactly, flag discrepancy
                        result_entry["Result"] = "FAIL"
                        result_entry["Discrepancy"] = "Signature mismatch"
                else:
                    # If no expected signature given (due to randomness), verify our signature against public key
                    public_key = private_key.public_key()
                    # Verify the last signature to ensure it is valid
                    try:
                        public_key.verify(signatures[-1], message, pss_padding, hash_algo())
                    except Exception as verr:
                        result_entry["Result"] = "FAIL"
                        result_entry["Discrepancy"] = "Signature verification failed"
            except Exception as ex:
                result_entry["Result"] = "FAIL"
                result_entry["Discrepancy"] = f"Exception: {ex}"
            results.append(result_entry)
    # Process signature verification test groups
    for group in sigver_vectors.get("testGroups", []):
        mod = group.get("modulo")
        hash_alg = group.get("hashAlg")
        salt_len = group.get("saltLen")
        tests = group.get("tests", [])
        hash_algo = getattr(hashes, hash_alg.replace('-', ''))
        for test in tests:
            tc_id = test.get("tcId")
            message_hex = test.get("message")
            sig_hex = test.get("signature")
            n_hex = test.get("n")
            e_hex = test.get("e")
            test_passed_expected = test.get("testPassed")  # expected boolean result
            result_entry = {
                "Algorithm": "RSA-PSS",
                "Operation": "SigVer",
                "TestCaseID": tc_id,
                "Result": "PASS",
                "AvgTime(s)": 0.0,
                "StdDev(s)": 0.0,
                "Discrepancy": ""
            }
            try:
                n = int(n_hex, 16)
                e = int(e_hex, 16)
                public_key = rsa.RSAPublicNumbers(e, n).public_key()
                message = bytes.fromhex(message_hex)
                signature = bytes.fromhex(sig_hex)
                pss_padding = padding.PSS(
                    mgf=padding.MGF1(hash_cls()),
                    salt_length=salt_len if (isinstance(salt_len, int) and salt_len >= 0) else padding.PSS.MAX_LENGTH
                )
                # Time signature verification 30 times
                run_times = []
                verification_ok = True
                for i in range(30):
                    start = time.time()
                    try:
                        public_key.verify(signature, message, pss_padding, hash_algo())
                        verified = True
                    except Exception:
                        verified = False
                    end = time.time()
                    run_times.append(end - start)
                    # Ensure verification result is consistent every iteration
                    if verified is False:
                        verification_ok = False
                avg_time = statistics.mean(run_times)
                std_time = statistics.pstdev(run_times)
                result_entry["AvgTime(s)"] = round(avg_time, 6)
                result_entry["StdDev(s)"] = round(std_time, 6)
                # Compare verification result with expected testPassed
                if verification_ok != bool(test_passed_expected):
                    result_entry["Result"] = "FAIL"
                    result_entry["Discrepancy"] = f"Verification result mismatch (expected {test_passed_expected})"
            except Exception as ex:
                result_entry["Result"] = "FAIL"
                result_entry["Discrepancy"] = f"Exception: {ex}"
            results.append(result_entry)
    return results
