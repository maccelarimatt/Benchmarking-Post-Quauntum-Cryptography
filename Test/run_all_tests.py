# file: run_all_tests.py

import csv
import datetime
import os

# Import individual test modules for each algorithm
import test_rsa_oaep
import test_rsa_pss
import test_kyber
import test_hqc
import test_dilithium
import test_falcon
import test_sphincs
import test_xmssmt

def run_all_tests():
    """Run all cryptographic algorithm tests and log results to CSV."""
    results = []
    # Each test module has a run_tests() that returns a list of result dicts
    results += test_rsa_oaep.run_tests()
    #results += test_rsa_pss.run_tests()
    results += test_kyber.run_tests()
    results += test_hqc.run_tests()
    results += test_dilithium.run_tests()
    results += test_falcon.run_tests()
    results += test_sphincs.run_tests()
    results += test_xmssmt.run_tests()
    # Define CSV file and headers
    csv_file = "test_results.csv"
    headers = ["Algorithm", "Operation", "TestCaseID", "Result", 
               "AvgTime(s)", "StdDev(s)", "Discrepancy"]
    # Write results to CSV
    with open(csv_file, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for res in results:
            writer.writerow(res)
    print(f"All tests completed on {datetime.datetime.now().isoformat()}")
    print(f"Results saved to {csv_file} in {os.getcwd()}")

if __name__ == "__main__":
    run_all_tests()
