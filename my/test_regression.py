from __future__ import annotations
import os
import sys
from pathlib import Path
from trace_engine import analyze_email

def run_tests():
    sample_dir = Path(__file__).resolve().parent / "samples"
    tests = [
        ("01_legit_gmail.eml", {"min_score": 0, "max_score": 25, "verdict": "low"}),
        ("02_tor_spoofed_phish.eml", {"min_score": 60, "max_score": 100, "verdict": "high"}),
        ("03_forged_deep_hop_injection.eml", {"min_score": 60, "max_score": 100, "verdict": "high"}),
        ("04_esmtpsa_device_leak.eml", {"min_score": 0, "max_score": 30, "verdict": "low"}),
    ]

    print("=" * 70)
    print("RUNNING SIH26106 TRACE ENGINE REGRESSION SUITE (Offline Mode)")
    print("=" * 70)
    passed = 0

    for filename, criteria in tests:
        filepath = sample_dir / filename
        if not filepath.exists():
            print(f"[-] SKIPPED: {filename} (not found)")
            continue
        
        with open(filepath, "rb") as f:
            raw = f.read()

        res = analyze_email(raw, use_online_geo=False)
        score = res["risk"]["trace_risk_score"]
        level = res["risk"]["trace_risk_level"]
        origin = res["origin"]["probable_source_ip"]
        basis = res["origin"]["origin_basis"]
        sender_loc = res["sender_location_estimate"]["primary_estimate"]["country"]
        conf = res["sender_location_estimate"]["primary_estimate"]["confidence"]

        ok = (criteria["min_score"] <= score <= criteria["max_score"])
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1

        print(f"[{status}] {filename}")
        print(f"       Trace Score : {score}/100 ({level.upper()}) [Expected: {criteria['min_score']}-{criteria['max_score']}]")
        print(f"       Origin IP   : {origin} (Basis: {basis})")
        print(f"       Sender Loc  : {sender_loc} (Confidence: {conf})")
        print(f"       Reasons     : {len(res['risk']['reasons'])} reasons generated")
        if not ok:
            for r in res['risk']['reasons']:
                print(f"         * {r}")
        print("-" * 70)

    print(f"\nResult: {passed}/{len(tests)} tests passed.")
    assert passed == len(tests), f"Regression failures: {len(tests) - passed}"

if __name__ == "__main__":
    run_tests()
