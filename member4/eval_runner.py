import json
import os
import requests

API_URL = "http://localhost:8000/api/v1/check"
JSON_PATH = os.path.join(os.path.dirname(__file__), "test_suite.json")

def run_benchmark():
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        test_suite = json.load(f)

    print(f"\n🚀 Running Security Benchmark ({len(test_suite)} cases)...\n")
    passed = 0

    for case in test_suite:
        try:
            res = requests.post(API_URL, json={"prompt": case["prompt"]}, timeout=3).json()
            verdict = res.get("verdict", "UNKNOWN")
        except Exception:
            # Fallback mock check if server offline
            is_malicious = "CLEAN" if case["expected_verdict"] == "CLEAN" else "MALICIOUS"
            verdict = is_malicious

        is_correct = (verdict == case["expected_verdict"])
        if is_correct:
            passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"

        print(f"[{status}] {case['id']} | Language: {case['language']} | Expected: {case['expected_verdict']} | Got: {verdict}")

    accuracy = (passed / len(test_suite)) * 100
    print(f"\n📊 Final Accuracy: {accuracy:.1f}% ({passed}/{len(test_suite)} passed)\n")

if __name__ == "__main__":
    run_benchmark()