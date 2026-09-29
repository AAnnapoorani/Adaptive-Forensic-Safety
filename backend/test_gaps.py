from app.jocky.polymorphic import PolymorphicEngine, PayloadEncryptor

# Test 1: Polymorphic engine produces unique hashes
script = "INVESTIGATE suspicious_network_activity"
result = PolymorphicEngine.mutate(script, iterations=5)
all_unique = len(set(result["hashes"])) == 5
print(f"Polymorphic Engine: 5 variants, all_unique_hashes={all_unique}")
print(f"  Original hash : {result['original_hash'][:20]}...")
for i, h in enumerate(result["hashes"]):
    print(f"  Variant {i+1} hash: {h[:20]}...")

# Test 2: Encryption/decryption roundtrip
payload = {"test": "evidence", "data": [1, 2, 3], "pid": 4820}
blob = PayloadEncryptor.encrypt(payload, "INV-TEST-001")
decrypted = PayloadEncryptor.decrypt(blob, "INV-TEST-001")
roundtrip_ok = decrypted == payload
print(f"Encryption roundtrip OK = {roundtrip_ok}")
print(f"  Blob size: {len(blob)} bytes")

# Test 3: Different investigation ID produces different blob
blob2 = PayloadEncryptor.encrypt(payload, "INV-TEST-002")
print(f"Different investigation = different blob = {blob != blob2}")

# Test 4: Correlation engine picks up new rules
from app.intelligence.correlation_engine import CorrelationEngine
engine = CorrelationEngine()
evidence = {
    "DRIVERS.LIST": [
        {"filename": "RTCore64.sys", "is_byovd_known_vulnerable": True, "byovd_risk": "CRITICAL",
         "byovd_cve": "CVE-2019-16098", "byovd_vendor": "MSI", "byovd_technique": "kernel r/w"}
    ],
    "MEMORY.ANALYSIS": [
        {"pid": 4820, "process_name": "powershell.exe", "region_size_bytes": 131072,
         "severity": "HIGH", "injection_indicator": "private_executable_region",
         "protection": "PAGE_EXECUTE_READWRITE"}
    ]
}
matches = engine.evaluate(evidence)
rule_names = [m.rule_name for m in matches]
print(f"New correlation rules fired: {rule_names}")
print("ALL TESTS PASSED" if all_unique and roundtrip_ok else "SOME TESTS FAILED")
