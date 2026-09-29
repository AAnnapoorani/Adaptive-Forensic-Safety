import urllib.request, json

BASE = 'http://127.0.0.1:8000/api'

def post(path, data=None):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(BASE+path, data=body, headers={'Content-Type':'application/json'}, method='POST')
    return json.loads(urllib.request.urlopen(req, timeout=15).read())

def get(path):
    return json.loads(urllib.request.urlopen(BASE+path, timeout=15).read())

def run_e2e():
    print("=== JOCKY FULL PIPELINE E2E TEST ===")

    # 1 Polymorphic
    r = post('/jocky/mutate', {'script':'INVESTIGATE byovd_detection','iterations':4})
    unique = r["all_hashes_unique"]
    count  = r["variant_count"]
    print(f"1. Polymorphic Engine : {count} variants | all_unique={unique}")

    # 2 Encrypt
    enc = post('/jocky/encrypt', {'payload':{'threat':'RTCore64.sys','cve':'CVE-2019-16098'},'investigation_id':'INV-E2E-001'})
    print(f"2. Encryption         : {enc['blob_size_bytes']} bytes | {enc['encryption_scheme'][:40]}")

    # 3 Decrypt roundtrip
    dec = post('/jocky/decrypt', {'blob_hex': enc['blob_hex'], 'investigation_id':'INV-E2E-001'})
    print(f"3. Decryption OK      : {dec['payload']}")

    # 4 Drivers scan
    drv = get('/jocky/drivers')
    print(f"4. Drivers endpoint   : status={drv['status']} | items={drv['item_count']}")

    # 5 CDN routing
    rt = get('/jocky/routing')
    print(f"5. CDN routing        : mode={rt.get('active_mode', rt.get('routing_mode'))}")

    # 6 Create + execute BYOVD investigation (simulation)
    inv = post('/investigations', {'intent':'byovd_detection'})
    inv_id = inv["id"]
    print(f"6. Investigation      : {inv_id} created")
    result = post(f'/investigations/{inv_id}/execute?demo=true')
    status   = result["status"]
    rounds   = result["rounds_executed"]
    artifacts = result["artifacts_collected"]
    print(f"7. Execution          : status={status} | rounds={rounds} | artifacts={artifacts}")

    # 7 Check correlations
    corrs = get(f'/investigations/{inv_id}/correlations')
    rule_names = [c['rule_name'] for c in corrs]
    print(f"8. Correlations fired : {rule_names}")

    byovd_fired = 'BYOVD_VULNERABLE_DRIVER_LOADED' in rule_names
    memory_fired = 'IN_MEMORY_INJECTION_DETECTED' in rule_names
    print(f"   BYOVD rule         : {'FIRED' if byovd_fired else 'NOT FIRED'}")
    print(f"   Memory rule        : {'FIRED' if memory_fired else 'NOT FIRED'}")

    print()
    overall = status == 'COMPLETED' and unique and byovd_fired
    print("=== ALL TESTS PASSED ===" if overall else "=== SOME FAILURES ===")

if __name__ == '__main__':
    run_e2e()

