import urllib.request
import json

base_url = 'http://127.0.0.1:8000/api'
intents = [
    'suspicious_network_activity',
    'possible_malware_execution',
    'system_compromise'
]

def verify_all():
    for intent in intents:
        script = f'INVESTIGATE {intent}'
        print(f'=== Testing intent: {intent} ===')
        
        # 1. Preview
        req = urllib.request.Request(
            f'{base_url}/investigations/preview',
            data=json.dumps({'script': script}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as resp:
            prev = json.loads(resp.read().decode())
            intent_name = prev['intent']
            ops = prev['initial_operations']
            dag_nodes = len(prev['evidence_graph']['nodes'])
            print(f'  [PREVIEW PASS] Intent: {intent_name}, Ops: {ops}, DAG Nodes: {dag_nodes}')
            assert prev['intent'] == intent
            assert len(prev['initial_operations']) > 0

        # 2. Create
        req = urllib.request.Request(
            f'{base_url}/investigations',
            data=json.dumps({'intent': intent, 'script': script}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as resp:
            inv = json.loads(resp.read().decode())
            inv_id = inv['id']
            print(f'  [CREATE PASS] ID: {inv_id}')

        # 3. Execute (demo=True)
        req = urllib.request.Request(
            f'{base_url}/investigations/{inv_id}/execute?demo=true',
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode())
            st = res['status']
            rounds = res['rounds_executed']
            arts = res['artifacts_collected']
            integ = res['integrity_verified']
            print(f'  [EXECUTE PASS] Status: {st}, Rounds: {rounds}, Artifacts: {arts}, Integrity: {integ}')
            assert res['status'] in ('COMPLETED', 'CONVERGED')
            assert res['integrity_verified'] is True

    print('\n>>> ALL 3 MAIN INTENTS VERIFIED SUCCESSFULLY! <<<')

if __name__ == '__main__':
    verify_all()
