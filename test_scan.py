import requests

try:
    resp = requests.post(
        'http://127.0.0.1:8000/scan',
        json={'url': 'http://httpbin.org/get'},
        headers={'x-api-key': 'test-key-123'},
        timeout=10
    )
    print(f'Status: {resp.status_code}')
    result = resp.json()
    print(f"Job ID: {result.get('job_id')}")
    print(f"Type: {result.get('type')}")
    print('SUCCESS - SCAN SUBMITTED!')
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
