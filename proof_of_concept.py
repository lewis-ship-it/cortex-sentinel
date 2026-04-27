import os
import sys
sys.path.append(os.getcwd())
from scanner.validator import verify # Import your validation logic
from scanner.models import ScanResult

# A mock response from testphp.vulnweb.com that contains an SQL error
mock_response = """
<html>
<body>
    <h1>Error: You have an error in your SQL syntax; check the manual...</h1>
</body>
</html>
"""

def run_poc():
    print("[*] Running PoC Scanner...")
    # Manually call your validator logic
    result = verify("cat=1'", mock_response)
    
    if result.is_vulnerable:
        print("[+] SUCCESS: Vulnerability detected!")
        print(f"[+] Method: {result.method}")
        print(f"[+] Evidence: {result.evidence_snippet}")
    else:
        print("[-] FAILED: Vulnerability not detected.")
        print(f"[-] Reason: {result.reason}")

if __name__ == "__main__":
    run_poc()