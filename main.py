import time
from urllib.parse import urlparse
from scanner.crawler import Crawler
from scanner.safety import SafetyAuditor
from scanner.active_engine import ActiveScanner
from core.database import DatabaseManager

class CortexSentinel:
    def __init__(self, target_url):
        self.target_url = target_url
        self.db = DatabaseManager()
        self.active_engine = ActiveScanner()
        
    def run_full_scan(self):
        """
        Executes the full pipeline: Discovery -> Passive -> Active -> Report
        """
        print(f"\n[+] Starting Cortex Sentinel Audit: {self.target_url}")
        
        # 1. Endpoint Discovery (Crawler)
        # Capabilities: Automated website crawling 
        spider = Crawler(self.target_url)
        print("[*] Phase 1: Discovering endpoints...")
        endpoints = spider.crawl()
        print(f"[!] Discovery Complete. Found {len(endpoints)} unique targets.")

        for url in endpoints:
            print(f"\n[*] Auditing: {url}")
            
            # 2. Passive Analysis (Headers & SSL)
            # Capabilities: Passive vulnerability detection 
            auditor = SafetyAuditor(url)
            header_results = auditor.audit_headers()
            ssl_results = auditor.check_ssl()
            
            # 3. Active Scanning (Smart Payload Injection)
            # Capabilities: Active vulnerability scanning (SQLi) [cite: 5, 7]
            # Uses verification loops to reduce false positives 
            vulnerabilities = self.active_engine.scan_url(url)
            
            # 4. Save to Database (Cost Optimization)
            # Cache results and avoid re-scanning unchanged assets 
            print(f"[*] Saving results to Cortex Sentinel database...")
            self.db.save_scan_result(
                url=url,
                headers=header_results,
                ssl=ssl_results,
                vulns=vulnerabilities
            )

    def monitor(self, interval_hours=24):
        """
        Continuous Monitoring Mode 
        """
        print(f"[+] Cortex Sentinel enters Monitoring Mode for {self.target_url}")
        while True:
            # Check if we already have a recent scan to optimize costs 
            last_scan = self.db.get_cached_result(self.target_url)
            
            if not last_scan:
                self.run_full_scan()
            else:
                print(f"[-] Recent data found for {self.target_url}. Skipping active scan to save resources.")
            
            print(f"[*] Next check in {interval_hours} hours...")
            time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    # Ensure your .env file is set up with SUPABASE_URL and SUPABASE_KEY
    TARGET = "https://example.com" # Replace with your target
    sentinel = CortexSentinel(TARGET)
    
    # Choose between a single scan or continuous monitoring
    # sentinel.run_full_scan() 
    sentinel.monitor(interval_hours=12)