import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv() # Loads variables from your .env file

class DatabaseManager:
    def __init__(self):
        url: str = os.environ.get("SUPABASE_URL")
        key: str = os.environ.get("SUPABASE_KEY")
        self.supabase: Client = create_client(url, key)

    def get_cached_result(self, target_url):
        # Implementation of "Cache scan results and avoid re-scanning"
        try:
            response = self.supabase.table("scan_results") \
                .select("*") \
                .eq("url", target_url) \
                .order("created_at", desc=True) \
                .limit(1) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Database Error: {e}")
            return None

    def save_scan(self, url, header_data, ssl_data):
        # Save results for future incremental scanning
        data = {
            "url": url,
            "headers": header_data,
            "ssl_info": ssl_data,
            "severity_score": 0 # Logic to be added later
        }
        self.supabase.table("scan_results").insert(data).execute()