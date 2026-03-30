import os
import streamlit as st
from supabase import create_client, Client
from dotenv import load_dotenv

class DatabaseManager:
    def __init__(self):
        url = None
        key = None

        # 1. Try Streamlit Secrets
        try:
            url = st.secrets.get("SUPABASE_URL")
            key = st.secrets.get("SUPABASE_KEY")
        except Exception:
            pass

        # 2. Try Environment Variables (Local/.env/GitHub Actions)
        if not url or not key:
            load_dotenv()
            url = os.environ.get("SUPABASE_URL")
            key = os.environ.get("SUPABASE_KEY")

        # 3. CRITICAL: Clean the strings to prevent [Errno -2]
        if url:
            # Removes spaces and trailing slashes
            url = url.strip().rstrip('/')
        if key:
            key = key.strip()

        # 4. Final Validation
        if not url or not key:
            raise ValueError("Cortex Sentinel Error: Supabase credentials not found.")

        # 5. Initialize the Client
        self.supabase: Client = create_client(url, key)

    def get_cached_result(self, target_url):
        try:
            response = self.supabase.table("scan_results") \
                .select("*") \
                .eq("url", target_url) \
                .order("created_at", desc=True) \
                .limit(1) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            st.error(f"Database Retrieval Error: {e}")
            return None

    def save_scan_result(self, url, headers, ssl, vulns=None):
        data = {
            "url": url,
            "headers": headers,
            "ssl_info": ssl,
            "vulnerabilities": vulns if vulns else [],
            "severity_score": 0 
        }
        try:
            self.supabase.table("scan_results").insert(data).execute()
        except Exception as e:
            st.error(f"Database Save Error: {e}")