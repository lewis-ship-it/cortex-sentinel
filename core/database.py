import os
import streamlit as st
from supabase import create_client, Client
from dotenv import load_dotenv

class DatabaseManager:
    def __init__(self):
        # 1. Try to get keys from Streamlit Secrets (for Cloud hosting)
        # Use .get() to avoid errors if the 'secrets' object isn't initialized
        url = st.secrets.get("SUPABASE_URL")
        key = st.secrets.get("SUPABASE_KEY")

        # 2. Fallback to local Environment/.env (for local development)
        if not url or not key:
            load_dotenv()
            url = os.environ.get("SUPABASE_URL")
            key = os.environ.get("SUPABASE_KEY")

        # 3. Validation: Ensure we actually have the credentials
        if not url or not key:
            raise ValueError(
                "Cortex Sentinel Error: Supabase credentials not found. "
                "Ensure SUPABASE_URL and SUPABASE_KEY are set in Streamlit Secrets or a .env file."
            )

        self.supabase: Client = create_client(url, key)

    def get_cached_result(self, target_url):
        """Implementation of 'Cache scan results and avoid re-scanning'"""
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
        """Save results for future incremental scanning and reporting"""
        data = {
            "url": url,
            "headers": headers,
            "ssl_info": ssl,
            "vulnerabilities": vulns if vulns else [],
            "severity_score": 0  # Logic for scoring can be added here later
        }
        try:
            self.supabase.table("scan_results").insert(data).execute()
        except Exception as e:
            st.error(f"Database Save Error: {e}")