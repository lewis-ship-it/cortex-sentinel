import os
import streamlit as st
from supabase import create_client, Client
from dotenv import load_dotenv

class DatabaseManager:
    def __init__(self):
        url = None
        key = None

        # 1. Try Streamlit Secrets (for Cloud)
        try:
            url = st.secrets.get("SUPABASE_URL")
            key = st.secrets.get("SUPABASE_KEY")
        except Exception:
            pass

        # 2. Fallback to local .env (for Local/GitHub Actions)
        if not url or not key:
            load_dotenv()
            url = os.environ.get("SUPABASE_URL")
            key = os.environ.get("SUPABASE_KEY")

        # 3. Clean and Validate
        if url:
            url = url.strip().rstrip('/')
        if not url or not key:
            raise ValueError("Cortex Sentinel Error: Supabase credentials not found.")

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
            print(f"Database Error: {e}")
            return None

    def calculate_grade(self, total_score):
        """Logic to turn a numeric score into a letter grade"""
        if total_score >= 9: return "F (Critical)"
        if total_score >= 7: return "D (Poor)"
        if total_score >= 4: return "C (Average)"
        if total_score > 0: return "B (Fair)"
        return "A (Secure)"

    def save_scan(self, url, header_data, ssl_data, vulnerabilities=None):
        # Calculate total severity score based on findings
        total_score = sum([v.get('score', 0) for v in vulnerabilities]) if vulnerabilities else 0
        
        data = {
            "url": url,
            "headers": header_data,
            "ssl_info": ssl_data,
            "vulnerabilities": vulnerabilities if vulnerabilities else [],
            "severity_score": total_score
        }
        self.supabase.table("scan_results").insert(data).execute()