import sqlite3
import os

# Path to your database
db_path = r"C:\Users\Administrator\Desktop\cortex-sentinel\sentinel.db"
job_id = "80ff7de6-111b-433a-8d98-f43cb85ed636"

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Enable foreign keys just in case
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # Delete the job
    cursor.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    
    conn.commit()
    print(f"Successfully deleted job {job_id}. Rows affected: {cursor.rowcount}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")