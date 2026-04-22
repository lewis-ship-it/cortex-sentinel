import sqlite3
import json

def check_job(job_id):
    # Adjust this path if your db is in a different location
    db_path = "sentinel.db" 
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Query the job state
        cursor.execute("SELECT status, progress FROM jobs WHERE id = ?", (job_id,))
        job = cursor.fetchone()
        
        # Query findings count for this job
        cursor.execute("SELECT COUNT(*) FROM findings WHERE job_id = ?", (job_id,))
        findings_count = cursor.fetchone()[0]
        
        if job:
            print(f"--- Job Status for {job_id} ---")
            print(f"Status:   {job[0]}")
            print(f"Progress: {job[1]}")
            print(f"Findings: {findings_count}")
        else:
            print(f"Job {job_id} not found in the database.")
            
        conn.close()
    except Exception as e:
        print(f"Error connecting to database: {e}")

if __name__ == "__main__":
    check_job("a85d6fa0-4497-441d-be48-554accae1f73")