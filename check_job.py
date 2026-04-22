import sqlite3

db_path = r"C:\Users\Administrator\Desktop\cortex-sentinel\sentinel.db"
job_id = "a85d6fa0-4497-441d-be48-554accae1f73"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT id, status, progress FROM jobs WHERE id = ?", (job_id,))
row = cursor.fetchone()

if row:
    print(f"ID: {row[0]}")
    print(f"Status: {row[1]}")
    print(f"Progress: {row[2]}")
else:
    print("Job not found in database.")
conn.close()