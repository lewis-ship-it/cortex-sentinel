import subprocess
import sys
import threading
import time

# List all the modules to run
WORKERS = [
    {"name": "BRAIN (API)  ", "cmd": ["python", "-m", "api.main"]},
    {"name": "MUSCLE (Scan)", "cmd": ["python", "-m", "workers.scan_worker"]},
    {"name": "exploit", "cmd": ["python", "-m", "workers.exploit_worker"]},
    {"name": "aggregation", "cmd": ["python", "-m", "workers.aggregation_worker"]},
    {"name": "report", "cmd": ["python", "-m", "workers.report_worker"]},
    {"name": "FACE (Dash) ", "cmd": ["streamlit", "run", "app/dashboard.py", "--server.headless", "true"]},
]

def stream_logs(pipe, name):
    """Reads output from a subprocess and prints it with a prefix."""
    for line in iter(pipe.readline, b''):
        # Print with the worker's name so you know who is talking
        print(f"[{name}] {line.decode().strip()}")
    pipe.close()

def start_system():
    processes = []
    print("🚀 Starting Sentinel AI Stack...\n")

    for worker in WORKERS:
        # We use bufsize=0 and stdout=PIPE to catch logs in real-time
        p = subprocess.Popen(
            worker["cmd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0
        )
        processes.append(p)
        
        # Start a background thread for each worker to handle its logs
        thread = threading.Thread(target=stream_logs, args=(p.stdout, worker["name"]))
        thread.daemon = True # Thread dies when main script dies
        thread.start()
        
        print(f"✅ Launched {worker['name']}")
        time.sleep(2) # Give Redis/Port a moment to breathe

    print("\n🔥 All systems active. Streaming logs below. Press Ctrl+C to stop.\n" + "="*60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down all processes...")
        for p in processes:
            p.terminate()
        print("👋 Goodbye.")

if __name__ == "__main__":
    start_system()