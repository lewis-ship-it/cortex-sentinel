import subprocess
import sys
import threading
import time
import os
import webbrowser

# 1. PATH CONFIGURATION
# We point directly to the python.exe inside your virtual environment
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")

# 2. ENVIRONMENT SYNC
# This ensures every worker knows where the project root is
env_config = os.environ.copy()
env_config["PYTHONPATH"] = PROJECT_ROOT

WORKERS = [
    {"name": "BRAIN (API)  ", "cmd": [VENV_PYTHON, "-m", "api.main"]},
    {"name": "MUSCLE (Scan)", "cmd": [VENV_PYTHON, "-m", "workers.scan_worker"]},
    {"name": "EXPLOIT       ", "cmd": [VENV_PYTHON, "-m", "workers.exploit_worker"]},
    {"name": "AGGREGATION   ", "cmd": [VENV_PYTHON, "-m", "workers.aggregation_worker"]},
    {"name": "REPORT        ", "cmd": [VENV_PYTHON, "-m", "workers.report_worker"]},
    # Note: Using app.py instead of dashboard.py to ensure crawl compatibility
    {"name": "FACE (Dash)   ", "cmd": [VENV_PYTHON, "-m", "streamlit", "run", "app.py", "--server.headless", "true"]},
]

browser_opened = False

def stream_logs(pipe, name):
    global browser_opened
    try:
        for line in iter(pipe.readline, b''):
            # Use 'replace' to prevent the UnicodeDecodeError on Windows
            decoded_line = line.decode('utf-8', errors='replace').strip()
            if decoded_line:
                print(f"[{name}] {decoded_line}")
                
                # Intelligent Browser Launch: Only trigger once Streamlit is truly ready
                if name == "FACE (Dash)   " and "Network URL:" in decoded_line and not browser_opened:
                    print("\n✨ Cortex Shield Dashboard Ready! Launching browser...")
                    webbrowser.open("http://localhost:8501")
                    browser_opened = True
    except Exception:
        pass
    finally:
        pipe.close()

def start_system():
    processes = []
    print(f"🛡️  Cortex Sentinel | Root: {PROJECT_ROOT}")
    print(f"🐍 Using Venv Python: {VENV_PYTHON}\n")

    for worker in WORKERS:
        try:
            # env=env_config is the key to fixing ModuleNotFoundErrors
            p = subprocess.Popen(
                worker["cmd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                shell=False,
                env=env_config 
            )
            processes.append(p)
            
            thread = threading.Thread(target=stream_logs, args=(p.stdout, worker["name"]))
            thread.daemon = True
            thread.start()
            
            print(f"✅ Launched {worker['name']}")
            time.sleep(1.5) # Staggered start to prevent Redis race conditions
        except Exception as e:
            print(f"❌ Critical Failure Launching {worker['name']}: {e}")

    print("\n🚀 All systems active. Streaming logs below. Press Ctrl+C to stop.\n" + "="*75)

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Sentinel... Terminating all workers.")
        for p in processes:
            p.terminate()
        print("Done.")

if __name__ == "__main__":
    # Final check: Ensure we are in the right folder
    os.chdir(PROJECT_ROOT)
    start_system()