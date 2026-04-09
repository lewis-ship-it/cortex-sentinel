import os
import fnmatch

# --- CONFIGURATION ---
OUTPUT_FILE = "fullsend.txt"

# 1. Add specific root files here ]
TARGET_FILES = [
]

# 2. Folders you want to deep-crawl
TARGET_FOLDERS = [
    "workers"
]
# 3. Things to ignore (crucial for clean dumps)
IGNORE_PATTERNS = ["__pycache__", "*.pyc", ".git", ".env", "venv", "node_modules"]

def should_ignore(path):
    for pattern in IGNORE_PATTERNS:
        if fnmatch.fnmatch(path, pattern) or pattern in path.split(os.sep):
            return True
    return False

def dump_project():
    count = 0
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        
        # --- PHASE 1: Specific Files ---
        out.write("### SECTION: ROOT FILES ###\n")
        for file_path in TARGET_FILES:
            if os.path.exists(file_path):
                out.write(f"\n\n===== FILE: {file_path} =====\n\n")
                with open(file_path, "r", encoding="utf-8") as f:
                    out.write(f.read())
                count += 1

        # --- PHASE 2: Folder Crawl ---
        out.write("\n\n### SECTION: DIRECTORY CRAWL ###\n")
        for folder in TARGET_FOLDERS:
            if not os.path.exists(folder):
                continue
                
            for root, _, files in os.walk(folder):
                if should_ignore(root):
                    continue
                    
                for file in files:
                    if file.endswith(".py") and not should_ignore(file):
                        path = os.path.join(root, file)
                        out.write(f"\n\n===== PATH: {path} =====\n\n")
                        with open(path, "r", encoding="utf-8") as f:
                            out.write(f.read())
                        count += 1

    print(f"✅ Dump complete! Processed {count} files → {OUTPUT_FILE}")

if __name__ == "__main__":
    dump_project()