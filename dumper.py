# dump_project.py

import os

OUTPUT_FILE = "fullsend.txt"

TARGET_FOLDERS = [
    "core",
    "scanner",
    "app",
    "api",
    "queue",
    "workers"
]

def dump():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for folder in TARGET_FOLDERS:
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(".py"):
                        path = os.path.join(root, file)

                        out.write(f"\n\n===== {path} =====\n\n")

                        with open(path, "r", encoding="utf-8") as f:
                            out.write(f.read())

    print("Dump complete →", OUTPUT_FILE)


if __name__ == "__main__":
    dump()