import os
import re
from pathlib import Path
import shutil

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_FILE = BASE_DIR / "import_fix_report.txt"
BACKUP_DIR = BASE_DIR / "import_backup"

# 🔥 MAP OLD → NEW IMPORT PATHS
IMPORT_MAP = {
    "scanner.api_engine": "scanner.api.api_engine",
    "scanner.network_engine": "scanner.network.network_engine",
    "scanner.mobile_engine": "scanner.mobile.mobile_engine",
    "scanner.playwright_engine": "scanner.browser.playwright_engine",
    "scanner.exploit_engine": "scanner.exploit.exploit_engine",

    "scanner.smart_crawler": "scanner.dast.smart_crawler",
    "scanner.payload_mutator": "scanner.dast.payload_mutator",
    "scanner.priority_engine": "scanner.dast.priority_engine",
    "scanner.param_engine": "scanner.dast.param_engine",
    "scanner.rate_limiter": "scanner.dast.rate_limiter",

    "scanner.ai_report": "intelligence.ai.report_generator",
    "scanner.attack_graph": "intelligence.attack_graph.engine",
    "scanner.risk_prioritizer": "intelligence.prioritization.risk_prioritizer",

    "core.database": "storage.database",
    "core.aggregation_store": "storage.aggregation_store",
}

EXCLUDE_DIRS = {"__pycache__", "venv", ".git", "node_modules", "import_backup"}


def backup_file(file_path):
    backup_path = BACKUP_DIR / file_path.relative_to(BASE_DIR)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(file_path, backup_path)


def fix_imports_in_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    original_content = content
    changes = []

    for old, new in IMPORT_MAP.items():
        # from ... import ...
        pattern1 = rf"from\s+{re.escape(old)}\s+import\s+"
        if re.search(pattern1, content):
            content = re.sub(pattern1, f"from {new} import ", content)
            changes.append(f"{old} → {new}")

        # import ...
        pattern2 = rf"import\s+{re.escape(old)}"
        if re.search(pattern2, content):
            content = re.sub(pattern2, f"import {new}", content)
            changes.append(f"{old} → {new}")

    if content != original_content:
        backup_file(file_path)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    return changes


def scan_and_fix():
    report_lines = []

    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = Path(root) / file

            changes = fix_imports_in_file(file_path)

            if changes:
                report_lines.append(f"\n[FILE] {file_path}")
                for c in changes:
                    report_lines.append(f"  - {c}")

    return report_lines


def write_report(lines):
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    print("Starting import fix...")

    BACKUP_DIR.mkdir(exist_ok=True)

    report = scan_and_fix()

    write_report(report)

    print("Done.")
    print(f"Report: {REPORT_FILE}")
    print(f"Backup: {BACKUP_DIR}")


if __name__ == "__main__":
    main()