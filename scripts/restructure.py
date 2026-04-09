import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_FILE = BASE_DIR / "restructure_report.txt"

moves = [
    # STORAGE
    ("core/database.py", "storage/database.py"),
    ("core/aggregation_store.py", "storage/aggregation_store.py"),

    # SCANNER ENGINES
    ("scanner/api_engine.py", "scanner/api/api_engine.py"),
    ("scanner/network_engine.py", "scanner/network/network_engine.py"),
    ("scanner/mobile_engine.py", "scanner/mobile/mobile_engine.py"),
    ("scanner/playwright_engine.py", "scanner/browser/playwright_engine.py"),
    ("scanner/exploit_engine.py", "scanner/exploit/exploit_engine.py"),

    # DAST
    ("scanner/smart_crawler.py", "scanner/dast/smart_crawler.py"),
    ("scanner/payload_mutator.py", "scanner/dast/payload_mutator.py"),
    ("scanner/priority_engine.py", "scanner/dast/priority_engine.py"),
    ("scanner/param_engine.py", "scanner/dast/param_engine.py"),
    ("scanner/rate_limiter.py", "scanner/dast/rate_limiter.py"),

    # INTELLIGENCE
    ("scanner/ai_report.py", "intelligence/ai/report_generator.py"),
    ("scanner/attack_graph.py", "intelligence/attack_graph/engine.py"),
    ("scanner/risk_prioritizer.py", "intelligence/prioritization/risk_prioritizer.py"),

    # WORKERS RENAME
    ("workers/crawl_workers.py", "workers/crawl_worker.py"),
    ("workers/scan_workers.py", "workers/scan_worker.py"),
    ("workers/browser_workers.py", "workers/browser_worker.py"),
    ("workers/aggregation_workers.py", "workers/aggregation_worker.py"),
    ("workers/exploit_workers.py", "workers/exploit_worker.py"),
    ("workers/report_workers.py", "workers/report_worker.py"),
]


def create_structure():
    dirs = [
        "storage",
        "scanner/api",
        "scanner/network",
        "scanner/mobile",
        "scanner/browser",
        "scanner/exploit",
        "scanner/dast",
        "intelligence/ai",
        "intelligence/attack_graph",
        "intelligence/prioritization",
    ]

    for d in dirs:
        path = BASE_DIR / d
        path.mkdir(parents=True, exist_ok=True)


def move_files():
    report_lines = []

    for src, dst in moves:
        src_path = BASE_DIR / src
        dst_path = BASE_DIR / dst

        if not src_path.exists():
            report_lines.append(f"[SKIP] {src} not found")
            continue

        dst_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(src_path), str(dst_path))
        report_lines.append(f"[MOVE] {src} → {dst}")

    return report_lines


def delete_legacy():
    report_lines = []

    legacy = BASE_DIR / "workers/workers.py"
    if legacy.exists():
        legacy.unlink()
        report_lines.append("[DELETE] workers/workers.py")

    return report_lines


def write_report(lines):
    with open(REPORT_FILE, "w") as f:
        f.write("\n".join(lines))


def main():
    print("Starting restructure...")

    create_structure()
    report = []

    report += move_files()
    report += delete_legacy()

    write_report(report)

    print("Done.")
    print(f"Report written to {REPORT_FILE}")


if __name__ == "__main__":
    main()