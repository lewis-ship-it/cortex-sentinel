
# workers/scoring_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES vs previous version:
#   1. Variable name collision: function was named `score` AND the local result
#      was also named `score` — calling score(findings) shadowed the function
#      on every invocation after the first.  Renamed function to calculate_score().
#   2. findings arrived as a dict (enriched payload from pipeline.on_aggregation_complete
#      which sends `data = {findings, attack_graph, chains}`).  score() iterated
#      a dict, producing KeyErrors.  Fixed: normalise to list at top of handle().
#   3. Added tier propagation to on_report_complete so the report pipeline has context.
#   4. Added CVSS-inspired multipliers and chain bonus instead of flat -20/-10/-5.
# ──────────────────────────────────────────────────────────────────────────────

from workers.base_worker import worker_loop, push_log
from task_queue.queues import SCORING_QUEUE
from core.pipeline import on_report_complete


def calculate_score(findings: list) -> int:
    """
    CVSS-inspired security score (0 = worst, 100 = clean).

    Deductions:
      Critical  : -25 each (cap: -60)
      High      : -15 each (cap: -30)
      Medium    : -7  each (cap: -14)
      Low       : -2  each (cap: -6)
    Chain bonus  : -10 if any attack chain finding present
    """
    if not findings:
        return 100

    sev_weights = {
        "Critical": 25,
        "High":     15,
        "Medium":   7,
        "Low":      2,
        "Info":     0,
    }
    sev_caps = {
        "Critical": 60,
        "High":     30,
        "Medium":   14,
        "Low":      6,
        "Info":     0,
    }
    sev_totals: dict[str, int] = {}

    has_chain = False
    for f in findings:
        sev = f.get("severity", "Low")
        if "Attack Chain" in f.get("type", ""):
            has_chain = True
        deduction = sev_weights.get(sev, 2)
        sev_totals[sev] = sev_totals.get(sev, 0) + deduction

    total_deduction = sum(
        min(total, sev_caps.get(sev, total))
        for sev, total in sev_totals.items()
    )
    if has_chain:
        total_deduction += 10

    return max(0, 100 - total_deduction)


def handle(job):
    job_id   = job["job_id"]
    raw      = job.get("findings", [])
    tier     = job.get("tier", "Basic")

    # FIX: pipeline sends findings as a dict {findings, attack_graph, chains}
    # normalise to list before scoring
    if isinstance(raw, dict):
        findings = raw.get("findings", [])
        chains   = raw.get("chains", [])
        # include chain findings in score
        findings = findings + [
            {"type": f"Attack Chain: {c.get('type','?')}", "severity": "Critical"}
            for c in chains
        ]
    else:
        findings = raw

    push_log(job_id, "[SCORING] Calculating risk score", tier=tier)

    final_score = calculate_score(findings)

    severity_breakdown = {}
    for f in findings:
        sev = f.get("severity", "Low")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    report = {
        "score":              final_score,
        "findings":           findings,
        "severity_breakdown": severity_breakdown,
        "total_findings":     len(findings),
        "tier":               tier,
    }

    push_log(job_id, f"[SCORING] Score = {final_score} | Breakdown: {severity_breakdown}", tier=tier)

    on_report_complete(job_id, report, tier=tier)


if __name__ == "__main__":
    worker_loop(SCORING_QUEUE, handle)

