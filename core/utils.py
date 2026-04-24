# core/utils.py
def normalize_finding(f: dict) -> dict:
    """
    Merge all known field aliases into a canonical finding dict.
    Preserves every field — never discards evidence or confidence data.
    """
    # Resolve field aliases
    target_url       = f.get("target_url") or f.get("url") or "N/A"
    param            = f.get("param") or f.get("parameter") or ""
    confidence       = f.get("confidence_score") or f.get("confidence") or 0.0
    evidence_snippet = (f.get("evidence_snippet") or f.get("evidence") or
                        f.get("note") or "")

    normalized = dict(f)  # keep ALL original fields
    # Set canonical keys so every downstream consumer finds what it needs
    normalized["target_url"]       = target_url
    normalized["url"]              = target_url
    normalized["param"]            = param
    normalized["parameter"]        = param
    normalized["confidence_score"] = confidence
    normalized["confidence"]       = confidence
    normalized["evidence_snippet"] = evidence_snippet
    if not normalized.get("evidence"):
        normalized["evidence"]     = evidence_snippet
    normalized.setdefault("type",     "Unknown")
    normalized.setdefault("severity", "Medium")
    normalized.setdefault("payload",  "")
    normalized.setdefault("method",   "")
    return normalized