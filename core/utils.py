
def normalize_finding(f):
    return {
        "type": f.get("type"),
        "target_url": f.get("target_url") or f.get("url") or "N/A",
        "payload": f.get("payload", ""),
        "severity": f.get("severity", "Low"),
        "confidence": f.get("confidence", 0),
        "note": f.get("note", "")
    }

