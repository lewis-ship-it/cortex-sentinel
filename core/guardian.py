import re

def rules(url: str):
    """
    Ensures the Sentinel doesn't scan prohibited targets.
    """
    target = url.lower().strip()

    # Rule 1: No self-scanning (Internal/Private IPs)
    if re.search(r"(localhost|127\.0\.0\.1|192\.168\.|10\.)", target):
        return {"allowed": False, "reason": "Internal network scanning is prohibited."}

    # Rule 2: No Gov/Mil infrastructure
    if target.endswith((".gov", ".mil")):
        return {"allowed": False, "reason": "Restricted domain policy activated."}

    return {"allowed": True, "rate_limit": 1.0}