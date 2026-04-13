# scanner/dast/context_analyzer.py
import re

class InjectionContext:
    HTML_BODY = "html_body"           # <div>REF</div>
    HTML_ATTR = "html_attr"           # <input value="REF">
    JS_STR    = "js_string"           # var name = 'REF';
    JSON      = "json"                # {"item": "REF"}
    UNKNOWN   = "unknown"

def identify_context(html: str, canary: str) -> str:
    """
    Finds where the 'canary' string is reflected and identifies the escape 
    requirements for that specific location.
    """
    if canary not in html:
        return InjectionContext.UNKNOWN

    # Find the first occurrence
    idx = html.find(canary)
    # Get 100 characters before the canary to see the "container"
    prefix = html[max(0, idx-100):idx].lower()
    
    # 1. Check for Script Context
    if "<script" in prefix and "</script" not in prefix:
        return InjectionContext.JS_STR
    
    # 2. Check for Attribute Context (looking for an unclosed quote)
    # If there's a " or ' followed by an = but no closing >
    attr_match = re.search(r'(\w+)\s*=\s*["\']$', prefix)
    if attr_match:
        return InjectionContext.HTML_ATTR
        
    # 3. Check for JSON context
    if prefix.strip().endswith(':') or prefix.strip().endswith(':"'):
        return InjectionContext.JSON

    return InjectionContext.HTML_BODY