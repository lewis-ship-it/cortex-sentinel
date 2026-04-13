# utils/differ.py
import difflib
import re

def calculate_similarity(html1, html2):
    """
    Returns a float between 0.0 and 1.0 representing similarity.
    1.0 means the pages are identical.
    """
    if not html1 or not html2:
        return 0.0
        
    # 1. Clean the HTML (Remove dynamic tokens like CSRF, timestamps, etc.)
    # This prevents false positives from pages that change every second naturally.
    def clean(text):
        text = re.sub(r'<input type="hidden" name="csrf_token" value=".*?">', '', text)
        text = re.sub(r'\d{2}:\d{2}:\d{2}', '', text) # Remove timestamps
        return text

    s = difflib.SequenceMatcher(None, clean(html1), clean(html2))
    return s.quick_ratio()

def has_structural_change(html1, html2):
    """Checks if the number of HTML tags changed significantly."""
    tags1 = len(re.findall(r'<[^>]+>', html1))
    tags2 = len(re.findall(r'<[^>]+>', html2))
    return tags1 != tags2