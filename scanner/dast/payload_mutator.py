# scanner/dast/payload_mutator.py
import urllib.parse

class PayloadMutator:
    def mutate(self, payload: str) -> list:
        return [
            payload,
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload)),   # double-encode
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("script", "scr<script>ipt"),
            payload.replace(" ", "/**/"),
            payload.upper(),
        ]
