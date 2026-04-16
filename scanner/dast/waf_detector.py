import httpx

class WAFDetector:
    def __init__(self):
        # Common WAF signatures in headers or body
        self.signatures = {
            "Cloudflare": ["__cfduid", "cf-ray", "cloudflare-nginx", "cloudflare"],
            "Akamai": ["akamai-ch", "akamai-ghost", "true-client-ip"],
            "AWS WAF": ["x-amzn-requestid", "awselb"],
            "ModSecurity": ["mod_security", "no-cache=\"set-cookie\"", "modsecurity_terminology"]
        }

    async def detect(self, client: httpx.AsyncClient, url: str) -> str:
        try:
            # Trigger a 'fake' attack to see how the WAF responds
            res = await client.get(f"{url}?test=<script>alert(1)</script>")
            headers_str = str(res.headers).lower()
            body_str = res.text.lower()

            for waf, sigs in self.signatures.items():
                if any(sig in headers_str or sig in body_str for sig in sigs):
                    return waf
            return "Generic"
        except Exception as e:
            return "Generic"