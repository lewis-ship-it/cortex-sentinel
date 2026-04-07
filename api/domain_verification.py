import httpx
import uuid

class DomainVerifier:

    def __init__(self):
        pass

    async def generate_token(self):
        return str(uuid.uuid4())

    async def verify_domain(self, domain, token):
        """
        User must place token at:
        https://domain/.sentinel-verification.txt
        """

        url = f"https://{domain}/.sentinel-verification.txt"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                res = await client.get(url)

                if res.status_code == 200 and token in res.text:
                    return True

        except:
            pass

        return False