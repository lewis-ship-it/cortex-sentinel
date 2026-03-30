import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.max_pages = max_pages

    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    async def crawl(self, client, url=None):
        if url is None:
            url = self.base_url

        if url in self.visited or len(self.visited) >= self.max_pages:
            return

        self.visited.add(url)

        try:
            res = await client.get(url)
            soup = BeautifulSoup(res.text, "html.parser")

            for link in soup.find_all("a", href=True):
                full = urljoin(self.base_url, link["href"])
                if self.is_internal(full):
                    self.endpoints.add(full)
                    await self.crawl(client, full)

            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = form.get("method", "get").lower()

                inputs = [
                    inp.get("name")
                    for inp in form.find_all(["input", "textarea"])
                    if inp.get("name")
                ]

                self.forms.append({
                    "url": urljoin(self.base_url, action),
                    "method": method,
                    "inputs": inputs
                })

        except:
            pass

        return self.endpoints, self.forms