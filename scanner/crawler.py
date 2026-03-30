import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.discovered_endpoints = set()

    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def crawl(self, url=None):
        if url is None:
            url = self.base_url
        
        if url in self.visited_urls or len(self.visited_urls) > 50: # Limit for MVP
            return

        self.visited_urls.add(url)
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                full_url = urljoin(self.base_url, link['href'])
                if self.is_internal(full_url) and full_url not in self.visited_urls:
                    self.discovered_endpoints.add(full_url)
                    self.crawl(full_url) # Recursive discovery
        except Exception as e:
            print(f"Error crawling {url}: {e}")

        return self.discovered_endpoints