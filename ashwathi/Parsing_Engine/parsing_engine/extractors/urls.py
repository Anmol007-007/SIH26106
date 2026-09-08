import re
import tldextract
from bs4 import BeautifulSoup
from parsing_engine.schema import UrlInfo
URL_REGEX = re.compile(r'https?://[^\s\'"<>]+')
def extract_urls(body_plain: str, body_html: str) -> list[UrlInfo]:
    results = {}
    for url in URL_REGEX.findall(body_plain):
        domain = _get_domain(url)
        results[url] = UrlInfo(url=url, domain=domain, anchor_text=None)
    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("http://", "https://")):
                domain = _get_domain(href)
                anchor = tag.get_text(strip=True) or None
                results[href] = UrlInfo(url=href, domain=domain, anchor_text=anchor)
    return list(results.values())
def _get_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
