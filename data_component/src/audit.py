from pathlib import Path
from collections import Counter
import json
from bs4 import BeautifulSoup

def audit_good_data(good_data_dir):
    good_data_dir = Path(good_data_dir)
    title_counter = Counter()
    domain_counter = Counter()

    for f in good_data_dir.rglob("*.json"):
        with f.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        body = data.get("body", "")
        soup = BeautifulSoup(body, "html.parser")

        # Collect titles
        if soup.title:
            title = soup.title.get_text(" ", strip=True).strip()
            title_counter[title] += 1

        # Collect base domains from internal links (reveals what platform served the page)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(href).netloc.lower()
                    # strip www and keep root domain
                    domain = ".".join(domain.split(".")[-2:])
                    domain_counter[domain] += 1
                except Exception:
                    pass

    print("\n=== TOP TITLES IN GOOD DATA ===")
    for title, count in title_counter.most_common(40):
        print(f"  {count:>4}x  {title[:100]}")

    print("\n=== TOP DOMAINS LINKED FROM GOOD DATA ===")
    for domain, count in domain_counter.most_common(30):
        print(f"  {count:>4}x  {domain}")

if __name__ == "__main__":
    import sys
    audit_good_data(sys.argv[1])