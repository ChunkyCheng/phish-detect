import asyncio
import csv
import ssl
import sys
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import aiohttp
from bs4 import BeautifulSoup


MAX_CONCURRENT = 20
REQUEST_TIMEOUT = 30
TARGET_TOTAL_PAGES = 20_000
MAX_DEPTH = 2

KEYWORDS = {
    "login", "signin", "sign-in", "auth",
    "register", "signup", "sign-up",
    "account", "profile", "dashboard",
    "checkout", "payment", "cart", "password"
}

SKIP_EXTENSIONS = {
    ".pdf", ".zip", ".gz", ".tar",
    ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".svg", ".mp4", ".mp3",
    ".doc", ".docx", ".xls", ".xlsx"
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


# -------------------------
# CSV SEED LOADING
# -------------------------
def load_seeds(csv_path: str):
    seeds = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)

        for row in reader:
            if not row:
                continue

            domain = row[0].strip().lower()

            if domain in ("domain", "rank", "#"):
                continue

            if not domain:
                continue

            # Tranco lists sometimes have "rank,domain" format — take last column
            if len(row) >= 2:
                domain = row[-1].strip().lower()

            if not domain.startswith("http"):
                domain = "https://" + domain

            seeds.append(domain)

    return seeds


# -------------------------
# URL HELPERS
# -------------------------
def normalize_url(url: str) -> str:
    url, _ = urldefrag(url)
    parsed = urlparse(url)

    path = parsed.path.rstrip("/")
    if not path:
        path = "/"

    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return False

    lower = parsed.path.lower()

    return not any(lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def is_internal(url: str, domain: str) -> bool:
    return urlparse(url).netloc == domain


def keyword_score(url: str) -> int:
    lower = url.lower()
    return sum(k in lower for k in KEYWORDS)


# -------------------------
# FETCH
# -------------------------
async def fetch(session, url):
    try:
        async with session.get(
            url,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            allow_redirects=True,
            max_redirects=5,
        ) as response:

            ct = response.headers.get("Content-Type", "")

            if "text/html" not in ct:
                return None

            # Avoid reading huge pages
            html = await response.text(errors="ignore")

            return {
                "url": str(response.url),
                "status": response.status,
                "html": html,
            }

    except aiohttp.ClientSSLError as e:
        print(f"  [SSL ERROR] {url}: {e}")
        return None
    except aiohttp.ClientConnectorError as e:
        print(f"  [CONNECT ERROR] {url}: {e}")
        return None
    except aiohttp.TooManyRedirects:
        print(f"  [TOO MANY REDIRECTS] {url}")
        return None
    except asyncio.TimeoutError:
        print(f"  [TIMEOUT] {url}")
        return None
    except Exception as e:
        print(f"  [FETCH ERROR] {url}: {type(e).__name__}: {e}")
        return None


# -------------------------
# PARSE
# -------------------------
def parse_page(base_url, html):
    soup = BeautifulSoup(html, "html.parser")

    title = soup.title.get_text(strip=True) if soup.title else ""

    links = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        link = urljoin(base_url, href)
        link = normalize_url(link)

        if is_valid_url(link):
            links.add(link)

    password_fields = soup.find_all("input", {"type": "password"})
    forms = soup.find_all("form")

    return {
        "title": title,
        "links": links,
        "num_forms": len(forms),
        "has_password_field": len(password_fields) > 0,
    }


# -------------------------
# CRAWLER PER DOMAIN
# -------------------------
async def crawl_domain(session, seed, domain, writer, state, lock):
    queue = deque([(seed, 0)])
    visited = set()

    # Also try www variant if seed doesn't have it
    alt_seed = None
    if not domain.startswith("www."):
        alt_seed = "https://www." + domain
        queue.append((alt_seed, 0))

    while queue:
        async with lock:
            if state["total"] >= TARGET_TOTAL_PAGES:
                return
            if state["per_domain"][domain] >= state["limit_per_domain"]:
                return

        url, depth = queue.popleft()

        if depth > MAX_DEPTH:
            continue

        if url in visited:
            continue

        visited.add(url)

        result = await fetch(session, url)
        if not result:
            continue

        final_url = result["url"]
        page = parse_page(final_url, result["html"])

        row = {
            "url": final_url,
            "status": result["status"],
            "title": page["title"],
            "num_forms": page["num_forms"],
            "has_password_field": page["has_password_field"],
            "domain": domain,
            "depth": depth,
        }

        async with lock:
            # Re-check limits inside the lock before writing
            if state["total"] >= TARGET_TOTAL_PAGES:
                return
            if state["per_domain"][domain] >= state["limit_per_domain"]:
                return

            writer.writerow(row)
            state["total"] += 1
            state["per_domain"][domain] += 1
            total = state["total"]

        print(f"[{domain}] {total}/{TARGET_TOTAL_PAGES} depth={depth} {final_url}")

        # Only follow internal links; also accept www variant as "internal"
        def is_same_site(u):
            netloc = urlparse(u).netloc
            return netloc == domain or netloc == "www." + domain or "www." + netloc == domain

        candidates = [
            link for link in page["links"]
            if is_same_site(link) and link not in visited
        ]

        candidates.sort(key=keyword_score, reverse=True)

        for link in candidates:
            queue.append((link, depth + 1))


# -------------------------
# MAIN
# -------------------------
async def main(seed_csv):
    seeds = load_seeds(seed_csv)

    if not seeds:
        print("No seeds loaded — check your CSV format.")
        sys.exit(1)

    total_domains = len(seeds)
    limit_per_domain = 50

    # Build per_domain keyed by netloc (after scheme is added)
    per_domain = {}
    deduped_seeds = []
    for s in seeds:
        netloc = urlparse(s).netloc
        if netloc and netloc not in per_domain:
            per_domain[netloc] = 0
            deduped_seeds.append(s)

    state = {
        "total": 0,
        "per_domain": per_domain,
        "limit_per_domain": limit_per_domain,
    }

    print(f"Loaded {len(deduped_seeds)} unique domains (from {total_domains} rows)")
    print(f"Limit per domain: {limit_per_domain}")
    print(f"Target total pages: {TARGET_TOTAL_PAGES}")

    # Create a permissive SSL context to avoid failing on bad certs
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT,
        ssl=ssl_ctx,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    lock = asyncio.Lock()

    async with aiohttp.ClientSession(connector=connector) as session:

        with open("benign_pages.csv", "w", newline="", encoding="utf-8") as f:

            writer = csv.DictWriter(f, fieldnames=[
                "url",
                "status",
                "title",
                "num_forms",
                "has_password_field",
                "domain",
                "depth",
            ])
            writer.writeheader()
            f.flush()  # Ensure header is written immediately

            tasks = [
                crawl_domain(session, seed, urlparse(seed).netloc, writer, state, lock)
                for seed in deduped_seeds
            ]

            await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\nDone. Wrote {state['total']} pages to benign_pages.csv")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python crawler.py seeds.csv")
        sys.exit(1)

    asyncio.run(main(sys.argv[1]))