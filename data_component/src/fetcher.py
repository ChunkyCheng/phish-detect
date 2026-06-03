import asyncio
import aiohttp
import logging
import csv
import json
import hashlib
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logging.getLogger("aiohttp.connector").setLevel(logging.CRITICAL)

MAX_CONCURRENT = 100      # simultaneous connections
TIMEOUT = 10              # seconds per request
MAX_RETRIES = 2           # retries on transient failure
RETRY_DELAY = 2           # seconds between retries

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}


async def fetch_url(session: aiohttp.ClientSession, url: str) -> dict:
    for attempt in range(MAX_RETRIES + 1):
        try:
            async with session.get(
                url,
                headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
                ssl=False,
            ) as response:
                body = await response.text(errors="replace")
                return {
                    "url": url,
                    "success": True,
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "error": None,
                }

        except aiohttp.ClientConnectorDNSError:
            # DNS failed — no point retrying, domain doesn't resolve
            return {
                "url": url,
                "success": False,
                "status_code": None,
                "headers": None,
                "body": None,
                "error": "dns_error",
            }

        except asyncio.TimeoutError:
            error = "timeout"
        except aiohttp.ClientConnectorError as e:
            # Covers connection refused, network unreachable, etc.
            error = f"connection_error: {e.os_error}"
        except aiohttp.ClientError as e:
            error = f"client_error: {type(e).__name__}"
        except Exception as e:
            error = str(e)

        if attempt < MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY)

    return {
        "url": url,
        "success": False,
        "status_code": None,
        "headers": None,
        "body": None,
        "error": error,
    }

def save_response(response: dict, output_dir: Path) -> None:
    url_id = hashlib.sha256(response["url"].encode()).hexdigest()
    outfile = output_dir / f"{url_id}.json"
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(response, f, indent=4)


async def process_urls(urls: list[str], output_dir: Path) -> tuple[int, int]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    total = len(urls)
    success = 0
    completed = 0

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=connector) as session:

        async def fetch_and_save(url: str) -> bool:
            async with semaphore:
                response = await fetch_url(session, url)
                save_response(response, output_dir)
                return response["success"]

        tasks = [fetch_and_save(url) for url in urls]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            if result:
                success += 1

            if completed % 500 == 0 or completed == total:
                print(f"  Progress: {completed}/{total} "
                      f"({success} successful, {completed - success} failed)")

    return total, success


def load_urls(csv_path: Path) -> list[str]:
    urls = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [name.lower() for name in reader.fieldnames]
        for row in reader:
            url = (row.get("url") or "").strip()
            if url:
                urls.append(url)
    return urls


def process_csv(csv_path: str) -> None:
    csv_path = Path(csv_path)
    output_dir = csv_path.parent / ("response_" + csv_path.stem)
    output_dir.mkdir(exist_ok=True, parents=True)

    print(f"Loading URLs from {csv_path}...")
    urls = load_urls(csv_path)
    print(f"Loaded {len(urls)} URLs. Starting fetch...\n")

    # Skip already-fetched URLs so you can resume interrupted runs
    existing = {f.stem for f in output_dir.glob("*.json")}
    urls = [u for u in urls if hashlib.sha256(u.encode()).hexdigest() not in existing]
    print(f"Skipping {len(existing)} already fetched. {len(urls)} remaining.\n")

    total, success = asyncio.run(process_urls(urls, output_dir))

    print("\n📊 Summary:")
    print(f"  Total:    {total}")
    print(f"  Success:  {success}")
    print(f"  Failed:   {total - success}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        try:
            process_csv(sys.argv[1])
        except KeyboardInterrupt:
            print("[Interrupted]")