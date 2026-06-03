import logging
import requests
import csv
from pathlib import Path
import json
import hashlib
from processor import extract_features

def fetch_url(url, timeout=5):
	try:
		response = requests.get(
			url,
			timeout=timeout,
			allow_redirects=True,
			headers={
				"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
			}
		)

		return {
            "url": url,
			"success": True,
			"status_code": response.status_code,
			"headers": dict(response.headers),
			"body": response.text,
			"error": None
		}

	except requests.exceptions.Timeout:
		return {
            "url": url,
			"success": False,
			"status_code": None,
			"headers": None,
			"body": None,
			"error": "timeout"
		}

	except requests.exceptions.RequestException as e:
		return {
            "url": url,
			"success": False,
			"status_code": None,
			"headers": None,
			"body": None,
			"error": str(e)
		}

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        exit()
    outfile = Path("test.json")
    response = fetch_url(sys.argv[1])
    with open(outfile, "w", encoding="utf-8") as file:
        json.dump(response, file, indent=4)
    processed = extract_features(outfile)
    with open(outfile, "w", encoding="utf-8") as file:
        json.dump(processed, file, indent=4)
