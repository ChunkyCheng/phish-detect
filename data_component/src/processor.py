from pathlib import Path
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json
import re
from collections import defaultdict, Counter


# -------------------------
# Keyword sets
# -------------------------
LOGIN_KEYWORDS = {
	"login", "log in", "sign in", "password",
	"verify", "account", "authenticate", "secure"
}

BANK_KEYWORDS = {
	"bank", "credit card", "debit card",
	"payment", "billing", "paypal"
}

CRYPTO_KEYWORDS = {
	"bitcoin", "wallet", "crypto",
	"usdt", "ethereum", "seed phrase"
}

URGENCY_KEYWORDS = {
	"urgent", "immediately", "action required",
	"suspended", "locked", "expire", "verify now"
}


# -------------------------
# Phrase + ngram extraction
# -------------------------
def extract_ngrams(text, n=2, max_items=20):
	words = re.findall(r"[a-zA-Z]{3,}", text.lower())
	ngrams = zip(*[words[i:] for i in range(n)])
	counter = Counter([" ".join(g) for g in ngrams])
	return [w for w, _ in counter.most_common(max_items)]


def extract_keyword_hits(text, categories):
	text = text.lower()
	results = {}

	for cat, keywords in categories.items():
		hits = [k for k in keywords if k in text]

		if hits:
			results[cat] = {
				"count": len(hits),
				"matches": hits
			}

	return results  # <- IMPORTANT: no empty categories


# -------------------------
# URL analysis (stronger)
# -------------------------
def analyze_url(url):
	parsed = urlparse(url)

	domain = parsed.netloc.lower()
	path = parsed.path.lower()

	return {
		"domain": domain,
		"subdomain_count": domain.count("."),
		"uses_ip": bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)),
		"path_length": len(parsed.path),
		"query_length": len(parsed.query),
		"has_suspicious_tld": any(tld in domain for tld in [".tk", ".ml", ".cf", ".ga"]),
		"path_entropy_hint": len(set(path)) / (len(path) + 1)
	}


# -------------------------
# Script analysis (stronger behavioral detection)
# -------------------------
def analyze_scripts(soup):
	scripts = soup.find_all("script")

	inline_snippets = []
	external = []
	signals = set()

	for s in scripts:
		src = s.get("src")

		if src:
			external.append(src)
			continue

		content = (s.string or "").lower()
		if not content:
			continue

		inline_snippets.append(content[:200])

		# behavioral signals
		if "eval(" in content:
			signals.add("eval_usage")
		if "atob(" in content or "base64" in content:
			signals.add("base64_obfuscation")
		if "window.location" in content or "location.href" in content:
			signals.add("redirect_js")
		if "document.write" in content:
			signals.add("document_write")

	return {
		"script_count": len(scripts),
		"inline_script_count": len(inline_snippets),
		"external_script_count": len(external),
		"external_scripts": external[:10],
		"script_signals": list(signals)
	}


# -------------------------
# Form analysis (HIGH SIGNAL AREA)
# -------------------------
def analyze_forms(soup, base_domain):
	forms = soup.find_all("form")

	form_data = []
	external_posts = 0
	password_forms = 0

	for f in forms:
		action = f.get("action", "")
		method = f.get("method", "get").lower()

		inputs = f.find_all("input")
		types = defaultdict(int)

		has_password = False

		for i in inputs:
			t = i.get("type", "text").lower()
			types[t] += 1
			if t == "password":
				has_password = True

		if has_password:
			password_forms += 1

		is_external = False
		if action.startswith("http"):
			is_external = urlparse(action).netloc != base_domain

		if is_external:
			external_posts += 1

		form_data.append({
			"action": action,
			"method": method,
			"input_types": dict(types),
			"is_external_action": is_external,
			"has_password": has_password
		})

	return {
		"form_count": len(forms),
		"forms": form_data,
		"external_form_posts": external_posts,
		"password_forms": password_forms
	}


# -------------------------
# Main extractor
# -------------------------
def extract_features(json_path: Path) -> dict:
	with json_path.open("r", encoding="utf-8") as f:
		data = json.load(f)

	body = data.get("body", "")
	url = data.get("url", "")

	soup = BeautifulSoup(body, "html.parser")

	text = soup.get_text(" ", strip=True)

	base_domain = urlparse(url).netloc.lower()

	# core analysis
	url_features = analyze_url(url)
	form_features = analyze_forms(soup, base_domain)
	script_features = analyze_scripts(soup)

	# keyword signals (compact)
	keyword_text = text.lower()
	keywords = extract_keyword_hits(keyword_text, {
		"login": LOGIN_KEYWORDS,
		"financial": BANK_KEYWORDS,
		"crypto": CRYPTO_KEYWORDS,
		"urgency": URGENCY_KEYWORDS
	})

	# ngrams = VERY IMPORTANT for phishing phrasing detection
	bigrams = extract_ngrams(keyword_text, n=2)
	trigrams = extract_ngrams(keyword_text, n=3)

	links = soup.find_all("a", href=True)

	internal = 0
	external = 0

	for a in links:
		href = a["href"]
		if href.startswith("http"):
			if urlparse(href).netloc == base_domain:
				internal += 1
			else:
				external += 1
		else:
			internal += 1

	return {
		"url": url,
		"status_code": data.get("status_code"),

		# keep raw signal for future ML
		"text_sample": text[:8000],

		# URL structure
		"url_features": url_features,

		# content stats
		"visible_text_length": len(text),
		"word_count": len(text.split()),

		# link structure
		"link_count": len(links),
		"internal_links": internal,
		"external_links": external,

		# forms (critical)
		"forms": form_features,

		# scripts (behavioral)
		"scripts": script_features,

		# keyword + phrase intelligence
		"keywords": keywords,
		"bigrams": bigrams,
		"trigrams": trigrams,

		# compact risk signals (better than raw booleans only)
		"risk_score_inputs": {
			"has_password_forms": form_features["password_forms"] > 0,
			"external_form_post": form_features["external_form_posts"] > 0,
			"suspicious_scripts": len(script_features["script_signals"]) > 0,
			"urgent_language": "urgency" in keywords,
		}
	}


# -------------------------
# batch runner
# -------------------------
def process_all_jsons(input_dir):
	input_dir = Path(input_dir)
	output_dir = input_dir.parent / "processed"
	output_dir.mkdir(parents=True, exist_ok=True)

	for f in input_dir.iterdir():
		if f.is_file() and f.suffix == ".json":
			out = extract_features(f)
			with open(output_dir / f.name, "w", encoding="utf-8") as w:
				json.dump(out, w, indent=4)


if __name__ == "__main__":
	import sys
	if len(sys.argv) == 2:
		process_all_jsons(sys.argv[1])