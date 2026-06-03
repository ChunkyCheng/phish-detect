from pathlib import Path
import json
import math
from collections import Counter


# -------------------------
# Helpers
# -------------------------
def jaccard(a, b):
    set_a = set(a)
    set_b = set(b)
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def cosine_numeric(a, b, keys):
    num = 0
    den_a = 0
    den_b = 0

    for k in keys:
        va = float(a.get(k, 0))
        vb = float(b.get(k, 0))

        num += va * vb
        den_a += va * va
        den_b += vb * vb

    if den_a == 0 or den_b == 0:
        return 0.0

    return num / (math.sqrt(den_a) * math.sqrt(den_b))


def safe_get(d, path, default=0):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p, {})
    return cur if cur != {} else default


# -------------------------
# Feature extraction from stored JSON
# -------------------------
def flatten_features(sample):
    return {
        # numeric structure signals
        "visible_text_length": sample.get("visible_text_length", 0),
        "word_count": sample.get("word_count", 0),
        "link_count": sample.get("link_count", 0),
        "internal_links": sample.get("internal_links", 0),
        "external_links": sample.get("external_links", 0),
        "iframe_count": sample.get("iframe_count", 0),

        # URL signals
        "subdomain_count": safe_get(sample, ["url_features", "subdomain_count"], 0),
        "uses_ip": 1 if safe_get(sample, ["url_features", "uses_ip"], False) else 0,

        # form signals
        "form_count": safe_get(sample, ["forms", "form_count"], 0),
        "external_form_posts": safe_get(sample, ["forms", "external_form_posts"], 0),

        # script signals
        "script_count": safe_get(sample, ["scripts", "script_count"], 0),
        "inline_script_count": safe_get(sample, ["scripts", "inline_script_count"], 0),
        "external_script_count": safe_get(sample, ["scripts", "external_script_count"], 0),

        # risk flags
        "has_password": 1 if safe_get(sample, ["risk_hints", "has_password_field"], False) else 0,
        "external_form_post": 1 if safe_get(sample, ["risk_hints", "external_form_post"], False) else 0,
        "redirect_js": 1 if safe_get(sample, ["risk_hints", "has_redirect_js"], False) else 0,

        # keyword presence (flattened)
        "login_hits": safe_get(sample, ["keywords", "login_family", "login", "count"], 0),
        "bank_hits": safe_get(sample, ["keywords", "financial_family", "bank", "count"], 0),
        "crypto_hits": safe_get(sample, ["keywords", "crypto_family", "crypto", "count"], 0),
        "urgency_hits": safe_get(sample, ["keywords", "urgency_family", "urgency", "count"], 0),

        # text signature (cheap similarity proxy)
        "bigrams": sample.get("bigrams", []),
        "trigrams": sample.get("trigrams", []),
    }


# -------------------------
# similarity function
# -------------------------
def similarity(a, b):
    # numeric similarity
    num_keys = [
        "visible_text_length",
        "word_count",
        "link_count",
        "internal_links",
        "external_links",
        "iframe_count",
        "subdomain_count",
        "uses_ip",
        "form_count",
        "external_form_posts",
        "script_count",
        "inline_script_count",
        "external_script_count",
        "has_password",
        "external_form_post",
        "redirect_js",
        "login_hits",
        "bank_hits",
        "crypto_hits",
        "urgency_hits",
    ]

    numeric_sim = cosine_numeric(a, b, num_keys)

    # structural similarity
    bigram_sim = jaccard(a.get("bigrams", []), b.get("bigrams", []))
    trigram_sim = jaccard(a.get("trigrams", []), b.get("trigrams", []))

    # weighted final score
    score = (
        0.55 * numeric_sim +
        0.25 * bigram_sim +
        0.20 * trigram_sim
    )

    return score


# -------------------------
# main checker
# -------------------------
def load_dataset(json_dir):
    json_dir = Path(json_dir)
    data = []

    for f in json_dir.iterdir():
        if f.suffix != ".json":
            continue

        with f.open("r", encoding="utf-8") as file:
            raw = json.load(file)

        data.append({
            "path": str(f),
            "features": flatten_features(raw)
        })

    return data


def find_similar(json_dir, query_dict, top_k=5):
    dataset = load_dataset(json_dir)
    query_features = flatten_features(query_dict)

    scored = []

    for item in dataset:
        score = similarity(query_features, item["features"])
        scored.append((score, item["path"]))

    scored.sort(reverse=True, key=lambda x: x[0])

    return scored[:top_k]


# -------------------------
# usage example
# -------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        exit()

    json_dir = sys.argv[1]

    # example query (replace with real input)
    with open(sys.argv[2], "r") as input_path:
        query = json.load(input_path)

    results = find_similar(json_dir, query)

    for score, path in results:
        print(f"{score:.4f} -> {path}")