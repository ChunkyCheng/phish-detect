"""
dataset_query.py
----------------
Queries the phishing_sites SQLite database to retrieve contextual intelligence
for a submitted URL's extracted features.
"""

import sqlite3
import json
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SimilarityResult:
    """
    Summarised similarity report for a submitted URL against the phishing corpus.

    score         – 0.0–1.0 composite similarity (higher = more kit-like)
    matched_signals – ordered list of (signal_name, detail) tuples that
                      contributed to the score, most impactful first
    corpus_matches  – number of corpus entries matched
    error           – set if something went wrong, None otherwise
    """
    score: float
    matched_signals: list          # list of {"signal": str, "detail": str, "weight": float}
    corpus_matches: int
    error: Optional[str] = None

    def summary(self) -> str:
        """Human-readable one-block summary."""
        if self.error:
            return f"Error: {self.error}"
        lines = [
            f"Similarity score : {self.score:.2f} / 1.00",
            f"Corpus matches   : {self.corpus_matches}",
            "",
            "Contributing signals:",
        ]
        if not self.matched_signals:
            lines.append("  (none)")
        for s in self.matched_signals:
            lines.append(f"  [{s['weight']:+.2f}]  {s['signal']}: {s['detail']}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# N-gram parsing — handles both JSON arrays and plain comma-separated strings
# ---------------------------------------------------------------------------

def parse_ngrams(raw) -> list:
    """
    Robustly parse ngrams stored as either:
      - JSON array:  '["home menu", "menu indicates"]'
      - CSV string:  'home menu,menu indicates,indicates required'
                     (with or without spaces after commas)
      - Already a list (passed programmatically)
      - None / empty string → returns []
    """
    if not raw:
        return []
    if isinstance(raw, list):
        # Filter out any blank entries that may have crept in
        return [item for item in raw if item and str(item).strip()]

    raw = raw.strip()
    if not raw:
        return []

    # Try JSON first (arrays only — ignore bare JSON scalars)
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass  # fall through to CSV split

    # Plain comma-separated string (the primary DB format)
    # Strip surrounding quotes that SQLite sometimes preserves
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]

    return [item.strip() for item in raw.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Brand extraction
# ---------------------------------------------------------------------------

KNOWN_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram",
    "netflix", "linkedin", "dropbox", "zoho", "outlook", "office365", "onedrive",
    "office 365", "sharepoint", "teams",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
    "metamask", "coinbase", "binance", "kraken",
    "att", "verizon", "tmobile", "comcast",
    "dhl", "fedex", "ups", "usps",
    "docusign", "adobe", "webmail", "cpanel", "roundcube",
    "yahoo", "hotmail", "icloud",
    "halifax", "lloyds", "natwest", "santander",
]

# Hosting providers to detect in domains
HOSTING_PROVIDERS = {
    "ipfs":         ["ipfs.dweb.link", "ipfs.io", "dweb.link", "cf-ipfs.com"],
    "google_sites": ["sites.google.com", "docs.google.com", "drive.google.com"],
    "weebly":       ["weebly.com"],
    "wix":          ["wix.com", "wixsite.com"],
    "wordpress":    ["wordpress.com", "wp.com"],
    "github_pages": ["github.io"],
    "netlify":      ["netlify.app"],
    "vercel":       ["vercel.app"],
    "firebase":     ["firebaseapp.com", "web.app"],
    "glitch":       ["glitch.me"],
    "replit":       ["repl.co", "replit.app"],
    "blogspot":     ["blogspot.com"],
    "squarespace":  ["squarespace.com"],
    "godaddy":      ["godaddysites.com"],
}


def detect_hosting_provider(domain: str) -> str:
    domain = (domain or "").lower()
    for provider, patterns in HOSTING_PROVIDERS.items():
        if any(p in domain for p in patterns):
            return provider
    return "unknown"


def extract_brand_terms(feature_json: dict) -> list:
    """
    Extract brand names from a feature JSON.
    Checks text_sample, domain, and n-grams.
    """
    brands_found = []

    sources = [
        (feature_json.get("text_sample") or "").lower(),
        (feature_json.get("url_features", {}).get("domain") or "").lower(),
        (feature_json.get("domain") or "").lower(),   # flat schema fallback
        " ".join(parse_ngrams(feature_json.get("bigrams") or [])),
        " ".join(parse_ngrams(feature_json.get("trigrams") or [])),
    ]
    combined = " ".join(sources)

    for brand in KNOWN_BRANDS:
        if brand in combined and brand not in brands_found:
            brands_found.append(brand)

    return brands_found


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for f in ("external_scripts", "script_signals",
              "login_keyword_matches", "bigrams", "trigrams"):
        if f in d:
            d[f] = parse_ngrams(d[f])   # normalise CSV → list for all callers
    return d


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def query_by_brand(db_path: str, brand_terms: list, limit: int = 50) -> list:
    if not brand_terms:
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    clauses, params = [], []
    for term in brand_terms[:3]:
        for col in ("text_sample", "domain", "bigrams", "trigrams"):
            clauses.append(f"LOWER({col}) LIKE ?")
            params.append(f"%{term}%")

    query = f"SELECT * FROM phishing_sites WHERE {' OR '.join(clauses)} LIMIT ?"
    params.append(limit)

    try:
        cur.execute(query, params)
        rows = [_row_to_dict(r) for r in cur.fetchall()]
    except sqlite3.Error as e:
        conn.close()
        raise RuntimeError(f"DB query failed: {e}") from e

    conn.close()
    return rows


def query_by_ngram_overlap(db_path: str, trigrams: list,
                            min_overlap: int = 2, limit: int = 20) -> list:
    """
    Find DB rows whose trigram CSV string contains at least one of the
    submitted trigrams, then rank by overlap count ≥ min_overlap.

    Because trigrams are plain CSV in the DB (e.g. "foo bar,bar baz,baz qux"),
    we build LIKE clauses that match the token at any position in the string:
      • mid / end  →  LIKE '%, foo bar%'
      • start      →  LIKE 'foo bar,%'
      • only token →  LIKE 'foo bar'      (exact equality handled by the others)
    This avoids false positives where "log" would match "login" etc.
    """
    if not trigrams:
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Use up to 10 trigrams for the initial DB filter
    sample = list(trigrams)[:10]

    clauses, params = [], []
    for t in sample:
        t_escaped = t.replace("%", r"\%").replace("_", r"\_")
        # Match as first token, middle/last token (all preceded by ", ")
        clauses.append("(LOWER(trigrams) LIKE ? OR LOWER(trigrams) LIKE ?)")
        params.extend([f"{t_escaped},%", f"%, {t_escaped}%"])

    sql = f"SELECT * FROM phishing_sites WHERE {' OR '.join(clauses)} LIMIT 200"

    try:
        cur.execute(sql, params)
        rows = [_row_to_dict(r) for r in cur.fetchall()]
    except sqlite3.Error as e:
        conn.close()
        raise RuntimeError(f"DB query failed: {e}") from e

    conn.close()

    # Exact set intersection now that tokens are proper lists
    trigram_set = set(trigrams)
    scored = []
    for row in rows:
        row_trigrams = set(row.get("trigrams") or [])
        overlap = trigram_set & row_trigrams
        if len(overlap) >= min_overlap:
            row["_ngram_overlap_count"] = len(overlap)
            row["_overlapping_ngrams"] = list(overlap)
            scored.append(row)

    scored.sort(key=lambda r: r["_ngram_overlap_count"], reverse=True)
    return scored[:limit]


# ---------------------------------------------------------------------------
# Scoring weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
#
# Each signal is evaluated against the matched corpus rows, producing a
# 0–1 sub-score that is multiplied by its weight and summed into the final
# composite score.
#
SIGNAL_WEIGHTS = {
    "brand_match":      0.25,   # submitted URL targets a known brand in the corpus
    "ngram_overlap":    0.25,   # trigram text is similar to known kit text
    "password_forms":   0.20,   # credential-harvesting form presence
    "external_post":    0.15,   # form posts to an off-domain endpoint
    "urgency_language": 0.10,   # urgent / threatening copy
    "script_signals":   0.05,   # obfuscation / redirect JS patterns
}


# ---------------------------------------------------------------------------
# Aggregation + scoring
# ---------------------------------------------------------------------------

def aggregate_corpus_intelligence(brand_terms, brand_rows,
                                   ngram_rows, submitted_trigrams) -> SimilarityResult:
    all_rows = {r["url"]: r for r in brand_rows + ngram_rows}
    all_rows_list = list(all_rows.values())
    total = len(all_rows_list)

    if total == 0:
        return SimilarityResult(score=0.0, matched_signals=[], corpus_matches=0)

    def get_col(row, *keys):
        for k in keys:
            if row.get(k):
                return row[k]
        return 0

    # --- per-signal sub-scores (each 0.0–1.0) ---

    signals = []

    # 1. Brand match
    if brand_terms:
        sub = 1.0   # presence of any known brand is a binary hit
        signals.append({
            "signal":  "brand_match",
            "detail":  f"matched brand(s): {', '.join(brand_terms)}",
            "weight":  round(sub * SIGNAL_WEIGHTS["brand_match"], 3),
            "_raw":    sub,
        })

    # 2. Trigram / ngram overlap
    submitted_set = set(submitted_trigrams)
    corpus_tgram_freq: dict[str, int] = {}
    for row in all_rows_list:
        for t in (row.get("trigrams") or []):
            if t in submitted_set:
                corpus_tgram_freq[t] = corpus_tgram_freq.get(t, 0) + 1

    if corpus_tgram_freq:
        top_overlapping = sorted(corpus_tgram_freq, key=lambda t: corpus_tgram_freq[t], reverse=True)[:5]
        # sub-score: fraction of submitted trigrams seen in corpus, capped at 1
        overlap_ratio = min(len(corpus_tgram_freq) / max(len(submitted_set), 1), 1.0)
        signals.append({
            "signal":  "ngram_overlap",
            "detail":  f"{len(corpus_tgram_freq)} shared trigram(s): {', '.join(f'\"{t}\"' for t in top_overlapping)}",
            "weight":  round(overlap_ratio * SIGNAL_WEIGHTS["ngram_overlap"], 3),
            "_raw":    overlap_ratio,
        })

    # 3. Password forms
    pw_rate = sum(1 for r in all_rows_list if get_col(r, "password_forms", "forms.has_password")) / total
    if pw_rate > 0:
        signals.append({
            "signal":  "password_forms",
            "detail":  f"present in {pw_rate:.0%} of matched corpus entries",
            "weight":  round(pw_rate * SIGNAL_WEIGHTS["password_forms"], 3),
            "_raw":    pw_rate,
        })

    # 4. External form post
    ext_rate = sum(1 for r in all_rows_list if get_col(r, "external_form_posts", "external_form_post")) / total
    if ext_rate > 0:
        signals.append({
            "signal":  "external_post",
            "detail":  f"form exfiltrates data off-domain in {ext_rate:.0%} of matches",
            "weight":  round(ext_rate * SIGNAL_WEIGHTS["external_post"], 3),
            "_raw":    ext_rate,
        })

    # 5. Urgency language
    urgency_rate = sum(1 for r in all_rows_list if r.get("urgent_language")) / total
    if urgency_rate > 0:
        signals.append({
            "signal":  "urgency_language",
            "detail":  f"urgent/threatening copy in {urgency_rate:.0%} of matches",
            "weight":  round(urgency_rate * SIGNAL_WEIGHTS["urgency_language"], 3),
            "_raw":    urgency_rate,
        })

    # 6. Script signals
    signal_counts: dict[str, int] = {}
    for row in all_rows_list:
        for sig in (row.get("script_signals") or []):
            signal_counts[sig] = signal_counts.get(sig, 0) + 1
    if signal_counts:
        top_sigs = sorted(signal_counts, key=lambda s: signal_counts[s], reverse=True)[:3]
        # sub-score: fraction of rows with any script signal
        rows_with_sig = sum(1 for r in all_rows_list if r.get("script_signals")) / total
        signals.append({
            "signal":  "script_signals",
            "detail":  f"JS patterns ({', '.join(top_sigs)}) in {rows_with_sig:.0%} of matches",
            "weight":  round(rows_with_sig * SIGNAL_WEIGHTS["script_signals"], 3),
            "_raw":    rows_with_sig,
        })

    # --- composite score ---
    composite = min(sum(s["weight"] for s in signals), 1.0)

    # Sort by contribution descending, strip internal _raw key
    signals.sort(key=lambda s: s["weight"], reverse=True)
    for s in signals:
        s.pop("_raw", None)

    return SimilarityResult(
        score=round(composite, 3),
        matched_signals=signals,
        corpus_matches=total,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def query_dataset(db_path: str, feature_json: dict) -> SimilarityResult:
    """
    Main entry point.
    Args:
        db_path:      path to phishing_sites.db
        feature_json: extracted features of the submitted URL (same schema as dataset)
    Returns:
        SimilarityResult with a 0–1 score and a list of contributing signals
    """
    db_path = str(Path(db_path).resolve())
    if not Path(db_path).exists():
        print(f"Database not found at {db_path}")
        return SimilarityResult(
            score=0.0, matched_signals=[], corpus_matches=0,
            error=f"Database not found: {db_path}",
        )
    else:
        print(f"Using database at {db_path}")

    brand_terms = extract_brand_terms(feature_json)

    brand_rows = []
    if brand_terms:
        try:
            brand_rows = query_by_brand(db_path, brand_terms)
        except RuntimeError as e:
            return SimilarityResult(
                score=0.0, matched_signals=[], corpus_matches=0,
                error=str(e),
            )

    # parse_ngrams handles CSV string or list transparently
    submitted_trigrams = parse_ngrams(feature_json.get("trigrams") or [])
    ngram_rows = []
    try:
        ngram_rows = query_by_ngram_overlap(db_path, submitted_trigrams)
    except RuntimeError:
        pass

    return aggregate_corpus_intelligence(
        brand_terms=brand_terms,
        brand_rows=brand_rows,
        ngram_rows=ngram_rows,
        submitted_trigrams=submitted_trigrams,
    )


# ---------------------------------------------------------------------------
# CLI / debug
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        # Normal mode: python dataset_query.py db.db features.json
        with open(sys.argv[2]) as f:
            features = json.load(f)
        result = query_dataset(sys.argv[1], features)
        print(result.summary())

    elif len(sys.argv) == 2:
        # Debug mode: python dataset_query.py db.db
        # Shows what brand terms would be extracted from a few real DB rows
        db = sys.argv[1]
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT url, domain, text_sample, bigrams, trigrams FROM phishing_sites LIMIT 5")
        for row in cur.fetchall():
            fake_json = {
                "text_sample": row["text_sample"],
                "domain": row["domain"],
                "bigrams": parse_ngrams(row["bigrams"]),
                "trigrams": parse_ngrams(row["trigrams"]),
            }
            brands = extract_brand_terms(fake_json)
            print(f"\nURL:     {row['url']}")
            print(f"Domain:  {row['domain']}")
            print(f"Brands:  {brands}")
            print(f"Trigrams (parsed): {parse_ngrams(row['trigrams'])[:5]}")
        conn.close()
    else:
        print("Usage:")
        print("  python dataset_query.py <db> <features.json>   # full query")
        print("  python dataset_query.py <db>                   # debug brand extraction")