from google import genai
import json
import os
from dotenv import load_dotenv

load_dotenv()

# get api key
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    import sys

    print(
        "\n[PhishShield] ERROR: GEMINI_API_KEY is not set.\n",
        file=sys.stderr,
        flush=True,
    )
    sys.exit(1)

# like personal connection to google ai service
client = genai.Client(api_key=api_key)

model = "gemini-2.5-flash"  # "gemma-4-31b-it"  # "gemma-4-26b-a4b-it"


def call(prompt: str) -> str:
    response = client.models.generate_content(model=model, contents=prompt)
    return response.text.strip().removeprefix("```json").removesuffix("```").strip()


def numeric_bool_only(obj, _depth=0):
    """Recursively keep only numeric/boolean fields — drop strings and lists of strings."""
    if _depth > 5:  # against calling recursively
        return None
    if isinstance(obj, bool):  # bool before int — bool is subclass of int in Python
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, dict):
        filtered = {k: numeric_bool_only(v, _depth + 1) for k, v in obj.items()}
        return {k: v for k, v in filtered.items() if v is not None}
    return None  # string, list, None → dropped automatically


# gemini first call
def is_suspicious(url: str, features: dict) -> dict:
    """
    First-pass verdict using structural features only.
    Returns {"suspicious": bool, "confidence": 0-100, "reasons": [...]}
    """
    signals = numeric_bool_only(features)

    # Step 1 is structural analysis only — strip content/keyword fields
    # (keywords + phrases belong in Step 2 where corpus context disambiguates)
    for key in ("keywords", "bigrams", "trigrams", "text_sample"):
        signals.pop(key, None)

    print(f"[Step 1] Calling Gemini for: {url}", flush=True)  # checking purpose

    prompt = f"""
        You are a cybersecurity expert analysing a URL for phishing risk.
        
        URL submitted: {url}

        Extracted structural signals (no raw page text — evaluate structure only):
        {json.dumps(signals, indent=2)}
        
        SIGNAL WEIGHTS — apply these strictly:

        STRONG signals (each alone can raise confidence significantly):
        - URL uses IP address instead of domain name
        - Excessive subdomains (3+) mimicking a brand
        - Subdomain contains brand name impersonation (e.g. "sign-inmeta2", "paypa1-secure", "google-verify")
        - Legitimate brand name embedded in subdomain of a free hosting platform (godaddysites.com, sites.google.com, weebly.com)
        - URL contains encoded characters or obfuscation (%20, hex sequences)
        - Domain uses deceptive TLD combinations (brand-name.xyz, brand-name.top)
        - Form submits data to an external domain (external_form_post is true)
        - Random-looking or auto-generated subdomain (alphanumeric string like qontomsg07, abc123x) hosted on a free platform (web.app, godaddysites.com, sites.google.com, netlify.app, weebly.com, github.io)
        - Extremely sparse page (word_count under 80) with zero scripts and zero forms — typical of a stripped-down lure or redirect page

        WEAK signals (require 3+ together to matter; alone they mean nothing):
        - urgent_language is true in risk_score_inputs
        - External links exceed internal links significantly
        - Very short visible text (word_count under 100) — sparse lure page
        - High inline script count combined with zero forms

        Based on the URL string AND these structural signals, decide if this URL is suspicious.
        Set "suspicious": true if confidence >= 70, false otherwise.
        
        Return ONLY valid JSON:
        {{
        "suspicious": true or false,
        "confidence": a 0-100 integer:
            - 90-100 = multiple STRONG phishing signals present
            - 70-89  = at least one STRONG signal, or 3+ WEAK signals together
            - 50-69  = only WEAK signals, inconclusive
            - below 50 = minimal or no meaningful signals
        "reasons": ["one-line reason 1", "one-line reason 2"]
        }}
    """
    result = json.loads(call(prompt))
    print(
        f"[Step 1] OK — suspicious={result.get('suspicious')}, confidence={result.get('confidence')}",
        flush=True,
    )
    print(f"[Step 1] Signals: {json.dumps(signals, indent=2)}", flush=True)  # check
    return result


# gemini second call
def explain_with_context(
    url: str, similarity_context: str, step1_reasons: list[str], risk_score: int
) -> dict:
    """
    Second-pass: Given we already know this URL is suspicious, explain it with corpus context.
    """
    reasons_text = (
        "\n".join(f"- {r}" for r in step1_reasons)
        if step1_reasons
        else "No specific reasons captured."
    )
    print(f"[Step 2] Calling Gemini for: {url}", flush=True)  # checking purpose
    print(
        f"[Step 2] Similarity context length: {len(str(similarity_context))}",
        flush=True,
    )  # checking purpose

    prompt = f"""
        You are a phishing analyst. A URL has already been flagged as SUSPICIOUS by structural analysis.

        URL: {url}

        The structural analysis flagged it for these reasons:
        {reasons_text}

        Similarity report from known phishing corpus:
        {similarity_context}

        Your job is to write a clear, human-readable explanation of WHY this URL is dangerous,
        combining the structural signals above with any corpus context.

        Return ONLY valid JSON:
        {{
        "verdict": "suspicious" or "phishing",
        "reasons": [
            "Plain-English explanation 1",
            "Plain-English explanation 2"
        ]
        }} Keep reasons short (one sentence each)
        IMPORTANT: Only return "phishing" if the corpus similarity score is high (above 50) 
        AND Step 1 found multiple strong structural signals together.
        If corpus similarity is low or Step 1 signals are weak, return "suspicious" at most.
        "phishing" means high confidence — do not use it for borderline cases.
    """
    result = json.loads(call(prompt))
    result["risk_score"] = risk_score  # inject calculated score from backend firmula
    print(
        f"[Step 2] OK — verdict={result.get('verdict')}, risk_score={risk_score}",
        flush=True,
    )  # checking purpose
    return result
