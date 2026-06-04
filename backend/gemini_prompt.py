from google import genai
import json
import os
from dotenv import load_dotenv

load_dotenv()

# get api key
api_key = os.getenv("GEMINI_API_KEY")

# like personal connection to google ai service
client = genai.Client(api_key=api_key)

model = "gemma-4-26b-a4b-it"


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

    prompt = f"""
        You are a cybersecurity expert analysing a URL for phishing risk.
        
        URL submitted: {url}
        
        Extracted structural signals (no raw page text — evaluate structure only):
        {json.dumps(signals, indent=2)}
        
        Based ONLY on these structural signals, decide if this URL is suspicious or phishing.
        Do NOT judge based on brand names in the URL string alone.
        Return ONLY valid JSON:
        {{
        "suspicious": true or false,
        "confidence": 0-100,
        "reasons": ["one-line reason 1", "one-line reason 2"]
        }}
    """
    return json.loads(call(prompt))


# gemini second call
def explain_with_context(url: str, similarity_context: str) -> dict:
    """
    Second-pass: produce human-readable verdict from similarity report alone.
    similarity_context is the full formatted string from similarity_match.
    """
    prompt = f"""
        You are a cybersecurity expert writing a phishing analysis report for a non-technical user.

        URL submitted: {url}

        Similarity report from known phishing corpus:
        {similarity_context}

        Using this report, produce a final verdict.
        Explain in plain English WHY this URL is or isn't dangerous, referencing the specific signals above.

        Return ONLY valid JSON:
        {{
        "verdict": "safe" or "suspicious" or "phishing",
        "risk_score": 0-100,
        "reasons": [
            "Plain-English explanation referencing a specific signal",
            "Plain-English explanation referencing another signal"
        ]
        }}
    """
    return json.loads(call(prompt))
