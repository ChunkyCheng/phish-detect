import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).parent.parent)
)  # adds phishing_w4/ to Python path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from gemini_prompt import is_suspicious, explain_with_context
from data_component.src.fetcher import fetch_single_url
from data_component.src.processor import extract_features
from data_component.src.similarity_match import query_dataset

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CheckRequest(BaseModel):
    url: str


@app.post("/check")
async def check_url(request: CheckRequest):
    try:
        # Step 1: fetch + extract features
        raw = await fetch_single_url(request.url)

        # fetch failure check
        if not raw.get("success") or raw.get("body") is None:
            return JSONResponse(
                {
                    "verdict": "suspicious",
                    "risk_score": 40,  # non-zero, signals something's off
                    "reasons": [
                        f"Could not reach the URL: {raw.get('error', 'unknown error')}",
                        "Unreachable URLs are commonly associated with taken-down phishing sites",
                    ],
                },
                status_code=200,
            )

        features = extract_features(raw)

        # Step 2: AI verdict on structure alone
        step1 = is_suspicious(request.url, features)
        if not step1.get("suspicious"):
            # Safe — return early, no need to query corpus
            return JSONResponse(
                {
                    "verdict": "safe",
                    "risk_score": max(0, 100 - step1.get("confidence", 90)),
                    "reasons": step1.get(
                        "reasons", ["No suspicious signals detected."]
                    ),
                }
            )

        # Step 3: query corpus for brand-specific phishing patterns
        similarity_context = query_dataset(request.url, features)
        similarity_context = []  # ← placeholder until partner's function is ready

        # Step 4: enrich verdict with corpus context
        result = explain_with_context(request.url, similarity_context)
        return JSONResponse(result)

    except Exception as e:
        return JSONResponse(
            {"verdict": "error", "risk_score": 0, "reasons": [str(e)]}, status_code=500
        )
