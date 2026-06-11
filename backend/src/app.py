import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from gemini_prompt import is_suspicious, explain_with_context
from data_component.fetcher import fetch_single_url
from data_component.processor import extract_features
from data_component.similarity_match import query_dataset

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
            error = raw.get("error", "unknown")

            if "timeout" in str(error):
                status = "Connection timed out"
            elif "dns" in str(error).lower() or "resolve" in str(error).lower():
                status = "Domain does not exist"
            else:
                status = "Website unreachable"
            return JSONResponse(
                {
                    "verdict": "unreachable",
                    "risk_score": None,
                    "reasons": [
                        f"{status} — PhishShield could not fetch this page.",
                        "No phishing analysis was performed.",
                        "Tip: Check the URL is correct and the site is online.",
                    ],
                },
            )

        features = extract_features(raw)

        # Step 2: AI verdict on structure alone
        step1 = is_suspicious(request.url, features)
        if not step1.get("suspicious"):
            # Safe — return early, no need to query corpus
            return JSONResponse(
                {
                    "verdict": "safe",
                    "risk_score": step1.get("confidence", 10),
                    "reasons": step1.get(
                        "reasons", ["No suspicious signals detected."]
                    ),
                }
            )

        # Step 3: query corpus for brand-specific phishing patterns
        similarity_context = query_dataset(os.getenv("DB_PATH"), features)

        # Combine: Step 1 AI confidence (60%) + corpus signal score (40%)
        step1_confidence = step1.get("confidence", 50)
        corpus_score = similarity_context.score * 100
        combined_risk = int(0.6 * step1_confidence + 0.4 * corpus_score)

        # check calculation
        print(
            f"[Score] step1_confidence={step1_confidence} | "
            f"corpus_score={corpus_score:.1f} | "
            f"combined_risk={combined_risk}",
            flush=True,
        )

        # Step 4: enrich verdict with corpus context
        result = explain_with_context(
            request.url, similarity_context, step1.get("reasons", []), combined_risk
        )
        return JSONResponse(result)

    except Exception as e:
        err = str(e)
        if "503" in err or "UNAVAILABLE" in err:
            msg = "AI service is temporarily busy — please try again in a moment."
        elif "500" in err or "INTERNAL" in err:
            msg = "AI service encountered an error — please try again."
        elif "401" in err or "403" in err:
            msg = "API key error — check your GEMINI_API_KEY configuration."
        else:
            msg = "An unexpected error occurred — please try again."
        return JSONResponse(
            {"verdict": "unreachable", "risk_score": None, "reasons": [msg]},
            status_code=200,
        )
