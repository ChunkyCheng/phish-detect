# PhishShield
AI-powered phishing URL detection system that analyses live web pages using structural feature extraction and a two-pass Gemini AI pipeline.

---

## Project Overview

### Problem Statement
People click links in emails, WhatsApp, or social media without knowing if they're safe. Scam sites look legitimate such as fake bank pages, fake Shopee/Lazada deals, fake government portals. By the time they realise, they've already entered their IC number or bank details that can lead to credential theft and malware delivery.

Users need real-time analysis that evaluates a URL's structure and content, not just whether it appears on a known list.

### Target Users
Everyday users who receive a suspious link and want to verify a suspicious link before clicking.

### System Goal
Given any URL, PhishShield fetches the live page, extracts structural signals, and uses a two-stage Gemini AI pipeline to produce a human-readable verdict: **Safe**, **Suspicious**, or **Phishing** — with a risk score and plain-English explanation.

---

## System Architecture

### Data Flow
```
User submits URL
        ↓
[Fetcher] — live HTTP fetch via aiohttp
        ↓
[Processor] — extract structural features (scripts, forms, links, TLD, etc.)
        ↓
[Gemini Step 1: is_suspicious()] — structural verdict only
        ↓ (if suspicious)
[Similarity Search] — query phishing corpus (SQLite vector DB)
        ↓
[Gemini Step 2: explain_with_context()] — final risk summary with corpus context
        ↓
JSON response — Frontend renders verdict card
```

### Module Breakdown
```
phishing_w4/
├── backend/
│   └── src/
│       ├── data_component/
│       │   ├── fetcher.py          
│       │   ├── processor.py        
│       │   ├── similarity_match.py 
│       │   ├── crawler.py          
│       │   ├── filter.py           
│       │   ├── loader.py           
│       │   └── audit.py            
│       ├── app.py                  
│       └── gemini_prompt.py 
├── frontend/
│   └── src/
│       ├── templates/
│       │   └── checker_page.html   
│       └── app.py                  
├── .env.example                    
├── docker-compose.yml              
└── README.md
```

---

## Setup & Installation

### Prerequisites
- `Python` version 3.14.*
- `uv` version 0.8.*
- Gemini API key
- `Docker Desktop` installed and running

### Setup Instructions
1. **Clone the repository**
```
git clone <your-repo-url>
cd phishing_w4
```
2. **Configure environment variables**
  **backend/.env**
  Copy the example env file and fill in your values:
```
cp backend/.env.example backend/.env
```
  Edit backend/.env:
```
GEMINI_API_KEY=your_gemini_api_key_here
DB_PATH=src/week_2/data/resources/your-db.db
```

**frontend/.env**
  BACKEND_URL=http://localhost:8001

3. **Add the required data file**
  Place the phishing_site database inside the DB_PATH
4. **Build and run**
```
docker compose up --build   # first time or after code changes
docker compose up           # subsequent runs (no code changes)
```

## Features

**ETL Pipeline**

1. `uv run src/fetcher.py <url CSV file>`
  Fetches responses from a list of urls

2. `uv run src/filter.py <response directory created by fetcher>`
  Filters good and bad data for usage

3. `uv run src/audit <directory to good data>`
  Gives a summary of page names to help fine tune filtering

4. `uv run src/processor.py <directory to good data>`
  Converts response htmls to a json of features

5. `uv run src/loader.py <directory to processed data>` 
  Loads features in json format into SQLite database

6. `uv run src/similarity_match.py <path to database> <feature.json>`
  Checks the input features against the database


## Technical Decisions
1. **Two-pass AI pipeline**
  - (Step 1) Structural verdict: return early for safe URLs
  - (Step 2) Human-readable explanation: return final summary

2. **Numeric/boolean features only for Step 1**
  - numeric_bool_only() filter strips all strings from the feature dict before passing to Gemini. 
  - prevents the model from being biased by brand names or domain strings (e.g. seeing "paypal" in the URL and calling it phishing without structural evidence).

**Trade-offs**

- Live fetching means dead phishing URLs (already taken down) cannot be fully analysed — only their URL structure is available to Step 1
- The corpus only covers phishing patterns collected during the project — novel attack techniques may not match

## Limitations
**Known Issues**
1. Dead phishing URLs
  - phishing sites are frequently taken down within hours of going live.
2. Google/legitimate infrastructure hosting 
  - phishing pages hosted on docs.google.com, sites.google.com, or similar legitimate domains score low on structural similarity compared to typical phishing URLs.
3. Gemini output variability
  - LLM responses are non-deterministic. 
  - the same URL checked twice may produce slightly different risk scores or reason wording.

**Future Improvements**
- Cache recent results to reduce Gemini API calls for repeated URLs
- Expand the corpus with regularly updated phishing feeds (e.g. PhishTank)