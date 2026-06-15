# Site Sentinel AI - Project Analysis Report

## Overview

**Site Sentinel AI** is a Chrome browser extension (Manifest V3) with a Python FastAPI backend that analyzes websites for privacy risks, phishing indicators, tracking behavior, and overall safety using **Google Gemini 2.5 Flash AI**. It acts as a real-time web safety scanner providing users with actionable insights before they interact with a page.

---

## Project Structure

```
Global-Tech-2026-Hackathon-main/
├── manifest.json          # Chrome extension manifest (v3)
├── background.js          # Service worker - network telemetry collection
├── content.js             # Content script - DOM/page analysis
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic & backend communication
└── backend/
    ├── app.py             # FastAPI server (main entry point)
    ├── scorer.py          # Heuristic rule-based pre-scoring engine
    ├── prompts.py         # Gemini AI prompt template
    ├── requirements.txt   # Python dependencies
    └── .env               # Gemini API key (not committed)
```

---

## Architecture & Data Flow

### Client-Server Hybrid Architecture

```
User opens extension popup
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  Chrome Extension (Client)                              │
│                                                         │
│  popup.js ──► content.js (page DOM telemetry)           │
│         └──► background.js (network request telemetry)  │
│                                                         │
│  User clicks "Analyze with Gemini AI"                   │
│         │                                               │
│         ▼                                               │
│  POST /analyze (combined telemetry)                     │
└─────────┬───────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI Backend (localhost:8000)                       │
│                                                         │
│  app.py receives telemetry                              │
│      │                                                 │
│      ├── scorer.py → compute_pre_score() (0-100)       │
│      ├── prompts.py → format Gemini prompt             │
│      └── google-generativeai → Gemini 2.5 Flash API    │
│                                                         │
│  Returns { pre_score, flagged_issues, ai_verdict }      │
└─────────────────────────────────────────────────────────┘
```

### Component Interaction

1. **content.js** — Injected into every page (`<all_urls>`). Crawls the DOM to collect forms, input fields, links, permissions, cookies, HTTPS status, and suspicious phishing keywords. Responds to `"get_telemetry"` messages from the popup.

2. **background.js** — Service worker monitoring `chrome.webRequest.onBeforeRequest`. Classifies third-party requests into tracking scripts, analytics scripts, and ad scripts. Stores per-tab counts and responds to `"get_network_telemetry"` messages.

3. **popup.html** — Extension popup UI with 7 data sections:
   - AI Safety Analysis (with Gemini trigger button)
   - Website Information
   - Phishing & Scam Indicators
   - Data Collection Fields
   - Privacy & Tracking
   - Link Analysis
   - Permissions States
   - Trust Indicators

4. **popup.js** — Orchestrator that queries both content and background scripts, populates the UI, and manages the AI analysis flow via `fetch()` to the backend.

5. **backend/app.py** — FastAPI server with `GET /health` and `POST /analyze` endpoints. Receives telemetry, runs heuristic pre-scoring, builds an AI prompt, calls Gemini API, and returns combined results.

6. **backend/scorer.py** — Deterministic rule engine (0-100 scale):
   - No HTTPS (-30 points)
   - No privacy policy (-15)
   - No terms (-10)
   - No contact page (-5)
   - External form actions (-35)
   - Login on insecure page (-20)
   - Suspicious keywords (up to -25)
   - Shortened URLs (up to -20)
   - Credit card fields (-10)

7. **backend/prompts.py** — System prompt instructing Gemini to act as a cybersecurity analyst, incorporating the pre-score, flagged issues, and raw telemetry JSON.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Browser Extension** | Chrome Manifest V3, Vanilla JavaScript |
| **Frontend UI** | HTML5, CSS3, Vanilla JavaScript |
| **Backend Framework** | Python 3.12+, FastAPI |
| **AI / LLM** | Google Gemini 2.5 Flash (`google-generativeai`) |
| **ASGI Server** | Uvicorn |
| **Validation** | Pydantic |
| **Environment** | python-dotenv |
| **CORS** | FastAPI CORSMiddleware (allow all origins) |
| **Browser APIs** | `chrome.tabs`, `chrome.runtime`, `chrome.webRequest`, `navigator.permissions`, DOM APIs |

---

## Key Features

- **Phishing Detection** — Scans for suspicious urgency keywords, external form submissions, shortened URLs, and missing trust signals.
- **Data Collection Audit** — Identifies name, email, phone, address, DOB, credit card, and file upload fields.
- **Network Telemetry** — Real-time tracking of third-party requests, analytics, advertising, and tracking scripts.
- **Permission Analysis** — Checks geolocation and notification permission states.
- **Two-Stage Risk Scoring** — Heuristic pre-score (deterministic) + Gemini AI analysis (LLM-based).
- **Actionable Recommendations** — AI-generated plain-English safety verdict with specific risks and user guidance.

---

## Security Observations

- **API Key in `.env`** — The `.env` file contains a placeholder API key. This file should be in `.gitignore` and never committed (the current key `AQ.Ab8RN6LIqYG71wliPkGQn6eOml6rcahqyvhM6r7k7gXl6YnkNw` appears to be a placeholder/invalid).
- **CORS All Origins** — The backend allows all origins (`"*"`), which is acceptable for a local-only extension backend but would need tightening for production.
- **No Rate Limiting** — The `/analyze` endpoint has no rate limiting, which could lead to abuse if exposed publicly.
- **No Authentication** — The backend has no authentication; anyone on localhost can use it.

---

## Getting Started

### Prerequisites
- Python 3.12+
- Chrome/Edge browser
- Google Gemini API key (free at https://aistudio.google.com/app/apikey)

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
# Edit .env - set your GEMINI_API_KEY
uvicorn app:app --reload
```

### Extension Setup
1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the project root
4. Pin the extension and navigate to any website

---

## Potential Improvements

- Add `.gitignore` to exclude `.env`, `__pycache__/`, and IDE files
- Implement caching for the Gemini API calls to avoid repeated analysis of the same domain
- Add support for more browser permission types (camera, microphone, clipboard)
- Improve network telemetry with request size and response type analysis
- Add a privacy policy and terms of service pages for the extension itself
- Add unit tests for `scorer.py` and integration tests for `app.py`
- Consider edge case where `document.body` could be null in `content.js`
- Make the `shorteners` list in `content.js` configurable or more comprehensive

---

## Conclusion

Site Sentinel AI is a well-structured, functional Chrome extension that provides meaningful web safety analysis by combining deterministic heuristics with AI-powered reasoning. The architecture cleanly separates concerns between DOM analysis (content script), network monitoring (background worker), UI (popup), and server-side AI processing (Python backend). The two-stage scoring approach (rules + AI) is a strong design pattern that provides both reliability and depth of analysis.
