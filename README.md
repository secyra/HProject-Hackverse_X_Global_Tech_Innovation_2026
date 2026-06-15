# Site Sentinel AI

> **Hackathon Architecture Document — Version 2.0**
> Production-Grade Design · Global Tech Hackathon 2026

**Real-time AI web safety scanner** — a Chrome MV3 Extension backed by FastAPI, Supabase Intelligence Layer, and Gemini 2.5 Flash (Vision + Text).

---

## Executive Summary

Site Sentinel AI is a Chrome browser extension that analyzes any website in real time for phishing threats, privacy risks, and malicious behavior. It combines deterministic heuristic scoring with Google Gemini 2.5 Flash AI — including visual screenshot analysis — and backs every scan with a crowdsourced domain intelligence layer powered by Supabase.

This document describes the complete production-grade architecture for the hackathon submission: every module, every database table, every API endpoint, every deployment step, and the exact 60-second demo script judges will see.

> **Winning Hypothesis:** Most teams will build a website scanner that sends a URL to an LLM. Site Sentinel AI is different in three ways: (1) Gemini Vision reads a screenshot and describes visual deception the text alone cannot catch, (2) every scan is persisted and crowd-aggregated so domain reputation compounds over time, and (3) every analysis generates a shareable public URL — a live artifact judges can keep after the hackathon ends.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Architecture Data Flow](#architecture-data-flow)
4. [Chrome Extension](#chrome-extension)
5. [FastAPI Backend](#fastapi-backend)
6. [Supabase Intelligence Layer](#supabase-intelligence-layer)
7. [Output Surfaces](#output-surfaces)
8. [Complete File Structure](#complete-file-structure)
9. [Deployment Guide](#deployment-guide)
10. [Full Technology Stack](#full-technology-stack)
11. [Priority Build Order](#priority-build-order)
12. [The 60-Second Judge Demo Script](#the-60-second-judge-demo-script)
13. [Environment Variables & API Key Setup](#environment-variables--api-key-setup)
14. [Security Notes](#security-notes)

---

## 1. System Overview

Site Sentinel AI is a client-server-database system with four distinct tiers. Each tier has a single responsibility and communicates over well-defined interfaces.

| Tier | Responsibility |
|---|---|
| **Browser (Chrome MV3)** | Collect DOM telemetry, network telemetry, and a page screenshot. Render the analysis result in the popup UI. |
| **FastAPI Backend** | Receive telemetry, run heuristic pre-scoring, call external reputation APIs, invoke Gemini AI with structured output, persist results to Supabase, return combined verdict. |
| **Supabase Intelligence Layer** | Store domain reputation, scan reports, and phishing infrastructure graphs. Serve crowdsourced intelligence on subsequent scans of the same domain. |
| **Output Surfaces** | Extension popup with animated trust score ring. Shareable public report page. D3 threat network graph. Live admin dashboard. |

---

## 2. Architecture Data Flow

The following diagram shows the complete data flow from browser through to output surfaces.

```
USER OPENS EXTENSION POPUP
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│  CHROME EXTENSION (MV3)                                     │
│                                                             │
│  content.js ──► DOM signals, forms, keywords, links        │
│  background.js ► Network map, trackers, ad scripts         │
│  offscreen.js ──► Page screenshot (base64 PNG)             │
│  popup.js ──────► React UI, trust ring, verdict card       │
│                                                             │
│  USER CLICKS ▶ ANALYZE                                     │
│         │                                                   │
│         ▼ POST /analyze (telemetry + screenshot)           │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  FASTAPI BACKEND (Railway / Render)                         │
│                                                             │
│  reputation.py ─► VirusTotal + URLScan + AbuseIPDB        │
│  scorer.py ─────► Weighted heuristic pre-score (0–100)    │
│  vision.py ─────► Gemini Vision screenshot analysis        │
│  prompts.py ────► Gemini text analysis (JSON schema mode)  │
│  report_gen.py ─► Write scan to Supabase, return token     │
│                                                             │
│  Returns { pre_score, reputation, ai_verdict, share_token }│
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  SUPABASE (PostgreSQL + pgvector + Edge Functions)          │
│                                                             │
│  domain_reputation  ◄──► aggregate_domain (Edge Fn)       │
│  scan_reports       ◄──► embed_report (Edge Fn, pgvector) │
│  phishing_network   ◄──► graph infrastructure clusters     │
│                                                             │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  OUTPUT SURFACES                                            │
│                                                             │
│  Extension Popup  ──► Trust ring, verdict, crowd badge     │
│  sentinel.app/r/{token} ► Shareable public report page     │
│  /graph ────────────► D3 phishing network visualizer       │
│  /dashboard ────────► Live metrics for judge demo          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Chrome Extension (Browser Tier)

### 3.1 content.js — DOM Telemetry Collector

Injected into every page via manifest `<all_urls>`. Crawls the live DOM and returns a structured telemetry object when queried by popup.js.

Collects the following signals:

- HTTPS status, certificate issuer, domain age estimate
- All form elements: action URLs, input field types (email, password, tel, cc-number, dob)
- External link ratio vs internal links
- Presence of privacy policy, terms of service, contact page links
- Phishing keyword density: urgency words, brand impersonation strings, threat language
- Shortened URL presence (bit.ly, tinyurl, t.co, etc.)
- Cookie count and SameSite policy
- `navigator.permissions` state for geolocation and notifications

### 3.2 background.js — Network Telemetry Service Worker

Persistent service worker using `chrome.webRequest.onBeforeRequest` to intercept all network requests for the active tab. Classifies third-party requests into categories using domain pattern matching.

Produces per-tab network telemetry object:

- `tracker_count`: domains matching known tracker lists
- `analytics_count`: GA, Mixpanel, Amplitude, Segment, etc.
- `ad_count`: advertising networks
- `third_party_domains`: unique external domain list
- `request_total`: total outbound requests

### 3.3 offscreen.js — Screenshot Capture (NEW)

> **New Module:** This is the feature that will win the hackathon. No competitor team will have visual AI analysis of the page layout. `offscreen.js` uses the Chrome Offscreen Documents API to capture a PNG screenshot of the active tab and pass it to the backend as base64. Gemini Vision then describes exactly which visual elements look suspicious — fake login boxes, misleading branding, urgency banners.

Implementation steps:

1. Register `offscreen.html` in `manifest.json` under offscreen permissions
2. Call `chrome.offscreen.createDocument()` from background.js when popup requests a scan
3. Use `chrome.tabs.captureVisibleTab()` inside the offscreen context to get base64 PNG
4. Return the base64 string to popup.js via `chrome.runtime.sendMessage`
5. popup.js bundles the screenshot into the `POST /analyze` request body

### 3.4 popup.js + React UI — Trust Ring (REBUILT)

The popup is rebuilt as a React application (Vite + React 18). Key UI components:

- **TrustRing.jsx** — SVG animated circular arc. Fills green (75–100), amber (40–74), or red (0–39) as the score resolves. This is the hero visual judges see first.
- **VerdictCard.jsx** — SAFE / SUSPICIOUS / DANGEROUS badge with AI-generated one-line summary
- **CrowdBadge.jsx** — 'Seen by N users, M flagged this domain' — pulled from `domain_reputation`
- **RiskFactorList.jsx** — collapsible accordion per risk category (Phishing, Privacy, Network, Visual)
- **ScreenshotInsights.jsx** — renders Gemini Vision's visual observations as a highlighted list
- **ShareButton.jsx** — copies `sentinel.app/r/{token}` to clipboard with one click

```jsx
// popup/src/components/TrustRing.jsx (skeleton)
const TrustRing = ({ score }) => {
  const r = 54, circ = 2 * Math.PI * r;
  const fill = score >= 75 ? '#0F6E56' : score >= 40 ? '#854F0B' : '#A32D2D';
  const dash = (score / 100) * circ;
  return (
    <svg viewBox='0 0 120 120' width={120} height={120}>
      <circle cx={60} cy={60} r={r} fill='none' stroke='#eee' strokeWidth={10}/>
      <circle cx={60} cy={60} r={r} fill='none' stroke={fill} strokeWidth={10}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap='round'
        style={{ transition: 'stroke-dasharray 0.8s ease', transform: 'rotate(-90deg)',
          transformOrigin: '50% 50%' }}/>
      <text x={60} y={65} textAnchor='middle' fontSize={22} fontWeight={700}
        fill={fill}>{score}</text>
    </svg>
  );
};
```

---

## 4. FastAPI Backend

Deployed on Railway (or Render). Exposes three endpoints. Receives the telemetry bundle, orchestrates all analysis passes, writes to Supabase, and returns a single combined response object.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe for Railway deployment. Returns `{status: ok, version}`. |
| `POST /analyze` | Main analysis endpoint. Accepts telemetry JSON + screenshot base64. Returns full verdict object including `share_token`. |
| `GET /report/{token}` | Fetches a previously generated report by share token. Powers the public shareable page. |
| `GET /domain/{domain}` | Returns crowd reputation for a domain. Used by the extension to show prior flags before running full analysis. |
| `GET /graph/{domain}` | Returns phishing network edges for a domain for the D3 visualizer. |

### 4.1 scorer.py — Heuristic Pre-Score v2

Extended from the original with additional weighted signals and reputation API inputs. Score is 0–100 (higher = safer). All deductions are capped to prevent over-penalization from a single signal.

| Signal | Deduction | Notes |
|---|---|---|
| No HTTPS | –30 | Immediate red flag |
| VirusTotal: any malicious vendor flag | –40 | Cap at 1 application per scan |
| External form action (login form posts to diff domain) | –35 | Strongest phishing signal |
| Login form on HTTP page | –20 | Credential harvesting risk |
| No privacy policy link found | –15 | Trust signal absent |
| Phishing keyword density > 3 per page | –25 | Urgency/threat language |
| URLScan flagged in last 30 days | –30 | Recent known-bad activity |
| AbuseIPDB score > 50 | –20 | Malicious IP infrastructure |
| Shortened URLs in links | –20 | Up to 4 instances, –5 each |
| No terms of service link | –10 | Minor trust signal |
| No contact page | –5 | Minor trust signal |
| Credit card field present | –10 | Context-dependent risk |
| Crowd flag rate > 20% of scans | –15 | Community intelligence |

### 4.2 vision.py — Gemini Vision Screenshot Analysis (NEW)

> **Demo Moment:** This is the single most impressive feature in the demo. Judges will watch Gemini describe specific visual deception on a phishing page — 'The login form mimics a PayPal interface but the domain does not match' — from a live screenshot captured seconds earlier.

`vision.py` receives the base64 PNG from the request body, constructs a multimodal Gemini prompt, and returns structured visual observations.

```python
# backend/vision.py
import google.generativeai as genai
import base64

VISION_PROMPT = '''
You are a cybersecurity analyst specializing in visual phishing detection.
Examine this webpage screenshot for visual deception techniques:
- Brand impersonation (fake logos, misspelled brand names)
- Misleading UI elements (fake security badges, false urgency banners)
- Suspicious form design (login boxes on pages claiming to be elsewhere)
- Layout anomalies that suggest a cloned or hastily constructed page

Return ONLY a JSON object with this exact schema:
{
  "visual_verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "confidence": 0.0-1.0,
  "observations": ["string", ...],
  "impersonated_brand": "string or null"
}
'''

def analyze_screenshot(base64_png: str) -> dict:
    model = genai.GenerativeModel('gemini-2.5-flash')
    image_part = {
        'mime_type': 'image/png',
        'data': base64.b64decode(base64_png)
    }
    response = model.generate_content(
        [VISION_PROMPT, image_part],
        generation_config=genai.GenerationConfig(
            response_mime_type='application/json'
        )
    )
    return response.text  # guaranteed JSON
```

### 4.3 prompts.py — Structured JSON Output Mode

The original `prompts.py` returns freetext which requires fragile string parsing. The new version uses Gemini's `response_mime_type` + `response_schema` to return a guaranteed valid JSON object every time.

```python
# backend/prompts.py — Structured Gemini response
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["SAFE","SUSPICIOUS","DANGEROUS"]},
        "confidence": {"type": "number"},
        "risk_factors": {"type": "array", "items": {"type": "string"}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
        "safe_to_proceed": {"type": "boolean"}
    }
}

def get_ai_verdict(telemetry: dict, pre_score: int, flagged: list) -> dict:
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = build_prompt(telemetry, pre_score, flagged)
    response = model.generate_content(
        prompt,
        generation_config=genai.GenerationConfig(
            response_mime_type='application/json',
            response_schema=RESPONSE_SCHEMA
        )
    )
    return json.loads(response.text)  # always valid, no try/catch needed
```

### 4.4 reputation.py — External Threat Intelligence (NEW)

Queries three free-tier APIs in parallel using `asyncio.gather()`. Results are merged into pre-score inputs before Gemini is called.

| API | What it provides |
|---|---|
| **VirusTotal** (free tier) | 90+ security vendor verdicts for the domain. Any malicious flag = –40 from pre-score. |
| **URLScan.io** (free) | Prior scan history. Flags if the domain was reported malicious in last 30 days. |
| **AbuseIPDB** (free) | IP reputation score. Server IP with score > 50 = –20 from pre-score. |

### 4.5 rate_limiter.py — Abuse Prevention (NEW)

Uses `slowapi` with Redis backend (Upstash free tier) to apply a sliding window rate limit of 30 requests per IP per minute on `POST /analyze`. Prevents Gemini API cost runaway if the extension is exposed publicly.

```python
# backend/rate_limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, storage_uri="redis://...")

# In app.py:
@app.post('/analyze')
@limiter.limit('30/minute')
async def analyze(request: Request, body: TelemetryBody):
    ...
```

---

## 5. Supabase Intelligence Layer

Supabase provides PostgreSQL, pgvector for semantic similarity search, Row Level Security for safe public reads, and Edge Functions for server-side aggregation logic. The free tier is sufficient for a hackathon deployment.

### 5.1 Database Schema

```sql
-- 001_init.sql

-- Domain-level crowd reputation
CREATE TABLE domain_reputation (
  domain         TEXT PRIMARY KEY,
  score          INT NOT NULL DEFAULT 50,
  flags          JSONB,              -- { no_https, external_form, ... }
  report_count   INT NOT NULL DEFAULT 0,
  flag_count     INT NOT NULL DEFAULT 0,
  first_seen     TIMESTAMPTZ DEFAULT NOW(),
  last_seen      TIMESTAMPTZ DEFAULT NOW()
);

-- Individual scan records (one per user scan)
CREATE TABLE scan_reports (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  share_token    UUID UNIQUE DEFAULT gen_random_uuid(),
  domain         TEXT REFERENCES domain_reputation(domain),
  telemetry      JSONB,
  ai_verdict     JSONB,
  vision_verdict JSONB,
  pre_score      INT,
  final_score    INT,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Phishing infrastructure graph edges
CREATE TABLE phishing_network (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_a       TEXT,
  domain_b       TEXT,
  edge_type      TEXT CHECK (edge_type IN
                   ('shared_ip','shared_cert','shared_registrar')),
  confidence     FLOAT,
  UNIQUE(domain_a, domain_b, edge_type)
);

-- pgvector for semantic similarity between scan reports
CREATE EXTENSION IF NOT EXISTS vector;
ALTER TABLE scan_reports ADD COLUMN embedding vector(768);

-- Public read RLS (no auth needed for hackathon demo)
ALTER TABLE domain_reputation ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY 'public read' ON domain_reputation FOR SELECT USING (true);
CREATE POLICY 'public read' ON scan_reports FOR SELECT USING (true);
```

### 5.2 Edge Functions

| Edge Function | Purpose |
|---|---|
| `aggregate_domain` | Called after every scan. Upserts `domain_reputation` with updated score, increments `report_count` and `flag_count` if the scan flagged issues. |
| `embed_report` | Generates a text embedding of the scan summary and stores it in `scan_reports.embedding` using pgvector. Enables semantic similarity search to find related phishing sites. |
| `build_network` | After each scan, checks if the scanned domain's IP, certificate fingerprint, or registrar matches any existing domain in `scan_reports`. Creates `phishing_network` edges where matches are found. |

---

## 6. Output Surfaces

### 6.1 Extension Popup

The popup is the primary interaction surface. It loads in under 200ms because it first shows cached crowd data from `domain_reputation` (fast Supabase read) while the full Gemini analysis runs in the background. Layout:

- **Header:** domain name + HTTPS padlock or warning icon
- **Hero:** TrustRing SVG with animated score fill, verdict label, confidence percentage
- **CrowdBadge:** 'N users scanned this domain. M flagged it as unsafe.'
- **Visual Insights panel:** Gemini Vision observations (expandable)
- **Risk accordion:** Phishing / Privacy / Network / Trust — each collapsible
- **Footer:** Share Report button + 'Report this site' user flag button

### 6.2 Shareable Public Report Page

Every scan generates a unique public URL: `https://sentinel-app.up.railway.app/r/{share_token}`. This page:

- Renders a full-page breakdown of the scan: all scores, all AI verdict text, all visual observations
- Shows a social share card (Open Graph meta tags) so sharing on Twitter/LinkedIn shows a preview
- Includes a PDF download button (`html2pdf.js` client-side)
- Shows the phishing network graph inline if the domain has known connections

> **Demo Tip:** Hand judges this URL before the presentation. If they open it on their phone while you demo, it signals that you have a live deployed product, not a localhost prototype.

### 6.3 Phishing Network Graph (D3)

A force-directed graph rendered with D3.js that shows infrastructure connections between phishing domains. Nodes are domains, edges are typed (shared IP, certificate, registrar). Node size scales with `report_count`. Node color encodes danger level (red = DANGEROUS, amber = SUSPICIOUS, green = SAFE).

This is the visually spectacular element for the judge demo. Seed the database with 10–15 known phishing domains from [openphish.com](https://openphish.com) before the presentation. The graph will show a connected cluster of malicious infrastructure — exactly the kind of threat intelligence output that looks like a real security product.

### 6.4 Admin Dashboard

A single-page React dashboard at `/dashboard` (protected by a simple env-var password for demo purposes). Shows:

- Total scans today / this week
- Domains flagged in last 24 hours
- Live scan feed (Supabase realtime subscription)
- Top 10 most-scanned domains table
- World map of scan origins (if browser locale is captured)

---

## 7. Complete File Structure

```
site-sentinel/
├── extension/
│   ├── manifest.json            # MV3, offscreen permission added
│   ├── offscreen.html           # NEW: screenshot capture context
│   ├── offscreen.js             # NEW: captureVisibleTab()
│   ├── background.js            # Updated: triggers screenshot capture
│   ├── content.js               # Updated: extended DOM signals
│   └── popup/                   # NEW: React app
│       ├── package.json
│       ├── vite.config.js
│       └── src/
│           ├── App.jsx
│           ├── api.js           # fetch() wrapper for backend calls
│           └── components/
│               ├── TrustRing.jsx
│               ├── VerdictCard.jsx
│               ├── CrowdBadge.jsx
│               ├── RiskFactorList.jsx
│               ├── ScreenshotInsights.jsx
│               └── ShareButton.jsx
│
└── backend/
    ├── app.py                   # FastAPI router, CORS, rate limiter
    ├── scorer.py                # Heuristic pre-score v2
    ├── prompts.py               # Structured Gemini text analysis
    ├── vision.py                # NEW: Gemini Vision screenshot
    ├── reputation.py            # NEW: VirusTotal + URLScan + AbuseIPDB
    ├── report_gen.py            # NEW: Supabase write + share token
    ├── rate_limiter.py          # NEW: slowapi Redis middleware
    ├── models.py                # Pydantic request/response models
    ├── Dockerfile               # NEW: Railway deployment
    ├── requirements.txt         # Updated dependencies
    ├── .env                     # GEMINI_API_KEY, SUPABASE_URL, VT_KEY
    └── supabase/
        └── migrations/
            └── 001_init.sql     # All tables + RLS + pgvector
```

---

## 8. Deployment Guide

### 8.1 Backend — Railway (30 minutes)

1. Create a free account at [railway.app](https://railway.app)
2. New Project → Deploy from GitHub repo
3. Add environment variables: `GEMINI_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`, `VT_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_KEY`
4. Railway auto-detects the Dockerfile and deploys
5. Copy the generated URL (e.g. `site-sentinel.up.railway.app`)
6. Update `extension/popup/src/api.js BASE_URL` to this URL
7. Rebuild the popup: `cd popup && npm run build`

### 8.2 Supabase — Database (20 minutes)

1. Create a free project at [supabase.com](https://supabase.com)
2. Open SQL Editor, paste and run `001_init.sql`
3. Copy Project URL and anon key to backend `.env`
4. Deploy the three Edge Functions from `supabase/functions/`

### 8.3 Extension — Chrome (5 minutes)

1. Run `npm run build` in the popup directory to generate `dist/`
2. Open `chrome://extensions` → Enable Developer Mode
3. Click Load Unpacked → select the `extension/` directory
4. Pin the extension to the toolbar

### 8.4 Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 9. Full Technology Stack

| Layer | Component / Library | Notes |
|---|---|---|
| **Browser Extension** | Chrome MV3, Vanilla JS | Offscreen Docs API for screenshot |
| **Popup UI** | React 18, Vite, Tailwind CSS | Built into dist/, loaded by manifest |
| **AI — Text** | Gemini 2.5 Flash (JSON mode) | Structured output, no string parsing |
| **AI — Vision** | Gemini 2.5 Flash (multimodal) | Screenshot + text prompt |
| **Backend Framework** | FastAPI + Python 3.12 | Async, type-safe, auto OpenAPI docs |
| **ASGI Server** | Uvicorn | Prod: gunicorn -k uvicorn.workers |
| **Validation** | Pydantic v2 | Request/response models |
| **Rate Limiting** | slowapi + Upstash Redis | Sliding window, per-IP |
| **Database** | Supabase (PostgreSQL 15) | pgvector extension enabled |
| **Semantic Search** | pgvector + Gemini Embeddings | 768-dimension vectors |
| **File Storage** | Supabase Storage | Screenshot archive (optional) |
| **Realtime** | Supabase Realtime | Live scan feed on dashboard |
| **Reputation APIs** | VirusTotal, URLScan, AbuseIPDB | All free tier, parallel fetch |
| **Frontend Graph** | D3.js v7 (force-directed) | Phishing network visualizer |
| **Deployment** | Railway (backend), Supabase (DB) | Both free tier, both public URLs |
| **PDF Export** | html2pdf.js | Client-side, shareable report |

---

## 10. Priority Build Order

If time is limited, build in this exact order. Each item is a complete deliverable that adds standalone value to the demo.

| Priority | Feature | Time | Judge Impact |
|---|---|---|---|
| **P0** | Deploy backend to Railway with Dockerfile | 30 min | Critical — no live demo without this |
| **P0** | Structured Gemini JSON output (prompts.py) | 1 hr | Eliminates fragile parsing, more reliable demo |
| **P1** | Supabase schema + scan_reports + share token | 2 hr | Enables shareable URL — biggest credibility signal |
| **P1** | TrustRing React popup UI + VerdictCard | 2 hr | Visual polish judges remember |
| **P2** | offscreen.js screenshot + vision.py Gemini Vision | 3 hr | The demo moment — no other team has this |
| **P2** | reputation.py (VirusTotal + URLScan) | 2 hr | Multi-source intel, stronger scores |
| **P3** | domain_reputation crowd aggregation | 2 hr | The 'N users flagged this' badge |
| **P3** | D3 phishing network graph | 4 hr | Visually spectacular, high wow factor |
| **P4** | Admin dashboard with live feed | 3 hr | Good for extended demo, not essential |

---

## 11. The 60-Second Judge Demo Script

Follow this script exactly. Every step is designed to produce a visible reaction from judges.

> **Before the presentation:** Seed your Supabase `domain_reputation` with 15–20 known phishing domains from [openphish.com](https://openphish.com) or [phishing.army](https://phishing.army). This ensures the crowd badge shows real numbers and the D3 graph shows a connected network. Do this the night before.

1. **Navigate to a known phishing demo site.** Use a sample from openphish.com or use checkphishing.org. Say: *"Here is a live phishing site."*
2. **Click the Site Sentinel extension icon.** Say: *"I'll run a real-time analysis."* The TrustRing animates to red. Pause here. Let judges see it.
3. **Point to the CrowdBadge.** Say: *"Our system has already seen this domain — 31 other users scanned it, 28 flagged it as dangerous."*
4. **Expand the Visual Insights panel.** Read out one Gemini Vision observation verbatim. Say: *"Our AI analyzed the actual screenshot and identified this specific visual deception."*
5. **Click Share Report.** Copy the URL. Open it in a second browser window (or on your phone). Say: *"Every analysis generates a permanent shareable report at a public URL."*
6. **Navigate to /graph.** The D3 network appears. Say: *"This domain shares infrastructure with three other phishing sites — same IP, same certificate authority. This is threat intelligence, not just a safety score."*
7. **End with:** *"Site Sentinel AI is deployed, live, and has already protected real users from real threats."*

---

## 12. Environment Variables & API Key Setup

| Variable | Where to get it |
|---|---|
| `GEMINI_API_KEY` | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) — free, no credit card |
| `SUPABASE_URL` | Supabase project Settings → API → Project URL |
| `SUPABASE_KEY` | Supabase project Settings → API → anon public key |
| `VT_API_KEY` | [virustotal.com](https://virustotal.com) → Sign up free → API Key in profile |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io) → Sign up free → API Key in settings |
| `ABUSEIPDB_KEY` | [abuseipdb.com](https://abuseipdb.com) → Sign up free → API tab |
| `REDIS_URL` | [upstash.com](https://upstash.com) → Create Redis database → Copy REST URL |
| `BACKEND_URL` | Set in `extension/popup/src/api.js` after Railway deploy |

---

## 13. Security Notes

- All API keys are stored in Railway environment variables, never in the codebase. The `.env` file is in `.gitignore`.
- CORS is locked to the Chrome extension origin in production (`chrome-extension://{your-id}`). Not allow-all as in the original.
- Rate limiting prevents Gemini API cost abuse. Set Gemini API quota limits in Google Cloud Console as a secondary guard.
- Supabase RLS policies allow public SELECT on `domain_reputation` and `scan_reports` (by `share_token` only). INSERT and UPDATE are backend-only via the service role key.
- The share token is a UUID v4 generated by PostgreSQL — 122 bits of entropy, effectively unguessable.
- Screenshots are never stored by default. They are processed in memory and discarded after Gemini Vision returns. Optional archival to Supabase Storage can be added post-hackathon.

---

## Quick Start (Current Codebase)

### Backend

```bash
cd backend
pip install -r requirements.txt
# Edit .env — set your GEMINI_API_KEY
uvicorn app:app --reload
```

### Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select this project root
4. Pin the extension and navigate to any website

### Scan

Click the extension icon → click **Analyze with Gemini AI**

---

### Current Project Structure

```
├── manifest.json          # Chrome extension manifest (v3)
├── background.js          # Service worker — network telemetry
├── content.js             # Content script — DOM analysis
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic & backend communication
├── backend/
│   ├── app.py             # FastAPI server
│   ├── scorer.py          # Heuristic risk pre-scoring
│   ├── prompts.py         # Gemini AI prompt template
│   ├── requirements.txt   # Python dependencies
│   └── .env               # API keys (gitignored)
├── docs/
│   ├── generate-architecture.js          # .docx generator
│   ├── SiteSentinel_Architecture.docx    # Generated architecture doc
│   └── package.json
└── README.md
```

---

*Site Sentinel AI · Global Tech Hackathon 2026*
*Built by Secyra*
