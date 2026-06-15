import json
import os
import uuid
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from scorer import compute_pre_score
from reputation import check_domain_reputation
from rate_limiter import limiter, apply_rate_limits
from scraper import scrape_url
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from models import UrlAnalyzePayload, TelemetryAnalyzePayload

load_dotenv(override=True)

app = FastAPI(title="Site Sentinel Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

apply_rate_limits(app)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

scan_store = {}

# Optional Gemini AI integration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
USE_GEMINI = bool(GEMINI_API_KEY)

if USE_GEMINI:
    import google.generativeai as genai
    from prompts import GEMINI_PROMPT_TEMPLATE
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-2.5-flash")


def build_rule_verdict(pre_score, flagged_issues, telemetry):
    score = pre_score
    safety_score = 100 - score

    if safety_score >= 80:
        verdict_text = "safe"
    elif safety_score >= 40:
        verdict_text = "suspicious"
    else:
        verdict_text = "dangerous"

    if safety_score >= 80:
        exposure = "low"
    elif safety_score >= 40:
        exposure = "medium"
    else:
        exposure = "high"

    domain = telemetry.get("domain", "the site")
    full_summary_parts = [f"Scanned {domain}."]
    if flagged_issues:
        full_summary_parts.append(f"Found {len(flagged_issues)} issue{'s' if len(flagged_issues) > 1 else ''}:")
        full_summary_parts.extend(flagged_issues[:3])
        if len(flagged_issues) > 3:
            full_summary_parts.append(f"and {len(flagged_issues) - 3} more.")
    else:
        full_summary_parts.append("No significant issues detected.")
    full_summary = " ".join(full_summary_parts)

    recommendation = "This site appears safe to browse." if verdict_text == "safe" else \
                     "Exercise caution. Review flagged issues before entering personal data." if verdict_text == "suspicious" else \
                     "Avoid entering any personal information on this site."

    return {
        "verdict": verdict_text,
        "safety_score": safety_score,
        "summary": full_summary,
        "top_risks": flagged_issues,
        "trust_assessment": f"The site uses {'HTTPS' if telemetry.get('trust', {}).get('isHttps') else 'HTTP'}.",
        "recommendation": recommendation,
        "data_exposure_risk": exposure
    }


def run_gemini_analysis(pre_score, flagged_issues, telemetry):
    issues_text = "\n".join(f"- {issue}" for issue in flagged_issues) if flagged_issues else "- No major issues flagged by pre-analysis"

    prompt = GEMINI_PROMPT_TEMPLATE.format(
        pre_score=pre_score,
        flagged_issues=issues_text,
        telemetry_json=json.dumps(telemetry, indent=2)
    )

    response = gemini_model.generate_content(prompt)
    raw_text = response.text.strip()

    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
        raw_text = raw_text.strip()

    return json.loads(raw_text)


@app.get("/health")
def health_check():
    ai_status = "available" if USE_GEMINI else "disabled (set GEMINI_API_KEY to enable)"
    return {"status": "ok", "version": "2.0", "message": "Site Sentinel backend is running", "ai": ai_status}


@app.post("/analyze")
@limiter.limit("30/minute")
async def analyze(request: Request, payload: TelemetryAnalyzePayload):
    telemetry = payload.telemetry or {}

    if not telemetry:
        return {
            "pre_score": 0,
            "flagged_issues": [],
            "ai_verdict": build_rule_verdict(0, [], {}),
            "vision_verdict": None
        }

    pre_score, flagged_issues = compute_pre_score(telemetry)

    if USE_GEMINI:
        try:
            ai_verdict = run_gemini_analysis(pre_score, flagged_issues, telemetry)
        except Exception as e:
            ai_verdict = build_rule_verdict(pre_score, flagged_issues, telemetry)
    else:
        ai_verdict = build_rule_verdict(pre_score, flagged_issues, telemetry)

    return {
        "pre_score": pre_score,
        "flagged_issues": flagged_issues,
        "ai_verdict": ai_verdict,
        "vision_verdict": None
    }


@app.post("/analyze-url")
@limiter.limit("30/minute")
async def analyze_url(request: Request, payload: UrlAnalyzePayload):
    scraped = await scrape_url(payload.url)

    if "error" in scraped:
        raise HTTPException(status_code=502, detail=scraped["error"])

    pre_score, flagged_issues = compute_pre_score(scraped)

    share_token = str(uuid.uuid4())
    scan_store[share_token] = {
        "domain": scraped.get("domain", ""),
        "pre_score": pre_score,
        "flagged_issues": flagged_issues,
        "source": "url_scan"
    }

    risk_score = pre_score
    safety_score = 100 - risk_score

    if safety_score >= 80:
        verdict_text = "safe"
    elif safety_score >= 40:
        verdict_text = "suspicious"
    else:
        verdict_text = "dangerous"

    if safety_score >= 80:
        exposure = "low"
    elif safety_score >= 40:
        exposure = "medium"
    else:
        exposure = "high"

    domain = scraped.get("domain", "the site")
    full_summary_parts = [f"Scanned {domain}."]
    if flagged_issues:
        full_summary_parts.append(f"Found {len(flagged_issues)} issue{'s' if len(flagged_issues) > 1 else ''}:")
        full_summary_parts.extend(flagged_issues[:3])
        if len(flagged_issues) > 3:
            full_summary_parts.append(f"and {len(flagged_issues) - 3} more.")
    else:
        full_summary_parts.append("No significant issues detected.")
    full_summary = " ".join(full_summary_parts)

    recommendation = "This site appears safe to browse." if verdict_text == "safe" else \
                     "Exercise caution. Review flagged issues before entering personal data." if verdict_text == "suspicious" else \
                     "Avoid entering any personal information on this site."

    return {
        "pre_score": pre_score,
        "flagged_issues": flagged_issues,
        "scraped_telemetry": scraped,
        "ai_verdict": {
            "verdict": verdict_text,
            "safety_score": safety_score,
            "summary": full_summary,
            "top_risks": flagged_issues,
            "trust_assessment": f"The site uses {'HTTPS' if scraped.get('trust', {}).get('isHttps') else 'HTTP'}.",
            "recommendation": recommendation,
            "data_exposure_risk": exposure
        },
        "vision_verdict": None,
        "share_token": share_token
    }


@app.get("/report/{token}")
def get_report(token: str):
    report = scan_store.get(token)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/domain/{domain}")
def get_domain_info(domain: str):
    reports = [r for r in scan_store.values() if r["domain"] == domain]
    if not reports:
        return {"domain": domain, "scan_count": 0, "last_verdict": None}
    last = reports[-1]
    flagged = sum(1 for r in reports if r.get("pre_score", 0) >= 40)
    return {
        "domain": domain,
        "scan_count": len(reports),
        "flag_count": flagged,
        "last_pre_score": last.get("pre_score"),
        "avg_pre_score": round(sum(r["pre_score"] for r in reports) / len(reports), 1)
    }
