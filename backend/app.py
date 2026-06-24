import json
import os
import uuid
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from scorer import compute_pre_score
from reputation import check_domain_reputation
from rate_limiter import limiter, apply_rate_limits
from scraper import scrape_url, deep_crawl
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from models import UrlAnalyzePayload, TelemetryAnalyzePayload
from vision import analyze_screenshot

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
    from google import genai
    from google.genai import types
    from prompts import GEMINI_PROMPT_TEMPLATE
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    GEMINI_MODEL = "gemini-2.5-flash"


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

    if verdict_text == "dangerous":
        briefing = f"This site appears to be a fraudulent version of {domain}. It contains security warnings and suspicious forms designed to trick you into sharing sensitive data. Do not enter any personal or financial information on this page."
    elif verdict_text == "suspicious":
        briefing = f"There are unusual signals on {domain} that suggest it may not be trustworthy. Some forms or links on this page could be collecting your information without your knowledge. Be cautious and avoid entering sensitive data."
    else:
        briefing = f"{domain} appears to be a legitimate website with standard security measures in place. No obvious signs of phishing or deception were detected. You can browse safely, but always stay alert."

    return {
        "verdict": verdict_text,
        "safety_score": safety_score,
        "summary": full_summary,
        "top_risks": flagged_issues,
        "trust_assessment": f"The site uses {'HTTPS' if telemetry.get('trust', {}).get('isHttps') else 'HTTP'}.",
        "recommendation": recommendation,
        "data_exposure_risk": exposure,
        "plain_english_briefing": briefing
    }


def run_gemini_analysis(pre_score, flagged_issues, telemetry):
    issues_text = "\n".join(f"- {issue}" for issue in flagged_issues) if flagged_issues else "- No major issues flagged by pre-analysis"

    prompt = GEMINI_PROMPT_TEMPLATE.format(
        pre_score=pre_score,
        flagged_issues=issues_text,
        telemetry_json=json.dumps(telemetry, indent=2)
    )

    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json"
        )
    )
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

    vision_verdict = None
    if USE_GEMINI and payload.screenshot:
        try:
            vision_verdict = analyze_screenshot(payload.screenshot, gemini_client)
        except Exception:
            pass

    return {
        "pre_score": pre_score,
        "flagged_issues": flagged_issues,
        "ai_verdict": ai_verdict,
        "vision_verdict": vision_verdict
    }


@app.post("/analyze-url")
@limiter.limit("30/minute")
async def analyze_url(request: Request, payload: UrlAnalyzePayload):
    if payload.deep:
        deep_result = await deep_crawl(payload.url)
        if "error" in deep_result:
            raise HTTPException(status_code=502, detail=deep_result["error"])

        main_page = deep_result["pages"][0] if deep_result["pages"] else {}
        pre_score = deep_result["aggregated"]["worst_score"]
        flagged_issues = deep_result["aggregated"]["total_flagged_issues"]

        share_token = str(uuid.uuid4())
        scan_store[share_token] = {
            "domain": urlparse(payload.url).hostname or "unknown",
            "pre_score": pre_score,
            "flagged_issues": flagged_issues,
            "source": "deep_url_scan",
            "pages_count": deep_result["pages_count"]
        }

        domain = urlparse(payload.url).hostname or "the site"
        safety_score = 100 - pre_score
        verdict_text = "safe" if safety_score >= 80 else "suspicious" if safety_score >= 40 else "dangerous"
        exposure = "low" if safety_score >= 80 else "medium" if safety_score >= 40 else "high"

        full_summary_parts = [f"Deep scan of {domain} ({deep_result['pages_count']} pages)."]
        if flagged_issues:
            full_summary_parts.append(f"Found {len(flagged_issues)} issue{'s' if len(flagged_issues) > 1 else ''} across all pages:")
            full_summary_parts.extend(flagged_issues[:3])
            if len(flagged_issues) > 3:
                full_summary_parts.append(f"and {len(flagged_issues) - 3} more.")
        else:
            full_summary_parts.append("No significant issues detected across any page.")
        full_summary = " ".join(full_summary_parts)

        recommendation = "This site appears safe to browse." if verdict_text == "safe" else \
                         "Exercise caution. Review flagged issues before entering personal data." if verdict_text == "suspicious" else \
                         "Avoid entering any personal information on this site."

        if verdict_text == "dangerous":
            briefing = f"This site appears to be a fraudulent version of {domain}. It contains security warnings and suspicious forms designed to trick you into sharing sensitive data. Do not enter any personal or financial information on this page."
        elif verdict_text == "suspicious":
            briefing = f"There are unusual signals on {domain} that suggest it may not be trustworthy. Some forms or links on this page could be collecting your information without your knowledge. Be cautious and avoid entering sensitive data."
        else:
            briefing = f"{domain} appears to be a legitimate website with standard security measures in place. No obvious signs of phishing or deception were detected. You can browse safely, but always stay alert."

        return {
            "pre_score": pre_score,
            "flagged_issues": flagged_issues,
            "scraped_telemetry": main_page,
            "deep_scan": deep_result,
            "ai_verdict": {
                "verdict": verdict_text,
                "safety_score": safety_score,
                "summary": full_summary,
                "top_risks": flagged_issues,
                "trust_assessment": f"Deep scan completed — {deep_result['pages_count']} pages analyzed.",
                "recommendation": recommendation,
                "data_exposure_risk": exposure,
                "plain_english_briefing": briefing
            },
            "vision_verdict": None,
            "share_token": share_token
        }

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

    if verdict_text == "dangerous":
        briefing = f"This site appears to be a fraudulent version of {domain}. It contains security warnings and suspicious forms designed to trick you into sharing sensitive data. Do not enter any personal or financial information on this page."
    elif verdict_text == "suspicious":
        briefing = f"There are unusual signals on {domain} that suggest it may not be trustworthy. Some forms or links on this page could be collecting your information without your knowledge. Be cautious and avoid entering sensitive data."
    else:
        briefing = f"{domain} appears to be a legitimate website with standard security measures in place. No obvious signs of phishing or deception were detected. You can browse safely, but always stay alert."

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
            "data_exposure_risk": exposure,
            "plain_english_briefing": briefing
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


@app.post("/classify-domain")
def classify_domain(payload: dict):
    domain = payload.get("domain", "")
    if not domain:
        return {"should_block": False, "reason": "", "category": "unknown"}

    suspicious_tlds = {'xyz', 'top', 'club', 'gq', 'ml', 'tk', 'cf', 'ga', 'work',
                       'review', 'loan', 'win', 'bid', 'trade', 'webcam', 'science',
                       'party', 'racing', 'download', 'stream', 'host', 'site', 'press'}
    tracker_keywords = ['track', 'analytics', 'metrics', 'pixel', 'beacon',
                        'adserver', 'adsystem', 'doubleclick', 'adsense',
                        'facebook.com/tr', 'pinterest.com', 'outbrain',
                        'taboola', 'criteo', 'rubicon', 'openx']
    malware_keywords = ['phish', 'malware', 'exploit', 'trojan', 'ransom',
                        'steal', 'hack', 'crack', 'keylog', 'fake', 'scam',
                        '0day', 'shell', 'cmd', 'admin', 'wp-admin',
                        'cgi-bin', 'eval', 'drop', 'payload']

    domain_lower = domain.lower()
    tld = domain_lower.split('.').pop() if '.' in domain_lower else ''
    should_block = False
    reason = ""
    category = "unknown"

    if USE_GEMINI:
        try:
            classify_prompt = f"""You are a web security classifier. Analyze this domain and determine if it should be blocked.
Domain: {domain}

Respond ONLY with JSON:
{{
  "should_block": true/false,
  "category": "tracking" | "advertising" | "malware" | "phishing" | "safe" | "unknown",
  "reason": "<brief reason>",
  "confidence": 0.0-1.0
}}

Block if it is: a known tracker/analytics service, ad network, malware/phishing host, or data collection endpoint.
Do NOT block well-known CDNs, frameworks, or legitimate API services unless clearly abusive.
"""
            response = gemini_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=classify_prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json'
                )
            )
            result = json.loads(response.text.strip())
            if result.get("should_block") and result.get("confidence", 0) >= 0.6:
                return result
        except Exception:
            pass

    if tld in suspicious_tlds:
        should_block = True
        reason = f"Suspicious TLD: .{tld}"
        category = "malware"

    for kw in tracker_keywords:
        if kw in domain_lower:
            should_block = True
            reason = f"Tracker keyword: {kw}"
            category = "tracking"
            break

    for kw in malware_keywords:
        if kw in domain_lower:
            should_block = True
            reason = f"Threat keyword: {kw}"
            category = "malware"
            break

    return {"should_block": should_block, "reason": reason, "category": category, "confidence": 0.9 if should_block else 0.0}


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
