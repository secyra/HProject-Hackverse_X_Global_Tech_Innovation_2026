import os
import httpx

VT_API_KEY = os.getenv("VT_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

async def check_virustotal(domain: str) -> dict:
    if not VT_API_KEY:
        return {"available": False, "reason": "No API key"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = await client.get(url, headers={"x-apikey": VT_API_KEY})
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {
                    "available": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_vendors": sum(stats.values()),
                    "flagged": malicious > 0 or suspicious > 0
                }
            return {"available": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}

async def check_urlscan(domain: str) -> dict:
    if not URLSCAN_API_KEY:
        return {"available": False, "reason": "No API key"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            resp = await client.get(url, headers={"API-Key": URLSCAN_API_KEY})
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                recent_malicious = 0
                for r in results:
                    if r.get("task", {}).get("status") == "malicious":
                        recent_malicious += 1
                return {
                    "available": True,
                    "total_scans": len(results),
                    "recent_malicious": recent_malicious,
                    "flagged": recent_malicious > 0
                }
            return {"available": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}

async def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "No API key"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "available": True,
                    "abuse_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "flagged": score > 50
                }
            return {"available": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}

async def check_domain_reputation(domain: str, ip: str = None) -> dict:
    vt = await check_virustotal(domain) if VT_API_KEY else {"available": False}
    us = await check_urlscan(domain) if URLSCAN_API_KEY else {"available": False}
    ab = await check_abuseipdb(ip) if ip and ABUSEIPDB_KEY else {"available": False}
    return {"virustotal": vt, "urlscan": us, "abuseipdb": ab}
