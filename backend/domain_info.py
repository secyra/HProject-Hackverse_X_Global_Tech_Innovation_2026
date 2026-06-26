import socket
import ssl
import datetime
import httpx
import logging

logger = logging.getLogger("domain_info")

def get_main_domain(hostname: str) -> str:
    parts = hostname.split('.')
    if len(parts) <= 2:
        return hostname
    two_part_tlds = {'co.uk','co.jp','com.au','co.nz','co.in','co.za','com.br','org.uk','ac.uk','gov.uk','net.au','org.au'}
    last_two = '.'.join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def get_ssl_info(hostname: str) -> dict:
    try:
        context = ssl.create_default_context()
        # Set a short timeout for socket connection
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"issuer": "Unknown", "days_remaining": None}
                
                # Extract issuer organization or common name
                issuer_info = dict(x[0] for x in cert.get('issuer', []))
                issuer = issuer_info.get('organizationName') or issuer_info.get('commonName') or 'Unknown'
                
                # Expiry info
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    expiry = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry - datetime.datetime.utcnow()).days
                    return {
                        "issuer": issuer,
                        "days_remaining": days_remaining,
                        "expiry_date": not_after_str
                    }
                return {"issuer": issuer, "days_remaining": None}
    except Exception as e:
        logger.warning(f"Failed to fetch SSL info for {hostname}: {e}")
        return {"issuer": "Unavailable", "days_remaining": None, "error": str(e)}

async def get_domain_creation_date(domain: str) -> dict:
    main_domain = get_main_domain(domain)
    url = f"https://rdap.org/domain/{main_domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                for event in events:
                    if event.get("eventAction") in ["registration", "creation"]:
                        date_str = event.get("eventDate")
                        if date_str:
                            return {"creation_date": date_str}
            return {"creation_date": None}
    except Exception as e:
        logger.warning(f"RDAP lookup failed for {main_domain}: {e}")
        return {"creation_date": None}

async def get_domain_trust_profile(hostname: str) -> dict:
    ssl_info = get_ssl_info(hostname)
    creation_info = await get_domain_creation_date(hostname)
    
    creation_date_str = creation_info.get("creation_date")
    age_str = "Unavailable"
    creation_year = None
    is_new_domain = False
    
    if creation_date_str:
        try:
            # Parse ISO date (e.g. 1995-03-04T05:00:00Z or similar)
            date_part = creation_date_str.split('T')[0]
            dt = datetime.datetime.strptime(date_part, '%Y-%m-%d')
            creation_year = dt.year
            creation_month = dt.strftime('%B')
            
            delta = datetime.datetime.utcnow() - dt
            years = delta.days // 365
            months = (delta.days % 365) // 30
            
            if years > 0:
                age_str = f"Established: {years} year{'s' if years != 1 else ''} ago (Registered {creation_month} {creation_year})"
            elif months > 0:
                age_str = f"Registered: {months} month{'s' if months != 1 else ''} ago ({creation_month} {creation_year})"
            else:
                age_str = f"🚨 New: Registered recently ({delta.days} days ago)"
                
            if delta.days < 365:
                is_new_domain = True
        except Exception:
            age_str = "Unavailable"
            
    return {
        "domain": hostname,
        "age_description": age_str,
        "creation_date": creation_date_str,
        "ssl_issuer": ssl_info.get("issuer", "Unavailable"),
        "ssl_days_remaining": ssl_info.get("days_remaining"),
        "is_new_domain": is_new_domain
    }
