import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent action required", "suspension notice",
    "security alert", "update password", "billing update",
    "unauthorized login", "gift card winner", "claim your prize",
    "congratulations you won", "limited time offer", "act now",
    "your account has been compromised", "confirm your identity",
    "unusual sign-in attempt", "reactivate your account",
    "you have been selected", "exclusive deal", "risk of closure"
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rebrand.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'ow.ly', 'mcaf.ee', 'su.pr',
    'shorturl.at', 'cutt.ly', 'shorte.st'
]


async def scrape_url(target_url: str) -> dict:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            resp = await client.get(target_url, headers=headers)
            html = resp.text
        except Exception as e:
            return {"error": f"Failed to fetch URL: {str(e)}"}

    parsed = urlparse(str(resp.url))
    domain = parsed.hostname or urlparse(target_url).hostname or "unknown"
    soup = BeautifulSoup(html, 'lxml')

    forms = soup.find_all('form')
    form_count = len(forms)
    login_forms = 0
    payment_forms = 0
    external_form_actions = 0

    for form in forms:
        action = form.get('action', '')
        abs_action = urljoin(str(resp.url), action) if action else str(resp.url)
        try:
            action_host = urlparse(abs_action).hostname
            if action_host and action_host != domain:
                external_form_actions += 1
        except Exception:
            pass

        form_text = form.get_text(separator=' ', strip=True).lower()
        has_password = form.find('input', {'type': 'password'}) is not None
        if has_password or any(kw in form_text for kw in ['log in', 'login', 'sign in']):
            login_forms += 1
        if any(kw in form_text for kw in ['payment', 'credit card', 'checkout', 'pay now']):
            payment_forms += 1

    password_fields = len(soup.find_all('input', {'type': 'password'}))

    inputs = soup.find_all(['input', 'textarea', 'select'])
    name_fields = 0
    email_fields = 0
    phone_fields = 0
    address_fields = 0
    dob_fields = 0
    credit_card_fields = 0
    file_upload_fields = 0

    for inp in inputs:
        tag_name = inp.name
        if tag_name == 'input':
            typ = (inp.get('type', '') or '').lower()
        else:
            typ = tag_name

        if typ == 'file':
            file_upload_fields += 1
            continue

        name = (inp.get('name', '') or '').lower()
        iid = (inp.get('id', '') or '').lower()
        placeholder = (inp.get('placeholder', '') or '').lower()
        autocomplete = (inp.get('autocomplete', '') or '').lower()
        aria_label = (inp.get('aria-label', '') or '').lower()
        match_text = f"{name} {iid} {placeholder} {autocomplete} {aria_label}"

        if any(kw in match_text for kw in ['card', 'cc', 'cvv', 'cvc', 'expiry']) or typ == 'cc-number':
            credit_card_fields += 1
            continue
        if typ == 'email' or 'email' in match_text or 'mail' in match_text:
            email_fields += 1
            continue
        if typ == 'tel' or any(kw in match_text for kw in ['phone', 'tel', 'mobile']):
            phone_fields += 1
            continue
        if any(kw in match_text for kw in ['dob', 'birth', 'bday']):
            dob_fields += 1
            continue
        if any(kw in match_text for kw in ['address', 'street', 'zip', 'postcode', 'city', 'state', 'country']):
            address_fields += 1
            continue
        if 'name' in match_text and 'username' not in match_text and 'cardname' not in match_text:
            name_fields += 1
            continue

    body_text = soup.get_text(separator=' ', strip=True).lower()
    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body_text]

    links = soup.find_all('a', href=True)
    internal_links = 0
    external_links = 0
    shortened_urls = 0
    has_privacy_policy = False
    has_terms = False
    has_contact = False

    for link in links:
        href = link.get('href', '')
        text = (link.get_text(strip=True) or '').lower()
        href_lower = href.lower()

        if 'privacy' in text or 'privacy' in href_lower:
            has_privacy_policy = True
        if any(kw in text for kw in ['terms', 'condition']) or any(kw in href_lower for kw in ['terms', 'condition']):
            has_terms = True
        if any(kw in text for kw in ['contact', 'support']) or any(kw in href_lower for kw in ['contact', 'support']):
            has_contact = True

        abs_url = urljoin(str(resp.url), href)
        try:
            link_host = urlparse(abs_url).hostname
            if not link_host:
                continue
            if any(s in link_host for s in SHORTENERS):
                shortened_urls += 1
            if link_host == domain:
                internal_links += 1
            else:
                external_links += 1
        except Exception:
            continue

    total_links = internal_links + external_links

    iframes = len(soup.find_all('iframe'))
    scripts = len(soup.find_all('script'))
    meta_tags = len(soup.find_all('meta'))

    is_https = str(resp.url).startswith('https://')

    cookies = []
    for cookie in resp.cookies:
        cookies.append(cookie.name)

    return {
        "url": str(resp.url),
        "domain": domain,
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "formCount": form_count,
        "loginForms": login_forms,
        "paymentForms": payment_forms,
        "passwordFields": password_fields,
        "externalFormActions": external_form_actions,
        "detectedKeywords": detected_keywords,
        "iframes": iframes,
        "scriptCount": scripts,
        "metaCount": meta_tags,
        "dataFields": {
            "nameFields": name_fields,
            "emailFields": email_fields,
            "phoneFields": phone_fields,
            "addressFields": address_fields,
            "dobFields": dob_fields,
            "creditCardFields": credit_card_fields,
            "fileUploadFields": file_upload_fields
        },
        "links": {
            "internalLinks": internal_links,
            "externalLinks": external_links,
            "shortenedUrls": shortened_urls,
            "totalLinks": total_links
        },
        "trust": {
            "isHttps": is_https,
            "hasPrivacyPolicy": has_privacy_policy,
            "hasTerms": has_terms,
            "hasContact": has_contact,
            "cookieCount": len(cookies)
        },
        "permissions": {}
    }
