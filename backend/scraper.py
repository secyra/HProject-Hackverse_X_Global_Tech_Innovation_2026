import re
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag

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
    domain_norm = domain.removeprefix('www.')
    soup = BeautifulSoup(html, 'lxml')

    forms = soup.find_all('form')
    form_count = len(forms)
    login_forms = 0
    payment_forms = 0
    external_form_actions = 0
    credential_form_found = False
    credential_form_secure = True

    for form in forms:
        action = form.get('action', '')
        abs_action = urljoin(str(resp.url), action) if action else str(resp.url)
        try:
            action_host = urlparse(abs_action).hostname
            if action_host and action_host.removeprefix('www.') != domain_norm:
                external_form_actions += 1
        except Exception:
            pass

        form_text = form.get_text(separator=' ', strip=True).lower()
        has_password = form.find('input', {'type': 'password'}) is not None
        if has_password or any(kw in form_text for kw in ['log in', 'login', 'sign in']):
            login_forms += 1
        if any(kw in form_text for kw in ['payment', 'credit card', 'checkout', 'pay now']):
            payment_forms += 1

        # Detect credential form: has password field or login/checkout submit button
        btn = form.find(['button', 'input'], attrs={'type': ['submit', None]})
        btn_text = (btn.get('value', '') or btn.get_text(strip=True) or '').lower()
        if has_password or any(kw in btn_text for kw in ['sign in', 'log in', 'sign up', 'register', 'create account', 'pay now', 'checkout']):
            credential_form_found = True
            if not str(resp.url).startswith('https://'):
                credential_form_secure = False

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
        inputmode = (inp.get('inputmode', '') or '').lower()
        maxlength = int(inp.get('maxlength', '0') or '0')

        # Get label text (try <label for=""> or <label wrapping="">)
        label_text = ''
        label_for = f'label[for="{inp.get("id", "")}"]' if inp.get('id') else ''
        if label_for:
            label_el = soup.select_one(label_for)
            if label_el:
                label_text = label_el.get_text(strip=True).lower()
        if not label_text:
            parent = inp.parent
            if parent:
                lbl = parent.find('label')
                if lbl:
                    label_text = lbl.get_text(strip=True).lower()

        # Get submit button text from parent form
        submit_text = ''
        parent_form = inp.find_parent('form')
        if parent_form:
            btn = parent_form.find(['button', 'input'], attrs={'type': ['submit', None]})
            if btn:
                submit_text = (btn.get('value', '') or btn.get_text(strip=True) or '').lower()

        # Prioritize autocomplete, label text, inputmode over name/id
        match_text = f"{autocomplete} {label_text} {submit_text} {inputmode} {aria_label} {placeholder} {name} {iid}"

        # Credit card: autocomplete values, type, keywords, or inputmode+numeric+maxlength heuristic
        if (autocomplete in ('cc-number', 'cc-name', 'cc-exp', 'cc-csc') or
            typ == 'cc-number' or
            re.search(r'\b(card|cc|cvv|cvc|expiry|credit.?card)\b', match_text) or
            (inputmode == 'numeric' and 13 <= maxlength <= 19)):
            credit_card_fields += 1
            continue

        # Email
        if typ == 'email' or autocomplete == 'email' or inputmode == 'email' or re.search(r'\b(email|e-mail)\b', match_text):
            email_fields += 1
            continue

        # Phone
        if typ == 'tel' or autocomplete == 'tel' or inputmode == 'tel' or re.search(r'\b(phone|mobile|cell|telephone|tel)\b', match_text):
            phone_fields += 1
            continue

        # Date of birth
        if autocomplete == 'bday' or re.search(r'\b(dob|birth|bday)\b', match_text):
            dob_fields += 1
            continue

        # Address
        if (autocomplete.startswith('address') or autocomplete in ('street-address', 'postal-code', 'country-name') or
            re.search(r'\b(address|street|zip|postcode|postal|city|state|country)\b', match_text)):
            address_fields += 1
            continue

        # Name
        if (autocomplete in ('name', 'given-name', 'family-name', 'full-name') or
            (re.search(r'\bname\b', match_text) and not re.search(r'\b(username|cardname)\b', match_text))):
            name_fields += 1
            continue

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
            if link_host.removeprefix('www.') == domain_norm:
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
    for c in resp.cookies:
        cookies.append(c.name if not isinstance(c, str) else c)

    return {
        "url": str(resp.url),
        "domain": domain,
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "formCount": form_count,
        "loginForms": login_forms,
        "paymentForms": payment_forms,
        "passwordFields": password_fields,
        "externalFormActions": external_form_actions,
        "credentialFormFound": credential_form_found,
        "credentialFormSecure": credential_form_secure,
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


def _extract_header_footer_links(soup: BeautifulSoup, base_url: str, domain: str) -> set[str]:
    candidates = set()

    nav_elements = soup.find_all(['header', 'footer', 'nav'])
    nav_elements += soup.find_all(['div', 'section'],
                                   class_=lambda c: c and any(
                                       kw in (c or '').lower() for kw in ['header', 'footer', 'nav', 'navigation', 'topbar', 'bottombar']))
    nav_elements += soup.find_all(['div', 'section'],
                                   id=lambda i: i and any(
                                       kw in (i or '').lower() for kw in ['header', 'footer', 'nav', 'navigation', 'topbar', 'bottombar']))

    for section in nav_elements:
        for link in section.find_all('a', href=True):
            href = link.get('href', '').strip()
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
            abs_url = urljoin(base_url, href)
            abs_url = urldefrag(abs_url)[0]
            try:
                link_host = urlparse(abs_url).hostname
                if link_host:
                    link_norm = link_host.removeprefix('www.')
                    domain_norm = domain.removeprefix('www.')
                    if link_norm == domain_norm:
                        candidates.add(abs_url)
            except Exception:
                continue

    return candidates


async def _parse_robots_txt(domain: str) -> set[str]:
    robots_url = f"https://{domain}/robots.txt"
    paths = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        try:
            resp = await client.get(robots_url, headers=headers)
            if resp.status_code != 200:
                return paths
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    paths.add(sitemap_url)
                elif line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        paths.add(f"https://{domain}{path}")
                elif line.lower().startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        paths.add(f"https://{domain}{path}")
        except Exception:
            pass
    return paths


RELEVANT_PATH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'auth', 'account', 'register', 'signup', 'sign-up',
    'checkout', 'cart', 'payment', 'pay', 'billing',
    'admin', 'dashboard', 'panel', 'cms',
    'profile', 'settings', 'password', 'reset-password', 'forgot',
    'order', 'orders', 'invoice', 'receipt',
    'subscription', 'membership', 'upgrade',
    'support', 'help', 'contact',
    'download', 'files', 'upload',
    'api', 'graphql', 'wp-json',
    'sso', 'oauth', 'callback',
    'token', 'verify', 'confirm',
    'bank', 'transfer', 'deposit', 'withdraw',
]


def _is_relevant_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(kw in path for kw in RELEVANT_PATH_KEYWORDS)


async def deep_crawl(target_url: str, max_pages: int = 20) -> dict:
    parsed = urlparse(target_url)
    domain = parsed.hostname or "unknown"
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    if not domain or domain == "unknown":
        return {"error": "Invalid URL: could not parse domain", "pages": [], "pages_count": 0}

    main_result = await scrape_url(target_url)
    if "error" in main_result:
        return {"error": main_result["error"], "pages": [], "pages_count": 0}

    try:
        html = await _fetch_html(target_url)
        soup = BeautifulSoup(html, 'lxml')
    except Exception as e:
        soup = BeautifulSoup("", 'lxml')

    discovered_raw = _extract_header_footer_links(soup, base_url, domain)
    robots_links = await _parse_robots_txt(domain)

    all_paths = discovered_raw | robots_links
    all_paths.discard(target_url.rstrip('/'))
    all_paths.discard(base_url.rstrip('/'))
    all_paths.discard(target_url)
    all_paths.discard(base_url)

    relevant = sorted(u for u in all_paths if _is_relevant_url(u))
    irrelevant_count = len(all_paths) - len(relevant)

    pages_data = []
    for page_url in relevant[:max_pages]:
        result = await scrape_url(page_url)
        if "error" not in result:
            pages_data.append(result)

    pages_data.insert(0, main_result)

    all_flagged = []
    page_scores = []
    high_risk_pages = []
    from scorer import compute_pre_score
    for page in pages_data:
        try:
            score, issues = compute_pre_score(page)
        except Exception:
            score, issues = 0, []
        page["_pre_score"] = score
        page["_flagged_issues"] = issues
        page_scores.append(score)
        all_flagged.extend(issues)
        if score >= 40:
            high_risk_pages.append(page.get("url", ""))

    from collections import Counter
    worst_score = max(page_scores) if page_scores else 0
    total_forms = sum(p.get("formCount", 0) for p in pages_data)
    total_logins = sum(p.get("loginForms", 0) for p in pages_data)
    total_passwords = sum(p.get("passwordFields", 0) for p in pages_data)
    total_external_actions = sum(p.get("externalFormActions", 0) for p in pages_data)

    return {
        "enabled": True,
        "pages_count": len(pages_data),
        "sources": {
            "header_footer_count": len(discovered_raw),
            "robots_txt_count": len(robots_links),
            "irrelevant_skipped": irrelevant_count,
        },
        "aggregated": {
            "worst_score": worst_score,
            "total_flagged_issues": list(dict.fromkeys(all_flagged)),
            "high_risk_pages": high_risk_pages,
            "total_forms_across_pages": total_forms,
            "total_login_forms": total_logins,
            "total_password_fields": total_passwords,
            "total_external_form_actions": total_external_actions,
        },
        "pages": [
            {
                "url": p.get("url", ""),
                "title": p.get("title", ""),
                "pre_score": p.get("_pre_score", 0),
                "flagged_issues": p.get("_flagged_issues", []),
                "formCount": p.get("formCount", 0),
                "loginForms": p.get("loginForms", 0),
            }
            for p in pages_data
        ]
    }


async def _fetch_html(url: str) -> str:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return ""
        return resp.text
