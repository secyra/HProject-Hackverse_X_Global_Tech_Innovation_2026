CATEGORY_WEIGHTS = {
    "phishing": 35,
    "credential_theft": 30,
    "scam": 25,
    "malware": 40,
    "social_engineering": 25,
    "financial": 20,
    "urgency": 10
}

def compute_pre_score(telemetry: dict) -> tuple[int, list[str]]:
    score = 0
    flags = []

    trust = telemetry.get("trust", {})
    links = telemetry.get("links", {})
    data_fields = telemetry.get("dataFields", {})
    security = telemetry.get("security", {})
    hidden = telemetry.get("hiddenElements", {})

    if not trust.get("isHttps", True):
        score += 30
        flags.append("Site is not using HTTPS (unencrypted connection)")

    if not trust.get("hasPrivacyPolicy", True):
        score += 15
        flags.append("No privacy policy link found")

    if not trust.get("hasTerms", True):
        score += 10
        flags.append("No terms & conditions link found")

    if not trust.get("hasContact", True):
        score += 5
        flags.append("No contact or support page found")

    if telemetry.get("externalFormActions", 0) > 0:
        score += 35
        flags.append(f"Form(s) submit data to an external domain ({telemetry['externalFormActions']} found)")

    suspicious_form_actions = telemetry.get("suspiciousFormActions", [])
    if suspicious_form_actions:
        score += 25
        flags.append(f"Suspicious form action URLs detected ({len(suspicious_form_actions)})")

    if telemetry.get("loginForms", 0) > 0 and not trust.get("isHttps", True):
        score += 20
        flags.append("Login form detected on an insecure (non-HTTPS) page")

    keyword_categories = telemetry.get("keywordCategories", {})
    if keyword_categories:
        cat_flags = []
        total_cat_score = 0
        for cat, data in keyword_categories.items():
            weight = CATEGORY_WEIGHTS.get(cat, 15)
            cat_score = min(data["count"] * (weight / 3), weight)
            total_cat_score += cat_score
            cat_flags.append(f"{data['count']} {cat.replace('_', ' ')} keyword(s) detected (severity: {data['maxSeverity']})")

        score += min(total_cat_score, 50)
        flags.extend(cat_flags[:3])
        if len(cat_flags) > 3:
            flags.append(f"Additional threat categories: {', '.join(keyword_categories.keys())}")

    keywords = telemetry.get("detectedKeywords", [])
    keyword_total_severity = telemetry.get("keywordTotalSeverity", 0)
    if keyword_total_severity > 0:
        severity_score = min(keyword_total_severity * 2, 30)
        score += severity_score
    elif keywords and not keyword_categories:
        kw_score = min(len(keywords) * 10, 25)
        score += kw_score
        flags.append(f"Suspicious keywords detected: {', '.join(keywords[:5])}")

    shortened = links.get("shortenedUrls", 0)
    if shortened > 0:
        score += min(shortened * 10, 20)
        flags.append(f"{shortened} shortened URL(s) found (destination hidden)")

    suspicious_links = links.get("suspiciousExternalLinks", [])
    if suspicious_links:
        score += min(len(suspicious_links) * 8, 25)
        flags.append(f"{len(suspicious_links)} suspicious external link(s) detected (potential phishing)")

    low_cred_links = links.get("lowCredibilityLinks", [])
    if low_cred_links:
        score += min(len(low_cred_links) * 5, 15)
        flags.append(f"{len(low_cred_links)} link(s) to low-credibility TLDs detected")

    card_fields = data_fields.get("creditCardFields", 0)
    if card_fields > 0:
        score += 10
        flags.append(f"Credit card input fields detected ({card_fields} found)")

    if telemetry.get("loginForms", 0) > 0 and telemetry.get("passwordFields", 0) > 3:
        score += 10
        flags.append(f"Multiple password fields detected ({telemetry['passwordFields']} found)")

    external_links = links.get("externalLinks", 0)
    internal_links = links.get("internalLinks", 0)
    total_links = external_links + internal_links
    if total_links > 0 and (external_links / total_links) > 0.8:
        score += 15
        flags.append(f"High external link ratio ({external_links}/{total_links} links go off-domain)")

    if telemetry.get("iframes", 0) > 3:
        score += 10
        flags.append(f"High number of iframes detected ({telemetry['iframes']} iframes)")

    if hidden:
        tiny_iframes = hidden.get("tinyIframes", 0)
        if tiny_iframes > 0:
            score += 15
            flags.append(f"{tiny_iframes} tiny/hidden iframe(s) detected (possible clickjacking)")

        hidden_inputs = hidden.get("hiddenInputs", 0)
        if hidden_inputs > 10:
            score += 5
            flags.append(f"High number of hidden input fields ({hidden_inputs})")

    if not security.get("hasCSP", True):
        score += 5
        flags.append("Missing Content-Security-Policy (risk of XSS)")

    net = telemetry.get("network", {})
    third_party_reqs = net.get("thirdPartyRequests", 0)
    if third_party_reqs > 50:
        score += 20
        flags.append(f"Excessive third-party requests ({third_party_reqs})")
    elif third_party_reqs > 20:
        score += 10
        flags.append(f"High number of third-party requests ({third_party_reqs})")

    tracking = net.get("trackingScripts", 0)
    if tracking > 0:
        score += 15
        flags.append(f"Tracking scripts detected ({tracking})")

    ads = net.get("adScripts", 0)
    if ads > 5:
        score += 10
        flags.append(f"Multiple advertising scripts ({ads})")

    analytics = net.get("analyticsScripts", 0)
    if analytics > 3:
        score += 5
        flags.append(f"Multiple analytics scripts ({analytics})")

    score = min(score, 100)

    return score, flags
