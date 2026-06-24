import base64
import json
from google import genai
from google.genai import types

VISION_PROMPT = """You are a phishing detection expert analyzing a screenshot of a webpage.

Examine this screenshot carefully for visual signs of deception. Focus on:

1. **Brand Impersonation** — Does the page copy the look and feel of a well-known brand (PayPal, Apple, Google, Microsoft, Amazon, banking sites, etc.) but with subtle visual inconsistencies?

2. **Fake Security Badges** — Are there fake SSL padlocks, "Verified by" seals, trust badges, or security certificates that appear unprofessional or out of place?

3. **Urgency Banners & Countdowns** — Are there elements creating false urgency (e.g. "Your account will be suspended!", "Limited time offer!", countdown timers, fake expiration warnings)?

4. **Cloned UI Layouts** — Does the page layout resemble a login portal, payment form, or sensitive data entry form that may be cloned? Look for mismatched fonts, pixel alignment issues, or low-resolution logos.

5. **Suspicious Visual Elements** — Any other visually suspicious elements such as misleading buttons, fake progress bars, deceptive overlays, or hidden redirects?

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "vision_analysis": "<1-2 sentence summary of what the screenshot shows visually>",
  "brand_impersonation": {
    "detected": true/false,
    "suspected_brand": "<brand name or null>",
    "details": "<specific observations>"
  },
  "fake_badges": {
    "detected": true/false,
    "badges_found": ["<badge type>"],
    "details": "<specific observations>"
  },
  "urgency_tactics": {
    "detected": true/false,
    "elements_found": ["<urgency element>"],
    "details": "<specific observations>"
  },
  "cloned_ui": {
    "detected": true/false,
    "details": "<specific observations>"
  },
  "visual_risk_score": <0-100, where 0 is safe and 100 is clearly malicious>,
  "visual_flags": ["<specific visual red flag>"]
}
"""


def analyze_screenshot(screenshot_base64: str, client: genai.Client) -> dict | None:
    if not screenshot_base64:
        return None

    try:
        image_data = base64.b64decode(screenshot_base64)
        image_part = types.Part.from_bytes(data=image_data, mime_type="image/png")

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[VISION_PROMPT, image_part],
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

    except Exception:
        return None
