import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from parsing_engine.schema import ParsedEmail
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "paypal.com", "amazon.com",
    "apple.com", "bankofamerica.com", "chase.com",
]
URGENCY_TERMS = [
    "urgent", "verify your account", "account suspended", "act now",
    "wire transfer", "gift card", "password expires", "immediate action",
    "last chance", "offer expires",
]
RISKY_ATTACHMENT_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".html", ".htm", ".iso", ".bat")
URL_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly")
def check_lookalike_domain(domain: str) -> list[str]:
    """Flag if `domain` is suspiciously similar (but not identical) to a trusted domain."""
    flags = []
    if not domain:
        return flags
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted:
            continue                                        
        similarity = SequenceMatcher(None, domain, trusted).ratio()
        if similarity > 0.75:
            flags.append(f"LOOKALIKE_DOMAIN:{domain}~{trusted}")
    return flags
def check_auth_results(parsed: ParsedEmail) -> list[str]:
    flags = []
    if parsed.auth_results.spf == "fail":
        flags.append("SPF_FAIL")
    elif parsed.auth_results.spf == "softfail":
        flags.append("SPF_SOFTFAIL")
    if parsed.auth_results.dkim == "fail":
        flags.append("DKIM_FAIL")
    if parsed.auth_results.dmarc == "fail":
        flags.append("DMARC_FAIL")
    return flags
def check_address_mismatches(parsed: ParsedEmail) -> list[str]:
    flags = []
    if not parsed.from_addr:
        return flags
    from_domain = parsed.from_addr[0][1].split("@")[-1].lower() if "@" in parsed.from_addr[0][1] else ""
    if parsed.reply_to:
        reply_addr = parsed.reply_to[0][1]
        reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
        if reply_domain and reply_domain != from_domain:
            flags.append("REPLY_TO_MISMATCH")
    if parsed.return_path and from_domain and from_domain not in parsed.return_path.lower():
        flags.append("RETURN_PATH_MISMATCH")
    flags += check_lookalike_domain(from_domain)
    return flags
def check_urgency_language(parsed: ParsedEmail) -> list[str]:
    flags = []
    body = (parsed.body_plain + " " + parsed.body_html).lower()
    for term in URGENCY_TERMS:
        if term in body:
            flags.append("URGENCY_LANGUAGE")
            break                                                     
    return flags
def check_urls(parsed: ParsedEmail) -> list[str]:
    flags = []
    for url_info in parsed.urls:
        host = urlparse(url_info.url).hostname or ""
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            flags.append(f"IP_BASED_URL:{url_info.url}")
        if any(s in host for s in URL_SHORTENERS):
            flags.append(f"SHORTENED_URL:{url_info.url}")
        if url_info.anchor_text:
            anchor_lower = url_info.anchor_text.lower()
            for trusted in TRUSTED_DOMAINS:
                brand = trusted.split(".")[0]
                if brand in anchor_lower and url_info.domain != trusted:
                    flags.append(f"ANCHOR_TEXT_MISMATCH:{url_info.anchor_text}->{url_info.domain}")
    return flags
def check_attachments(parsed: ParsedEmail) -> list[str]:
    flags = []
    for att in parsed.attachments:
        if att.filename and att.filename.lower().endswith(RISKY_ATTACHMENT_EXTENSIONS):
            flags.append(f"RISKY_ATTACHMENT:{att.filename}")
    return flags
IMPERSONATION_BRANDS = [
    "microsoft", "google", "paypal", "amazon", "apple", "bank of america",
    "chase", "irs", "ceo", "cfo", "hr department", "it support", "helpdesk",
]
def check_display_name_impersonation(parsed: ParsedEmail) -> list[str]:
    """
    Flags when the display name claims a trusted brand/role, but the
    actual sending domain has no relation to that brand — classic
    impersonation/BEC pattern.
    """
    flags = []
    if not parsed.from_addr:
        return flags
    display_name, email_addr = parsed.from_addr[0]
    if not display_name or "@" not in email_addr:
        return flags
    display_lower = display_name.lower()
    domain = email_addr.split("@")[-1].lower()
    for brand in IMPERSONATION_BRANDS:
        brand_token = brand.split()[0]                                      
        if brand_token in display_lower and brand_token not in domain:
            flags.append(f"DISPLAY_NAME_IMPERSONATION:{display_name}->{domain}")
    return flags
BEC_TERMS = [
    "wire transfer", "change of bank details", "update payment information",
    "urgent payment", "invoice attached", "new account number",
    "confidential transaction", "gift cards", "purchase gift cards",
    "keep this between us", "don't discuss with anyone",
]
def check_bec_language(parsed: ParsedEmail) -> list[str]:
    flags = []
    body = (parsed.body_plain + " " + parsed.body_html).lower()
    for term in BEC_TERMS:
        if term in body:
            flags.append("BEC_LANGUAGE_PATTERN")
            break
    return flags
def run_heuristics(parsed: ParsedEmail) -> dict:
    """Runs all rule-based checks and returns combined flags + a rule score (0-100)."""
    flags = []
    flags += check_auth_results(parsed)
    flags += check_address_mismatches(parsed)
    flags += check_urgency_language(parsed)
    flags += check_urls(parsed)
    flags += check_attachments(parsed)
    flags += check_display_name_impersonation(parsed)
    flags += check_bec_language(parsed) 
    weight_map = {
        "SPF_FAIL": 20, "DKIM_FAIL": 20, "DMARC_FAIL": 20, "SPF_SOFTFAIL": 10,
        "REPLY_TO_MISMATCH": 15, "RETURN_PATH_MISMATCH": 10, "DISPLAY_NAME_IMPERSONATION": 25,
        "URGENCY_LANGUAGE": 8,
        "RISKY_ATTACHMENT": 25,
        "BEC_LANGUAGE_PATTERN": 18,
    }
    score = 0
    for flag in flags:
        base_type = flag.split(":")[0]
        score += weight_map.get(base_type, 12)                                          
    score = min(score, 100)
    return {"flags": flags, "rule_score": score}
import joblib
import os
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
_vectorizer, _clf = None, None
def _load_model():
    global _vectorizer, _clf
    if _vectorizer is None or _clf is None:
        _vectorizer, _clf = joblib.load(_MODEL_PATH)
    return _vectorizer, _clf
def ml_score(parsed: ParsedEmail) -> float:
    vectorizer, clf = _load_model()
    text = f"{parsed.subject} {parsed.body_plain}"
    text_vec = vectorizer.transform([text])
    probability = clf.predict_proba(text_vec)[0][1]
    return float(probability)
FLAG_CATEGORIES = {
    "SPF_FAIL": "auth", "DKIM_FAIL": "auth", "DMARC_FAIL": "auth", "SPF_SOFTFAIL": "auth",
    "REPLY_TO_MISMATCH": "identity", "RETURN_PATH_MISMATCH": "identity",
    "DISPLAY_NAME_IMPERSONATION": "identity", "LOOKALIKE_DOMAIN": "identity",
    "URGENCY_LANGUAGE": "language", "BEC_LANGUAGE_PATTERN": "language",
    "IP_BASED_URL": "url", "SHORTENED_URL": "url", "ANCHOR_TEXT_MISMATCH": "url",
    "RISKY_ATTACHMENT": "attachment",
}
TOTAL_CATEGORIES = 5                                             
def compute_confidence(flags: list[str], ml_prob: float, fraud_score: int) -> float:
    categories_hit = set()
    for flag in flags:
        base_type = flag.split(":")[0]
        categories_hit.add(FLAG_CATEGORIES.get(base_type, "other"))
    diversity_score = len(categories_hit) / TOTAL_CATEGORIES
    distance_to_boundary = min(abs(fraud_score - 40), abs(fraud_score - 75))
    margin_score = min(distance_to_boundary / 37.5, 1.0)
    ml_certainty = abs(ml_prob - 0.5) * 2
    confidence = (0.5 * diversity_score) + (0.3 * margin_score) + (0.2 * ml_certainty)
    return round(min(confidence, 1.0), 2)
def confidence_label(confidence: float) -> str:
    """
    Converts a raw 0.0-1.0 confidence score into a human-readable tier
    for dashboard display.
    """
    if confidence >= 0.75:
        return "Very High"
    elif confidence >= 0.55:
        return "High"
    elif confidence >= 0.35:
        return "Moderate"
    elif confidence >= 0.15:
        return "Low"
    else:
        return "Very Low"
def run_detection(parsed: ParsedEmail) -> dict:
    rule_result = run_heuristics(parsed)
    ml_prob = ml_score(parsed)
    fraud_score = round(0.7 * rule_result["rule_score"] + 0.3 * (ml_prob * 100))
    if fraud_score >= 75:
        category = "phishing"
    elif fraud_score >= 40:
        category = "suspicious"
    else:
        category = "legitimate"
    confidence = compute_confidence(rule_result["flags"], ml_prob, fraud_score)
    return {
        "message_id": parsed.message_id,
        "fraud_score": fraud_score,
        "category": category,
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "flags": rule_result["flags"],
        "ml_confidence": round(ml_prob, 3),
    }
