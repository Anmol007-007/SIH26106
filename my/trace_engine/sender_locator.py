from __future__ import annotations
import re, unicodedata
from email.message import Message
from typing import Dict, Any, List, Optional
from .hop_parser import Hop, valid_ip, is_private_ip
from .geo_intel import lookup_ip

TZ_MAP = {
    "+0530": ("India", "IN"), "+05:30": ("India", "IN"), "+0600": ("Bangladesh", "BD"),
    "+0500": ("Pakistan", "PK"), "+0800": ("China / Singapore", "CN"), "+0900": ("Japan", "JP"),
    "+0300": ("Saudi Arabia / Russia", "RU"), "+0200": ("Eastern Europe", "ZA"),
    "+0100": ("Central Europe", "DE"), "+0000": ("United Kingdom / UTC", "GB"),
    "-0400": ("US Eastern", "US"), "-0500": ("US Eastern", "US"), "-0800": ("US Pacific", "US")
}

_PATTERNS = {
    "upi_ids": (re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|upi|apl)\b", re.I), "S4_UPI_VPA", "Indian UPI / VPA Payment Handle", 0.45, "India", "IN"),
    "phone_numbers": (re.compile(r"(?:\+91[\-\s]?)?[6789]\d{9}\b"), "S4_PHONE_NUMBER", "Indian Telecom Number", 0.40, "India", "IN"),
    "ifsc_codes": (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), "S4_IFSC_CODE", "Indian Banking IFSC Code", 0.45, "India", "IN"),
    "financial_mentions": (re.compile(r"(?:₹|Rs\.?|INR)\s*[\d,]+(?:\.\d{2})?", re.I), "S4_CURRENCY_INR", "Indian Rupee Currency Context", 0.35, "India", "IN"),
}

def _get_body_text(msg: Message) -> str:
    parts = []
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() in ("text/plain", "text/html") and "attachment" not in str(part.get("Content-Disposition", "")):
            payload = part.get_payload(decode=True)
            if payload:
                parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(parts)

def estimate_sender_location(
    msg: Message,
    hops: List[Hop],
    origin_res: Dict[str, Any],
    geolite_dir: Optional[str] = None,
    use_online_geo: bool = True,
) -> Dict[str, Any]:
    """Stage E: Multi-Signal Fusion for Sender Origin Estimation."""
    signals, scores, loc_meta = [], {}, {}
    artifacts = {"client_ips": [], "upi_ids": [], "phone_numbers": [], "ifsc_codes": [], "financial_mentions": [], "detected_scripts": []}

    def credit(country: str, cc: str, weight: float, meta: Dict[str, Any]):
        scores[country] = scores.get(country, 0.0) + weight
        loc_meta.setdefault(country, {"country": country, "country_code": cc, **meta})

    # S1: ESMTPSA / Authenticated Submission Hop
    s1_ip = next((h.from_ip for h in hops if (h.protocol in ("ESMTPSA", "SMTPSA") or h.auth_user) and h.from_ip and not h.is_private_ip), None)
    if s1_ip:
        artifacts["client_ips"].append(s1_ip)
        g = lookup_ip(s1_ip, geolite_dir, use_online_geo)
        c, cc = g.get("country") or "Unknown", g.get("country_code") or "XX"
        credit(c, cc, 0.90, {"city": g.get("city"), "region": g.get("region"), "ip": s1_ip, "isp": g.get("isp")})
        signals.append({"signal_id": "S1_ESMTPSA_SUBMISSION_IP", "name": "Authenticated SMTP Client IP", "weight": 0.90, "value": s1_ip, "estimated_location": f"{g.get('city') or ''}, {c}".strip(", "), "evidence": f"Client authenticated at submission hop with IP {s1_ip} ({c}, {g.get('isp') or 'ISP'})."})

    # S2: X-Originating-IP
    s2_ip = None
    for h in ("X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Apparently-From"):
        v = msg.get(h)
        if v:
            m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(v))
            if m and valid_ip(m.group(0)) and not is_private_ip(m.group(0)):
                s2_ip = m.group(0)
                break
    if s2_ip and s2_ip != s1_ip:
        artifacts["client_ips"].append(s2_ip)
        g = lookup_ip(s2_ip, geolite_dir, use_online_geo)
        c, cc = g.get("country") or "Unknown", g.get("country_code") or "XX"
        credit(c, cc, 0.90, {"city": g.get("city"), "region": g.get("region"), "ip": s2_ip, "isp": g.get("isp")})
        signals.append({"signal_id": "S2_X_ORIGINATING_IP", "name": "Provider Stamped Client IP", "weight": 0.90, "value": s2_ip, "estimated_location": f"{g.get('city') or ''}, {c}".strip(", "), "evidence": f"Webmail header stamped client IP {s2_ip} ({c}, {g.get('isp') or 'ISP'})."})

    # S3: Date Header Timezone
    tz_m = re.search(r"([+\-]\d{4})\b", str(msg.get("Date", "")))
    if tz_m and tz_m.group(1) in TZ_MAP:
        c, cc = TZ_MAP[tz_m.group(1)]
        credit(c, cc, 0.30, {"timezone": tz_m.group(1)})
        signals.append({"signal_id": "S3_DATE_TIMEZONE", "name": "Mail Client Timezone Offset", "weight": 0.30, "value": tz_m.group(1), "estimated_location": c, "evidence": f"Sender client system clock configured with timezone offset {tz_m.group(1)} ({c})."})

    # S4: Content Artifacts
    full_text = f"{msg.get('Subject', '')}\n{_get_body_text(msg)}"
    for key, (pat, sig_id, name, wt, c, cc) in _PATTERNS.items():
        found = pat.findall(full_text)
        if found:
            items = list(dict.fromkeys(found if isinstance(found[0], str) else [x[0] for x in found]))
            artifacts[key].extend(items)
            credit(c, cc, wt, {})
            signals.append({"signal_id": sig_id, "name": name, "weight": wt, "value": ", ".join(items[:3]), "estimated_location": c, "evidence": f"Found {name.lower()} in message: {', '.join(items[:3])}."})

    # S5: Scripts
    scripts = {}
    for ch in full_text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            for s in ("DEVANAGARI", "BENGALI", "TAMIL", "TELUGU", "GUJARATI", "ARABIC", "CYRILLIC"):
                if s in name:
                    scripts[s.capitalize()] = scripts.get(s.capitalize(), 0) + 1
    for s_name, count in scripts.items():
        artifacts["detected_scripts"].append(f"{s_name} ({count} chars)")
        c, cc = ("India", "IN") if s_name in ("Devanagari", "Bengali", "Tamil", "Telugu", "Gujarati") else ("International", "XX")
        if c == "India":
            credit(c, cc, 0.20, {})
        signals.append({"signal_id": "S5_UNICODE_SCRIPT", "name": f"Regional Script: {s_name}", "weight": 0.20, "value": f"{count} chars", "estimated_location": c, "evidence": f"Message contains {count} characters in {s_name} script."})

    # S6: Infrastructure Fallback
    prob_ip = origin_res.get("probable_source_ip")
    if not scores and prob_ip:
        g = lookup_ip(prob_ip, geolite_dir, use_online_geo)
        c, cc = g.get("country") or "Unknown", g.get("country_code") or "XX"
        credit(c, cc, 0.25, {"city": g.get("city"), "region": g.get("region"), "ip": prob_ip, "isp": g.get("isp")})
        signals.append({"signal_id": "S6_INFRASTRUCTURE_GEO", "name": "Relay Infrastructure IP Geolocation", "weight": 0.25, "value": prob_ip, "estimated_location": f"{g.get('city') or ''}, {c}".strip(", "), "evidence": f"Fallback to relay IP {prob_ip} ({g.get('infrastructure_type', 'datacenter')})."})

    ranked = []
    for c, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        m = loc_meta.get(c, {})
        matched = [s["signal_id"] for s in signals if s.get("estimated_location") == c or c in s.get("estimated_location", "")]
        ranked.append({"country": c, "country_code": m.get("country_code", "XX"), "city": m.get("city"), "region": m.get("region"), "ip": m.get("ip"), "isp": m.get("isp"), "confidence_score": round(score, 2), "signals_matched": matched})

    top = ranked[0] if ranked else None
    confidence = "high" if (s1_ip or s2_ip) else ("medium" if len(signals) >= 2 and top and top["confidence_score"] >= 0.60 else ("low" if top else "unknown"))

    return {
        "primary_estimate": {
            "country": top["country"] if top else None,
            "country_code": top["country_code"] if top else None,
            "city": top.get("city") if top else None,
            "region": top.get("region") if top else None,
            "device_ip": top.get("ip") if top else None,
            "confidence": confidence,
            "evidence_count": len(signals),
            "basis": [s["evidence"] for s in signals],
        },
        "ranked_candidates": ranked,
        "signals": signals,
        "investigation_artifacts": {k: list(dict.fromkeys(v)) for k, v in artifacts.items()},
    }
