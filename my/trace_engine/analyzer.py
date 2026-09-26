from __future__ import annotations
import email, email.policy
from typing import Union, Optional, Dict, Any, List
from .hop_parser import parse_hops
from .origin_resolver import resolve_origin
from .auth_checker import check_authentication
from .geo_intel import lookup_ip
from .sender_locator import estimate_sender_location

def _risk_assessment(auth: Dict[str, Any], origin_res: Dict[str, Any], origin_geo: Optional[Dict[str, Any]], hops_count: int, notes: List[str]) -> Dict[str, Any]:
    score, reasons = 0, []
    # 1. Auth Failures (up to 45 pts)
    summary = auth.get("summary")
    if summary == "failed": score += 45; reasons.append("Email authentication failed (SPF/DKIM/DMARC).")
    elif summary == "unknown": score += 15; reasons.append("No authentication results available.")
    elif summary == "partially_authenticated": score += 10; reasons.append("Partial authentication passed.")

    # 2. Identity Mismatch (10 pts)
    for flag in auth.get("flags", []):
        if any(w in flag.lower() for w in ("differs from", "impersonation", "spoofing")):
            score += 10; reasons.append(flag); break

    # 3. Forged Header Tripwires (15 pts)
    if not origin_res.get("claimed_is_verified") and origin_res.get("claimed_origin_ip"):
        if origin_res.get("claimed_origin_ip") != origin_res.get("probable_source_ip"):
            score += 15; reasons.append(f"Forged header tripwire: Claimed IP [{origin_res.get('claimed_origin_ip')}] differs from edge [{origin_res.get('probable_source_ip')}].")

    for n in notes:
        if "NEGATIVE time delta" in n: score += 15; reasons.append(n)
        elif "IP literal" in n: score += 10; reasons.append(n)

    # 4. Headerless Injection (20 pts)
    if hops_count == 0: score += 20; reasons.append("No Received headers present — possible local injection.")

    # 5. Infrastructure Risk (Anonymizer 15, Datacenter 10, Missing PTR 5)
    if origin_geo:
        infra = origin_geo.get("infrastructure_type", "")
        if origin_geo.get("is_proxy_or_vpn") or infra == "proxy/vpn/anonymizer":
            score += 15; reasons.append(f"Origin IP [{origin_geo.get('ip')}] is a known proxy/VPN/Tor node.")
        elif infra == "datacenter/hosting":
            score += 10; reasons.append(f"Origin IP [{origin_geo.get('ip')}] is datacenter/cloud infrastructure ({origin_geo.get('isp') or 'Hosting'}).")
        if origin_geo.get("reverse_dns") is None and origin_geo.get("error") is None:
            score += 5; reasons.append(f"Origin IP [{origin_geo.get('ip')}] has no reverse DNS (PTR) record.")

    score = min(score, 100)
    level = "high" if score >= 60 else ("medium" if score >= 30 else "low")
    return {"trace_risk_score": score, "trace_risk_level": level, "reasons": reasons}

def analyze_email(raw: Union[bytes, str], geolite_dir: Optional[str] = None, use_online_geo: bool = True) -> Dict[str, Any]:
    """Unified Email Threat Trace Engine: executes Stages A through E."""
    if isinstance(raw, str): raw = raw.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    hops = parse_hops(msg)
    auth = check_authentication(msg)
    origin_res = resolve_origin(hops, auth, msg)

    prob_ip = origin_res.get("probable_source_ip")
    edge_ip = origin_res.get("edge_ip")
    notes = list(dict.fromkeys(origin_res.get("notes", [])))

    origin_geo = lookup_ip(prob_ip, geolite_dir, use_online_geo) if prob_ip else None
    edge_geo = lookup_ip(edge_ip, geolite_dir, use_online_geo) if (edge_ip and edge_ip != prob_ip) else None

    hop_route = []
    for h in reversed(hops):
        entry = h.to_dict()
        if h.from_ip and not h.is_private_ip:
            g = lookup_ip(h.from_ip, geolite_dir, use_online_geo)
            entry["geo"] = {k: g.get(k) for k in ("country", "country_code", "city", "lat", "lon", "isp", "asn", "infrastructure_type")}
        else:
            entry["geo"] = None
        hop_route.append(entry)

    sender_location = estimate_sender_location(msg, hops, origin_res, geolite_dir, use_online_geo)
    actual_sender = sender_location.get("primary_estimate") or {}

    is_provider_relay = origin_res.get("via_provider") or (
        origin_geo and any(p in str(origin_geo.get("isp", "")).lower() for p in ("google", "microsoft", "yahoo", "zoho", "apple", "fastmail", "mailgun", "sendgrid", "amazon"))
    )
    if is_provider_relay and origin_geo and actual_sender.get("country"):
        origin_geo["relay_country"] = origin_geo.get("country")
        origin_geo["relay_country_code"] = origin_geo.get("country_code")
        origin_geo["relay_city"] = origin_geo.get("city")
        origin_geo["relay_isp"] = origin_geo.get("isp")
        origin_geo["country"] = actual_sender.get("country")
        origin_geo["country_code"] = actual_sender.get("country_code")
        origin_geo["city"] = actual_sender.get("city") or ""
        origin_geo["region"] = actual_sender.get("region") or ""
        origin_geo["location_source"] = "sender_device_signal_fusion"
    elif actual_sender.get("confidence") == "high" and origin_geo:
        origin_geo["country"] = actual_sender.get("country")
        origin_geo["country_code"] = actual_sender.get("country_code")
        origin_geo["city"] = actual_sender.get("city") or origin_geo.get("city")
        origin_geo["location_source"] = "sender_device_signal_fusion"

    risk = _risk_assessment(auth, origin_res, origin_geo, len(hops), notes)


    return {
        "module": "trace_engine", "version": "1.0.0",
        "message_meta": {
            "message_id": str(msg.get("Message-ID", "")).strip() or None,
            "subject": str(msg.get("Subject", "")) or None,
            "from": str(msg.get("From", "")) or None,
            "to": str(msg.get("To", "")) or None,
            "date": str(msg.get("Date", "")) or None,
        },
        "delivery_path": {"hops_count": len(hops), "hops": hop_route, "notes": notes},
        "origin": {
            "probable_source_ip": prob_ip, "origin_basis": origin_res.get("origin_basis"),
            "origin_hop_index": origin_res.get("origin_hop_index"), "confidence": origin_res.get("confidence"),
            "via_provider": origin_res.get("via_provider"), "attribution_note": origin_res.get("attribution_note"),
            "geo": origin_geo, "edge_ip": edge_ip, "edge_geo": edge_geo,
            "claimed_origin_ip": origin_res.get("claimed_origin_ip"), "claimed_is_verified": origin_res.get("claimed_is_verified"),
            "spf_edge_ip": auth.get("spf", {}).get("client_ip"), "spf_edge_geo": edge_geo,
        },
        "authentication": auth,
        "sender_location_estimate": sender_location,
        "risk": risk,
    }
