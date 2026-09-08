from __future__ import annotations
import email
import email.policy
from typing import Union
from .hop_parser import parse_hops, find_origin_ip
from .auth_checker import check_authentication
from .geo_intel import lookup_ip
def _risk_assessment(auth: dict, trace_notes: list[str], origin_geo: dict | None,
                     hops_count: int) -> dict:
    score = 0
    reasons: list[str] = []
    if auth["summary"] == "failed":
        score += 45
        reasons.append("Email authentication failed (SPF/DKIM/DMARC).")
    elif auth["summary"] == "unknown":
        score += 15
        reasons.append("No authentication results available.")
    elif auth["summary"] == "partially_authenticated":
        score += 10
        reasons.append("Only partial authentication (not all of SPF/DKIM/DMARC passed).")
    for f in auth["flags"]:
        if "impersonation" in f or "spoofing" in f.lower():
            score += 10
            reasons.append(f)
    for n in trace_notes:
        if "NEGATIVE time delta" in n:
            score += 15
            reasons.append(n)
        if "IP literal" in n:
            score += 10
            reasons.append(n)
    if hops_count == 0:
        score += 20
        reasons.append("No Received headers at all — message may be locally injected or forged.")
    if origin_geo:
        infra = origin_geo.get("infrastructure_type", "")
        if origin_geo.get("is_proxy_or_vpn"):
            score += 15
            reasons.append("Origin IP is a known proxy/VPN/anonymizer.")
        elif infra == "datacenter/hosting":
            score += 10
            reasons.append("Origin IP belongs to datacenter/hosting infrastructure "
                           "(legit bulk senders also do this, but so do phishers).")
        if origin_geo.get("reverse_dns") is None and origin_geo.get("error") is None:
            score += 5
            reasons.append("Origin IP has no reverse DNS (PTR) record.")
    score = min(score, 100)
    level = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {"trace_risk_score": score, "trace_risk_level": level, "reasons": reasons}
def analyze_email(raw: Union[bytes, str], geolite_dir: str | None = None,
                  use_online_geo: bool = True) -> dict:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    hops = parse_hops(msg)
    origin_ip, origin_hop, trace_notes = find_origin_ip(hops)
    auth = check_authentication(msg)
    spf_ip = auth["spf"].get("client_ip")
    if spf_ip and origin_ip and spf_ip != origin_ip:
        trace_notes.append(
            f"SPF client-ip ({spf_ip}) differs from bottom-hop IP ({origin_ip}). "
            f"Reporting bottom-hop as origin but flagging the edge IP too."
        )
    origin_geo = None
    if origin_ip:
        origin_geo = lookup_ip(origin_ip, geolite_dir, use_online_geo)
    edge_geo = None
    if spf_ip and spf_ip != origin_ip:
        edge_geo = lookup_ip(spf_ip, geolite_dir, use_online_geo)
    hop_route = []
    for hop in reversed(hops):
        entry = hop.to_dict()
        if hop.from_ip and not hop.is_private_ip:
            g = lookup_ip(hop.from_ip, geolite_dir, use_online_geo)
            entry["geo"] = {k: g.get(k) for k in
                            ("country", "country_code", "city", "lat", "lon",
                             "isp", "asn", "infrastructure_type")}
        else:
            entry["geo"] = None
        hop_route.append(entry)
    risk = _risk_assessment(auth, trace_notes, origin_geo, len(hops))
    return {
        "module": "trace_engine",
        "version": "0.1.0",
        "message_meta": {
            "message_id": str(msg.get("Message-ID", "")).strip() or None,
            "subject": str(msg.get("Subject", "")) or None,
            "from": str(msg.get("From", "")) or None,
            "to": str(msg.get("To", "")) or None,
            "date": str(msg.get("Date", "")) or None,
        },
        "delivery_path": {
            "hops_count": len(hops),
            "hops": hop_route,
            "notes": trace_notes,
        },
        "origin": {
            "probable_source_ip": origin_ip,
            "origin_hop_index": origin_hop.index if origin_hop else None,
            "confidence": _origin_confidence(origin_hop, auth, trace_notes),
            "geo": origin_geo,
            "spf_edge_ip": spf_ip,
            "spf_edge_geo": edge_geo,
        },
        "authentication": auth,
        "risk": risk,
    }
def _origin_confidence(origin_hop, auth: dict, notes: list[str]) -> str:
    if origin_hop is None:
        return "low"
    if any("NEGATIVE time delta" in n for n in notes):
        return "low"
    spf_ip = auth["spf"].get("client_ip")
    if spf_ip and origin_hop.from_ip == spf_ip:
        return "high"
    if auth["summary"] == "authenticated":
        return "high"
    if auth["summary"] == "failed":
        return "medium"
    return "medium"
