from __future__ import annotations
import re
from email.message import Message
from typing import Optional, List, Dict, Any
from .hop_parser import Hop, is_private_ip, valid_ip

REPUTABLE_DOMAINS = (
    "google.com", "googlemail.com", "gmail.com", "1e100.net",
    "outlook.com", "hotmail.com", "microsoft.com", "office365.com",
    "yahoo.com", "yahoo.co.in", "yahoodns.net", "sendgrid.net",
    "mailgun.org", "amazonses.com", "zoho.com", "protonmail.ch", "apple.com"
)

def _is_reputable(host: Optional[str]) -> bool:
    if not host: return False
    h = host.lower().strip("[]().")
    return any(h == d or h.endswith("." + d) for d in REPUTABLE_DOMAINS)

def _get_x_ip(msg: Message) -> Optional[str]:
    for h in ("X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Apparently-From"):
        v = msg.get(h)
        if v:
            m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(v))
            if m and valid_ip(m.group(0)) and not is_private_ip(m.group(0)):
                return m.group(0)
    return None

def resolve_origin(hops: List[Hop], auth: Dict[str, Any], msg: Message) -> Dict[str, Any]:
    """Stage B: Top-Down Trust-Walk Origin Resolution."""
    notes = []
    if not hops:
        x_ip = _get_x_ip(msg)
        return {
            "probable_source_ip": x_ip, "origin_basis": "x_originating_ip" if x_ip else "no_received_headers",
            "confidence": "medium" if x_ip else "low", "edge_ip": None, "claimed_origin_ip": x_ip,
            "claimed_is_verified": False, "via_provider": False, "origin_hop_index": None,
            "attribution_note": "No Received headers found.", "notes": ["No Received headers present."]
        }

    # 1. Edge Hop & IP (top-down)
    edge_idx = next((i for i, h in enumerate(hops) if h.from_ip and not h.is_private_ip), None)
    edge_ip = hops[edge_idx].from_ip if edge_idx is not None else auth.get("spf", {}).get("client_ip")

    # 2. Bottom Claimed IP
    claimed_hop = next((h for h in reversed(hops) if h.from_ip and not h.is_private_ip), None)
    claimed_ip = claimed_hop.from_ip if claimed_hop else None

    # 3. Forged Header Tripwires
    has_skew = False
    for h in hops:
        if h.delay_seconds is not None and h.delay_seconds < -30:
            has_skew = True
            notes.append(f"Hop {h.index}: NEGATIVE time delta ({h.delay_seconds:.0f}s) — forged header or skewed clock.")
        if h.helo_literal_ip and h.from_ip and not h.is_private_ip:
            notes.append(f"Hop {h.index}: sender identified by raw IP literal [{h.from_ip}].")

    # 4. Top-Down Trust Walk
    trusted_ip, trusted_idx, basis, via_provider = edge_ip, edge_idx, "edge_received_hop", False
    if edge_idx is not None:
        if _is_reputable(hops[edge_idx].by_host) or _is_reputable(hops[edge_idx].from_host):
            via_provider = True
        for next_i in range(edge_idx + 1, len(hops)):
            parent = hops[next_i - 1]
            if _is_reputable(parent.by_host) or _is_reputable(parent.from_host):
                curr = hops[next_i]
                if curr.from_ip and not curr.is_private_ip:
                    trusted_ip, trusted_idx, basis = curr.from_ip, next_i, "reputable_relay_descent"
                elif curr.protocol == "ESMTPSA" and curr.from_ip:
                    trusted_ip, trusted_idx, basis = curr.from_ip, next_i, "esmtpsa_submission"
            else:
                if claimed_ip != trusted_ip:
                    notes.append(f"Trust walk stopped at Hop {next_i}: intermediate writer untrusted. Claimed IP [{claimed_ip}] treated as unverified.")
                break

    # 5. X-Originating-IP
    x_ip = _get_x_ip(msg)
    if x_ip and via_provider:
        trusted_ip, basis = x_ip, "x_originating_ip"

    verified = (claimed_ip == trusted_ip) if (claimed_ip and trusted_ip) else False
    if claimed_ip and trusted_ip and not verified:
        notes.append(f"Origin divergence: verified edge IP [{trusted_ip}] differs from claimed [{claimed_ip}] (forgery tripwire).")

    confidence = "low" if (has_skew or not trusted_ip) else ("high" if (auth.get("summary") in ("failed", "authenticated") or basis != "edge_received_hop") else "medium")

    return {
        "probable_source_ip": trusted_ip,
        "origin_basis": basis,
        "confidence": confidence,
        "edge_ip": edge_ip,
        "claimed_origin_ip": claimed_ip,
        "claimed_is_verified": verified,
        "via_provider": via_provider,
        "origin_hop_index": trusted_idx,
        "attribution_note": f"Traced via {basis.replace('_', ' ')}: {trusted_ip or 'unknown'} (Edge: {edge_ip or 'none'}, Claimed: {claimed_ip or 'none'}).",
        "notes": notes,
    }
