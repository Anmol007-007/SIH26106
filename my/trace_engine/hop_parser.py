from __future__ import annotations
import ipaddress, re
from dataclasses import dataclass, asdict
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Optional, List, Tuple

@dataclass
class Hop:
    index: int
    raw: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    is_private_ip: bool = False
    is_tls: bool = False
    delay_seconds: Optional[float] = None
    auth_user: Optional[str] = None
    helo_literal_ip: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

_FROM_RE = re.compile(r"from\s+(?P<host>\[?[A-Za-z0-9._:\-]+\]?)(?:\s+\((?P<paren>[^)]*)\))?", re.I)
_BY_RE = re.compile(r"\bby\s+([A-Za-z0-9._\-]+)", re.I)
_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9+\-]+)", re.I)
_IP_RE = re.compile(r"(?:(?<=\[)|(?<=\s)|(?<=\()|^)((?:\d{1,3}\.){3}\d{1,3}|[A-Fa-f0-9:]{2,45}:[A-Fa-f0-9:]*)")
_AUTH_RE = re.compile(r"\b(?:authenticated\s+as|auth=)\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+|[A-Za-z0-9._\-]+)", re.I)

def valid_ip(val: Optional[str]) -> Optional[str]:
    if not val: return None
    s = val.strip("[]() \t\r\n")
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None

def is_private_ip(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local or o.is_reserved or o.is_unspecified
    except ValueError:
        return True

def _extract_ip(text: str) -> Tuple[Optional[str], Optional[str], bool]:
    m = _FROM_RE.search(text)
    host, ip, literal = None, None, False
    if m:
        raw_h = m.group("host") or ""
        host = raw_h.strip("[]")
        literal = bool(valid_ip(raw_h))
        if literal: ip = valid_ip(raw_h)
        for ipm in _IP_RE.finditer(m.group("paren") or ""):
            v = valid_ip(ipm.group(1))
            if v: ip = v; break
    if not ip:
        for ipm in _IP_RE.finditer(text[text.lower().find("from "):] if "from " in text.lower() else text):
            v = valid_ip(ipm.group(1))
            if v: ip = v; break
    return ip, host, literal

def parse_hops(msg: Message) -> List[Hop]:
    """Parse Received headers into chronological hops with delay calculations."""
    hops: List[Hop] = []
    for i, raw in enumerate(msg.get_all("Received") or []):
        v = re.sub(r"\s+", " ", str(raw)).strip()
        h = Hop(index=i, raw=v)
        h.from_ip, h.from_host, h.helo_literal_ip = _extract_ip(v)
        if h.from_ip: h.is_private_ip = is_private_ip(h.from_ip)
        bm = _BY_RE.search(v)
        if bm: h.by_host = bm.group(1)
        wm = _WITH_RE.search(v)
        if wm:
            h.protocol = wm.group(1).upper()
            h.is_tls = "TLS" in h.protocol or h.protocol in ("ESMTPS", "ESMTPSA", "SMTPS")
        am = _AUTH_RE.search(v)
        if am: h.auth_user = am.group(1)
        if ";" in v:
            try: h.timestamp = parsedate_to_datetime(v.rsplit(";", 1)[1].strip()).isoformat()
            except Exception: pass
        hops.append(h)

    for i in range(len(hops) - 1):
        if hops[i].timestamp and hops[i+1].timestamp:
            try:
                from datetime import datetime
                hops[i].delay_seconds = (datetime.fromisoformat(hops[i].timestamp) - datetime.fromisoformat(hops[i+1].timestamp)).total_seconds()
            except Exception: pass
    return hops

def find_origin_ip(hops: List[Hop]) -> Tuple[Optional[str], Optional[Hop], List[str]]:
    """Legacy origin IP extractor."""
    notes = []
    hop = next((h for h in reversed(hops) if h.from_ip and not h.is_private_ip), None)
    ip = hop.from_ip if hop else None
    for h in hops:
        if h.delay_seconds is not None and h.delay_seconds < -30:
            notes.append(f"Hop {h.index}: NEGATIVE time delta ({h.delay_seconds:.0f}s) — possible forged header.")
    return ip, hop, notes
