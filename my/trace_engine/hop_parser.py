from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, asdict
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Optional
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
    def to_dict(self) -> dict:
        return asdict(self)
_FROM_RE = re.compile(
    r"from\s+(?P<host>\[?[A-Za-z0-9._:\-]+\]?)"
    r"(?:\s+\((?P<paren>[^)]*)\))?",
    re.IGNORECASE,
)
_BY_RE = re.compile(r"\bby\s+(?P<by>[A-Za-z0-9._\-]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9+\-]+)", re.IGNORECASE)
_IP_RE = re.compile(
    r"(?:(?<=\[)|(?<=\s)|(?<=\()|^)"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[A-Fa-f0-9:]{2,45}:[A-Fa-f0-9:]*)"
)
def _valid_ip(candidate: str) -> Optional[str]:
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        return candidate.strip("[]")
    except ValueError:
        return None
def _is_private(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved
    except ValueError:
        return True
def _extract_ip_from_header(value: str) -> Optional[str]:
    m = _FROM_RE.search(value)
    if m:
        paren = m.group("paren") or ""
        for ipm in _IP_RE.finditer(paren):
            ip = _valid_ip(ipm.group("ip"))
            if ip:
                return ip
        ip = _valid_ip(m.group("host"))
        if ip:
            return ip
    from_idx = value.lower().find("from ")
    search_space = value[from_idx:] if from_idx >= 0 else value
    for ipm in _IP_RE.finditer(search_space):
        ip = _valid_ip(ipm.group("ip"))
        if ip:
            return ip
    return None
def _extract_timestamp(value: str) -> Optional[str]:
    if ";" not in value:
        return None
    date_part = value.rsplit(";", 1)[1].strip()
    try:
        dt = parsedate_to_datetime(date_part)
        return dt.isoformat()
    except Exception:
        return None
def parse_hops(msg: Message) -> list[Hop]:
    hops: list[Hop] = []
    received_headers = msg.get_all("Received") or []
    for i, raw in enumerate(received_headers):
        value = re.sub(r"\s+", " ", str(raw)).strip()
        hop = Hop(index=i, raw=value)
        m = _FROM_RE.search(value)
        if m:
            hop.from_host = m.group("host").strip("[]")
        b = _BY_RE.search(value)
        if b:
            hop.by_host = b.group("by")
        w = _WITH_RE.search(value)
        if w:
            hop.protocol = w.group("proto").upper()
            hop.is_tls = "TLS" in hop.protocol or hop.protocol == "ESMTPS"
        hop.from_ip = _extract_ip_from_header(value)
        if hop.from_ip:
            hop.is_private_ip = _is_private(hop.from_ip)
        hop.timestamp = _extract_timestamp(value)
        hops.append(hop)
    for i in range(len(hops) - 1):
        t_now, t_prev = hops[i].timestamp, hops[i + 1].timestamp
        if t_now and t_prev:
            try:
                from datetime import datetime
                d = (datetime.fromisoformat(t_now) - datetime.fromisoformat(t_prev)).total_seconds()
                hops[i].delay_seconds = d
            except Exception:
                pass
    return hops
def find_origin_ip(hops: list[Hop]) -> tuple[Optional[str], Optional[Hop], list[str]]:
    notes: list[str] = []
    origin_ip, origin_hop = None, None
    for hop in reversed(hops):
        if hop.from_ip and not hop.is_private_ip:
            origin_ip, origin_hop = hop.from_ip, hop
            break
        if hop.from_ip and hop.is_private_ip:
            notes.append(
                f"Hop {hop.index}: private/internal IP {hop.from_ip} skipped "
                "(mail still inside an internal network)."
            )
    for hop in hops:
        if hop.delay_seconds is not None and hop.delay_seconds < -30:
            notes.append(
                f"Hop {hop.index}: NEGATIVE time delta ({hop.delay_seconds:.0f}s) — "
                "possible forged Received header or badly skewed clock."
            )
        if hop.from_host and hop.from_ip and not hop.is_private_ip:
            if hop.from_host.replace("[", "").replace("]", "") == hop.from_ip:
                notes.append(
                    f"Hop {hop.index}: sender identified only by IP literal "
                    f"[{hop.from_ip}] with no hostname — common for botnet/direct-to-MX spam."
                )
    if origin_ip is None:
        notes.append("No public origin IP could be extracted from Received headers.")
    return origin_ip, origin_hop, notes
