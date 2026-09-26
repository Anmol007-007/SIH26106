from __future__ import annotations
import ipaddress, json, os, socket
from functools import lru_cache
from typing import Optional

try:
    import geoip2.database
    _HAS_GEOIP2 = True
except ImportError:
    _HAS_GEOIP2 = False

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_DC = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode", "vultr", "hosting", "datacenter", "vps")

def _blank(ip: str) -> dict:
    return {"ip": ip, "country": None, "country_code": None, "region": None, "city": None, "lat": None, "lon": None,
            "timezone": None, "isp": None, "org": None, "asn": None, "asn_name": None, "reverse_dns": None,
            "is_hosting": None, "is_proxy_or_vpn": None, "is_mobile": None, "infrastructure_type": "unknown",
            "sources": [], "error": None}

@lru_cache(maxsize=4096)
def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def _lookup_maxmind(ip: str, db_dir: str) -> Optional[dict]:
    if not _HAS_GEOIP2: return None
    c_db, a_db = os.path.join(db_dir, "GeoLite2-City.mmdb"), os.path.join(db_dir, "GeoLite2-ASN.mmdb")
    out = {}
    try:
        if os.path.exists(c_db):
            with geoip2.database.Reader(c_db) as r:
                c = r.city(ip)
                out.update({"country": c.country.name, "country_code": c.country.iso_code, "region": c.subdivisions.most_specific.name,
                            "city": c.city.name, "lat": c.location.latitude, "lon": c.location.longitude, "timezone": c.location.time_zone})
        if os.path.exists(a_db):
            with geoip2.database.Reader(a_db) as r:
                a = r.asn(ip)
                out.update({"asn": f"AS{a.autonomous_system_number}", "asn_name": a.autonomous_system_organization, "isp": a.autonomous_system_organization})
    except Exception: pass
    return out or None

def _lookup_ip_api(ip: str, timeout: float = 2.0) -> Optional[dict]:
    if not _HAS_REQUESTS: return None
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting", timeout=timeout).json()
        if r.get("status") != "success": return None
        return {"country": r.get("country"), "country_code": r.get("countryCode"), "region": r.get("regionName"), "city": r.get("city"),
                "lat": r.get("lat"), "lon": r.get("lon"), "timezone": r.get("timezone"), "isp": r.get("isp"), "org": r.get("org"),
                "asn": (r.get("as") or "").split(" ")[0] or None, "asn_name": r.get("asname"), "reverse_dns": r.get("reverse"),
                "is_hosting": r.get("hosting"), "is_proxy_or_vpn": r.get("proxy"), "is_mobile": r.get("mobile")}
    except Exception: return None

def _classify(res: dict) -> str:
    if res.get("is_proxy_or_vpn"): return "proxy/vpn/anonymizer"
    if res.get("is_hosting"): return "datacenter/hosting"
    blob = " ".join(str(res.get(k) or "") for k in ("isp", "org", "asn_name")).lower()
    if any(k in blob for k in _DC): return "datacenter/hosting"
    if res.get("is_mobile"): return "mobile network"
    return "residential/business ISP" if (res.get("isp") or res.get("asn_name")) else "unknown"

def _resolve_dir(d: Optional[str]) -> str:
    if d and os.path.isdir(d): return d
    env = os.environ.get("GEOLITE2_DIR")
    if env and os.path.isdir(env): return env
    mod = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "geolite2")
    return mod if os.path.isdir(mod) else "./geolite2"

@lru_cache(maxsize=4096)
def enrich_ip(ip: str, db_dir: Optional[str] = None, use_online: bool = True) -> str:
    res = _blank(ip)
    try:
        o = ipaddress.ip_address(ip)
        if o.is_private or o.is_loopback or o.is_link_local:
            res["error"], res["infrastructure_type"] = "private/internal IP", "internal network"
            return json.dumps(res)
    except ValueError:
        res["error"] = "invalid IP address"
        return json.dumps(res)

    mm = _lookup_maxmind(ip, _resolve_dir(db_dir))
    if mm:
        res.update(mm)
        res["sources"].append("maxmind_geolite2")

    if use_online and not res.get("country"):
        api = _lookup_ip_api(ip)
        if api:
            res.update({k: v for k, v in api.items() if v is not None})
            res["sources"].append("ip-api.com")

    if use_online and not res.get("reverse_dns"):
        res["reverse_dns"] = reverse_dns(ip)
        if res["reverse_dns"]: res["sources"].append("ptr_lookup")

    res["infrastructure_type"] = _classify(res)
    return json.dumps(res)

def lookup_ip(ip: str, db_dir: Optional[str] = None, use_online: bool = True) -> dict:
    return json.loads(enrich_ip(ip, db_dir, use_online))
