from __future__ import annotations

import ipaddress
import json
import os
import socket
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


IP_API_FIELDS = (
    "status,message,country,countryCode,regionName,city,lat,lon,timezone,"
    "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)

_DC_KEYWORDS = (
    "amazon", "aws", "google cloud", "microsoft azure", "azure", "digitalocean",
    "ovh", "hetzner", "linode", "vultr", "contabo", "alibaba", "tencent",
    "hosting", "datacenter", "data center", "server", "cloud", "colo", "vps",
)


def _blank_result(ip: str) -> dict:
    return {
        "ip": ip,
        "country": None, "country_code": None, "region": None, "city": None,
        "lat": None, "lon": None, "timezone": None,
        "isp": None, "org": None, "asn": None, "asn_name": None,
        "reverse_dns": None,
        "is_hosting": None, "is_proxy_or_vpn": None, "is_mobile": None,
        "infrastructure_type": "unknown",
        "sources": [],
        "error": None,
    }


@lru_cache(maxsize=4096)
def reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _lookup_maxmind(ip: str, db_dir: str) -> Optional[dict]:
    if not _HAS_GEOIP2:
        return None
    city_db = os.path.join(db_dir, "GeoLite2-City.mmdb")
    asn_db = os.path.join(db_dir, "GeoLite2-ASN.mmdb")
    out: dict = {}
    try:
        if os.path.exists(city_db):
            with geoip2.database.Reader(city_db) as r:
                c = r.city(ip)
                out.update({
                    "country": c.country.name,
                    "country_code": c.country.iso_code,
                    "region": c.subdivisions.most_specific.name,
                    "city": c.city.name,
                    "lat": c.location.latitude,
                    "lon": c.location.longitude,
                    "timezone": c.location.time_zone,
                })
        if os.path.exists(asn_db):
            with geoip2.database.Reader(asn_db) as r:
                a = r.asn(ip)
                out.update({
                    "asn": f"AS{a.autonomous_system_number}",
                    "asn_name": a.autonomous_system_organization,
                    "isp": a.autonomous_system_organization,
                })
    except Exception:
        return out or None
    return out or None


def _lookup_ip_api(ip: str, timeout: float = 6.0) -> Optional[dict]:
    if not _HAS_REQUESTS:
        return None
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}", params={"fields": IP_API_FIELDS}, timeout=timeout
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": (data.get("as") or "").split(" ")[0] or None,
            "asn_name": data.get("asname"),
            "reverse_dns": data.get("reverse") or None,
            "is_hosting": data.get("hosting"),
            "is_proxy_or_vpn": data.get("proxy"),
            "is_mobile": data.get("mobile"),
        }
    except Exception:
        return None


def _classify_infrastructure(res: dict) -> str:
    if res.get("is_proxy_or_vpn"):
        return "proxy/vpn/anonymizer"
    if res.get("is_hosting"):
        return "datacenter/hosting"
    blob = " ".join(str(res.get(k) or "") for k in ("isp", "org", "asn_name")).lower()
    if any(k in blob for k in _DC_KEYWORDS):
        return "datacenter/hosting"
    if res.get("is_mobile"):
        return "mobile network"
    if res.get("isp") or res.get("asn_name"):
        return "residential/business ISP"
    return "unknown"


@lru_cache(maxsize=4096)
def enrich_ip(ip: str, db_dir: str | None = None, use_online: bool = True) -> str:
    db_dir = db_dir or os.environ.get("GEOLITE2_DIR", "./geolite2")
    res = _blank_result(ip)

    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local:
            res["error"] = "private/internal IP — not geolocatable"
            res["infrastructure_type"] = "internal network"
            return json.dumps(res)
    except ValueError:
        res["error"] = "invalid IP address"
        return json.dumps(res)

    mm = _lookup_maxmind(ip, db_dir)
    if mm:
        res.update({k: v for k, v in mm.items() if v is not None})
        res["sources"].append("maxmind_geolite2")

    if use_online:
        api = _lookup_ip_api(ip)
        if api:
            for k, v in api.items():
                if v is not None and (res.get(k) is None or k in ("is_hosting", "is_proxy_or_vpn", "is_mobile")):
                    res[k] = v
            res["sources"].append("ip-api.com")

    if res.get("reverse_dns") is None:
        res["reverse_dns"] = reverse_dns(ip)
        if res["reverse_dns"]:
            res["sources"].append("ptr_lookup")

    res["infrastructure_type"] = _classify_infrastructure(res)
    if not res["sources"]:
        res["error"] = "no geo data available (offline and no local GeoLite2 DB found)"
    return json.dumps(res)


def lookup_ip(ip: str, db_dir: str | None = None, use_online: bool = True) -> dict:
    return json.loads(enrich_ip(ip, db_dir, use_online))
