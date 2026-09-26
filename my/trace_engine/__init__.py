from .analyzer import analyze_email
from .hop_parser import parse_hops
from .origin_resolver import resolve_origin
from .auth_checker import check_authentication
from .geo_intel import lookup_ip
from .sender_locator import estimate_sender_location

__all__ = [
    "analyze_email",
    "parse_hops",
    "resolve_origin",
    "check_authentication",
    "lookup_ip",
    "estimate_sender_location",
]
__version__ = "1.0.0"

