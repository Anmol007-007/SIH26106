import re
from parsing_engine.schema import AuthResults
def parse_auth_results(headers: list[str]) -> AuthResults:
    """
    headers: all Authentication-Results header values (there can be more
    than one if the mail passed through multiple filtering systems).
    """
    if not headers:
        return AuthResults(raw="", spf="none", dkim="none", dmarc="none")
    raw = " | ".join(headers)
    def extract(mechanism: str) -> str:
        match = re.search(rf"{mechanism}=(\w+)", raw, re.IGNORECASE)
        return match.group(1).lower() if match else "none"
    return AuthResults(
        raw=raw,
        spf=extract("spf"),
        dkim=extract("dkim"),
        dmarc=extract("dmarc"),
    )
