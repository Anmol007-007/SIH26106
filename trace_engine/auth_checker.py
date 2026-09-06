from __future__ import annotations

import re
from email.message import Message
from typing import Optional


_RESULT_WORDS = ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy")


def _find(pattern: str, text: str) -> Optional[str]:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).lower() if m else None


def check_authentication(msg: Message) -> dict:
    auth_headers = msg.get_all("Authentication-Results") or []
    auth_text = " ; ".join(re.sub(r"\s+", " ", str(h)) for h in auth_headers)

    spf = {"result": "unknown", "domain": None, "client_ip": None}
    dkim = {"result": "unknown", "domain": None}
    dmarc = {"result": "unknown", "policy": None}

    if auth_text:
        spf_res = _find(r"spf=([a-z]+)", auth_text)
        if spf_res in _RESULT_WORDS:
            spf["result"] = spf_res
        spf["domain"] = _find(r"smtp\.mailfrom=(?:.*?@)?([A-Za-z0-9.\-]+)", auth_text)

        dkim_res = _find(r"dkim=([a-z]+)", auth_text)
        if dkim_res in _RESULT_WORDS:
            dkim["result"] = dkim_res
        dkim["domain"] = _find(r"header\.[di]=@?([A-Za-z0-9.\-]+)", auth_text)

        dmarc_res = _find(r"dmarc=([a-z]+)", auth_text)
        if dmarc_res in _RESULT_WORDS:
            dmarc["result"] = dmarc_res
        dmarc["policy"] = _find(r"\bp=([a-z]+)", auth_text)

    rspf = msg.get("Received-SPF")
    if rspf and spf["result"] == "unknown":
        rspf_txt = re.sub(r"\s+", " ", str(rspf))
        first_word = rspf_txt.strip().split(" ", 1)[0].lower()
        if first_word in _RESULT_WORDS:
            spf["result"] = first_word
        spf["client_ip"] = _find(r"client-ip=\[?([0-9a-fA-F.:]+)\]?", rspf_txt)

    if spf["client_ip"] is None and auth_text:
        spf["client_ip"] = _find(r"sender ip is \[?([0-9a-fA-F.:]+)\]?", auth_text)

    flags: list[str] = []
    results = (spf["result"], dkim["result"], dmarc["result"])

    if "fail" in results or "permerror" in results:
        summary = "failed"
    elif spf["result"] == "softfail":
        summary = "failed"
        flags.append("SPF softfail: sending IP is not authorized (domain uses ~all).")
    elif all(r == "unknown" for r in results):
        summary = "unknown"
        flags.append("No Authentication-Results header found — receiving server did not "
                     "record SPF/DKIM/DMARC verdicts.")
    elif spf["result"] == "pass" and dkim["result"] == "pass" and dmarc["result"] == "pass":
        summary = "authenticated"
    else:
        summary = "partially_authenticated"

    if spf["result"] in ("fail", "softfail"):
        flags.append(f"SPF {spf['result'].upper()}: the origin IP is NOT permitted to send "
                     f"mail for {spf['domain'] or 'the claimed domain'} — spoofing indicator.")
    if dkim["result"] == "fail":
        flags.append("DKIM signature verification FAILED — message content may have been "
                     "altered or the signature is forged.")
    if dmarc["result"] == "fail":
        flags.append(f"DMARC FAILED (policy={dmarc['policy'] or 'unknown'}) — the From: domain "
                     "does not align with SPF/DKIM identities.")

    from_hdr = str(msg.get("From", ""))
    return_path = str(msg.get("Return-Path", ""))
    from_dom = _find(r"@([A-Za-z0-9.\-]+)", from_hdr)
    rp_dom = _find(r"@([A-Za-z0-9.\-]+)", return_path)
    if from_dom and rp_dom and from_dom != rp_dom:
        if not (from_dom.endswith("." + rp_dom) or rp_dom.endswith("." + from_dom)):
            flags.append(f"From domain ({from_dom}) differs from Return-Path domain ({rp_dom}) "
                         "— possible sender impersonation (can be legit for mailing lists).")

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "summary": summary,
        "flags": flags,
        "from_domain": from_dom,
        "return_path_domain": rp_dom,
    }
