from __future__ import annotations
import re
from email.message import Message
from email.utils import parseaddr
from typing import Optional, Dict, Any

RESULTS = ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy")

def _f(pat: str, txt: str) -> Optional[str]:
    m = re.search(pat, txt, re.I)
    return m.group(1).lower() if m else None

def _dom(addr: str) -> Optional[str]:
    if not addr: return None
    _, e = parseaddr(addr)
    return e.split("@", 1)[1].lower().strip("[]().") if "@" in e else None

def check_authentication(msg: Message) -> Dict[str, Any]:
    """Stage C: SPF/DKIM/DMARC verdicts and identity alignment."""
    txt = " ; ".join(re.sub(r"\s+", " ", str(h)) for h in (msg.get_all("Authentication-Results") or []))
    spf = {"result": _f(r"spf=([a-z]+)", txt) if _f(r"spf=([a-z]+)", txt) in RESULTS else "unknown",
           "domain": _f(r"smtp\.mailfrom=(?:.*?@)?([A-Za-z0-9.\-]+)", txt),
           "client_ip": _f(r"sender ip is \[?([0-9a-fA-F.:]+)\]?", txt)}
    dkim = {"result": _f(r"dkim=([a-z]+)", txt) if _f(r"dkim=([a-z]+)", txt) in RESULTS else "unknown",
            "domain": _f(r"header\.[di]=@?([A-Za-z0-9.\-]+)", txt)}
    dmarc = {"result": _f(r"dmarc=([a-z]+)", txt) if _f(r"dmarc=([a-z]+)", txt) in RESULTS else "unknown",
             "policy": _f(r"\bp=([a-z]+)", txt)}

    rspf = msg.get("Received-SPF")
    if rspf:
        rt = re.sub(r"\s+", " ", str(rspf))
        first = rt.strip().split(" ", 1)[0].lower()
        if spf["result"] == "unknown" and first in RESULTS: spf["result"] = first
        if not spf["client_ip"]: spf["client_ip"] = _f(r"client-ip=\[?([0-9a-fA-F.:]+)\]?", rt)
        if not spf["domain"]: spf["domain"] = _f(r"envelope-from=(?:.*?@)?([A-Za-z0-9.\-]+)", rt)

    flags, r_tuple = [], (spf["result"], dkim["result"], dmarc["result"])
    if "fail" in r_tuple or "permerror" in r_tuple or spf["result"] == "softfail":
        summary = "failed"
        if spf["result"] in ("fail", "softfail"): flags.append(f"SPF {spf['result'].upper()}: origin IP not authorized for {spf['domain'] or 'domain'}.")
        if dkim["result"] == "fail": flags.append("DKIM verification FAILED — altered content or forged signature.")
        if dmarc["result"] == "fail": flags.append(f"DMARC FAILED (policy={dmarc['policy'] or 'none'}) — From: domain not aligned.")
    elif all(r == "unknown" for r in r_tuple):
        summary = "unknown"
        flags.append("No Authentication-Results headers recorded by edge receiver.")
    elif spf["result"] == "pass" and dkim["result"] == "pass" and dmarc["result"] == "pass":
        summary = "authenticated"
    else:
        summary = "partially_authenticated"

    f_dom, rp_dom, rt_dom, s_dom = _dom(msg.get("From")), _dom(msg.get("Return-Path")), _dom(msg.get("Reply-To")), _dom(msg.get("Sender"))
    if f_dom and rp_dom and f_dom != rp_dom and not (f_dom.endswith("." + rp_dom) or rp_dom.endswith("." + f_dom)):
        flags.append(f"From domain ({f_dom}) differs from Return-Path ({rp_dom}) — possible sender impersonation.")
    if f_dom and rt_dom and f_dom != rt_dom and not (f_dom.endswith("." + rt_dom) or rt_dom.endswith("." + f_dom)):
        flags.append(f"Reply-To domain ({rt_dom}) differs from From ({f_dom}) — replies route elsewhere.")

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "summary": summary, "flags": flags,
            "from_domain": f_dom, "return_path_domain": rp_dom, "reply_to_domain": rt_dom, "sender_domain": s_dom}
