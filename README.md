# SIH26106 — Trace Engine & Geo/IP Intelligence

My module for the team project: **AI-Powered Email Threat Detection, GeoLocation
and Forensic Intelligence Platform**.

Takes a raw email → reconstructs the delivery path from `Received:` headers →
finds the probable source IP → checks SPF/DKIM/DMARC → enriches the origin with
country / ISP / ASN / infrastructure type → emits an explainable trace-risk score.

## Quick start

```bash
# no mandatory dependencies beyond the stdlib; these improve results:
pip install requests            # online geo via ip-api.com (free, no key)
pip install geoip2              # optional: local MaxMind GeoLite2 databases

python trace_cli.py samples/phishing_spoofed.eml        # pretty report
python trace_cli.py samples/legit_gmail.eml --json      # raw JSON (API shape)
python trace_cli.py mymail.eml --offline                # no internet mode
```

To use MaxMind GeoLite2 offline (recommended for the demo — no rate limits,
works without internet):
1. Free signup at https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
3. Put them in `./geolite2/` (or set env `GEOLITE2_DIR`)

## Files

| File | What it does |
|---|---|
| `trace_engine/hop_parser.py` | Parses `Received:` headers → hop chain, finds earliest reliable public IP, detects forged-header signals (negative time deltas, private-IP skips, IP-literal HELOs) |
| `trace_engine/auth_checker.py` | Reads SPF/DKIM/DMARC verdicts from `Authentication-Results` / `Received-SPF`, flags From vs Return-Path mismatch |
| `trace_engine/geo_intel.py` | Geo/ASN/infra enrichment: MaxMind GeoLite2 (offline) + ip-api.com (online) + reverse DNS, with caching |
| `trace_engine/analyzer.py` | Orchestrates everything → one JSON report + trace risk score |
| `trace_cli.py` | Manual tester / demo tool |
| `docs/output_contract.md` | **The interface my teammates integrate against** |
| `samples/` | One legit Gmail mail, one spoofed phishing mail (forged hop, Tor exit origin, SPF/DMARC fail) |

## Integration (one line for the worker)

```python
from trace_engine import analyze_email
report = analyze_email(raw_email_bytes)   # JSON-serializable dict
```

## Honest limitations (say these to the judges — it earns credibility)

- Geolocation is **infrastructure-level**, not the attacker's house. If the
  origin is a Tor exit / VPN (like the phishing sample), we say so via
  `infrastructure_type` instead of pretending the country is meaningful.
- Received headers below the trusted edge can be forged; we mitigate with the
  earliest-**reliable**-hop logic, timestamp-consistency checks, and SPF
  client-ip corroboration, and we report a **confidence** level, never certainty.
- SPF/DKIM verdicts are read from the receiving server's header rather than
  re-evaluated via DNS (a documented stretch goal: `pyspf` / `dkimpy`).
