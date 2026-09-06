# Trace Engine — Output Contract (v0.1)

**Audience:** Muskan (queue workers), Pooja (API + dashboard + masking), Soumya (mail store).
This is the JSON that `trace_engine.analyze_email(raw_bytes)` returns. Treat it as the
interface between my module and yours — if I change it, I bump the `version` field.

## How to call it (Muskan — inside the Celery trace worker)

```python
from trace_engine import analyze_email

@celery_app.task(name="trace.analyze")
def trace_task(email_id: str):
    raw = load_raw_email(email_id)            # from Soumya's raw mail store
    report = analyze_email(raw)               # <- my module (takes ~0.2-2s)
    save_trace_report(email_id, report)       # into PostgreSQL (JSONB column is fine)
    notify_dashboard(email_id)                 # websocket / polling flag
```

- Input: **raw RFC-822 bytes** (the full original email WITH all headers —
  Soumya must store `raw.eml`, not just the parsed body!).
- Safe to run in parallel workers. Geo lookups are cached in-process.
- Optional kwargs: `geolite_dir="./geolite2"`, `use_online_geo=False` (offline demo mode).

## Top-level shape

```jsonc
{
  "module": "trace_engine",
  "version": "0.1.0",

  "message_meta": {           // convenience copy; parsing engine owns the canonical one
    "message_id": "...", "subject": "...", "from": "...", "to": "...", "date": "..."
  },

  "delivery_path": {
    "hops_count": 3,
    "hops": [ /* chronological: FIRST hop (origin side) ... LAST hop (inbox) */
      {
        "index": 2,               // index in header order (0 = top header)
        "from_host": "mail.x.com",// claimed HELO name
        "from_ip": "1.2.3.4",     // actual connecting IP (null if none)
        "by_host": "mx.y.com",
        "protocol": "ESMTPS",
        "is_tls": true,
        "is_private_ip": false,
        "timestamp": "2025-09-01T10:12:03+05:30",
        "delay_seconds": 2.0,     // negative => forged-header suspicion
        "raw": "full Received header",
        "geo": {                  // null for private IPs
          "country": "...", "country_code": "US", "city": "...",
          "lat": 0.0, "lon": 0.0, "isp": "...", "asn": "AS15169",
          "infrastructure_type": "datacenter/hosting"
        }
      }
    ],
    "notes": [ "human-readable warnings about the chain" ]
  },

  "origin": {
    "probable_source_ip": "185.220.101.45",
    "origin_hop_index": 0,
    "confidence": "high | medium | low",
    "geo": {                      // FULL geo record for origin IP
      "ip": "...", "country": "...", "country_code": "...", "region": "...",
      "city": "...", "lat": 0.0, "lon": 0.0, "timezone": "...",
      "isp": "...", "org": "...", "asn": "AS60729", "asn_name": "...",
      "reverse_dns": "tor-exit-45.for-privacy.net",
      "is_hosting": false, "is_proxy_or_vpn": true, "is_mobile": false,
      "infrastructure_type": "proxy/vpn/anonymizer | datacenter/hosting | residential/business ISP | mobile network | internal network | unknown",
      "sources": ["maxmind_geolite2", "ip-api.com", "ptr_lookup"],
      "error": null
    },
    "spf_edge_ip": "…",           // IP recorded by SPF check, if different
    "spf_edge_geo": { ... }       // same shape as geo, or null
  },

  "authentication": {
    "spf":   { "result": "pass|fail|softfail|none|unknown", "domain": "...", "client_ip": "..." },
    "dkim":  { "result": "...", "domain": "..." },
    "dmarc": { "result": "...", "policy": "reject|quarantine|none|null" },
    "summary": "authenticated | partially_authenticated | failed | unknown",
    "flags": [ "warnings, e.g. From vs Return-Path mismatch" ],
    "from_domain": "sbi.co.in",
    "return_path_domain": "sbi-secure-verify.com"
  },

  "risk": {
    "trace_risk_score": 95,       // 0-100, TRACE-side signals only
    "trace_risk_level": "high | medium | low",
    "reasons": [ "explainable list — show these on the dashboard!" ]
  }
}
```

## Notes for Pooja (dashboard + masking)

- **Map view:** plot `delivery_path.hops[*].geo.lat/lon` as a polyline —
  "route the email travelled". Origin marker = `origin.geo`.
- **Masking:** mask `message_meta.to` (victim address) and any recipient info in
  `hops[*].raw` before display/export. Origin IP + geo is investigation data,
  usually NOT masked for analysts; make it role-based if time permits.
- **Combined verdict:** final score = combine my `trace_risk_score` with the
  detection engine's content score (e.g. `max()` or 0.4/0.6 weighted).
- Show `risk.reasons` and `authentication.flags` as the "Why was this flagged?"
  panel — explainability is a big judging plus.

## Notes for Soumya (ingestion)

- Store the **complete raw message** (`.eml`, bytes, unmodified). Gmail API:
  `users.messages.get(format="raw")`. IMAP: `RFC822` fetch. If headers are
  stripped or re-encoded, tracing breaks.
