# SIH26106 — AI-Powered Email Threat Detection, Hop Trace & Origin Intelligence Platform

A unified cybersecurity platform designed for **Smart India Hackathon (SIH Problem Statement 26106)**.

The platform provides end-to-end forensic analysis of emails by combining **real-time ingestion**, **AI/NLP phishing detection**, **multi-hop delivery path reconstruction**, and **true sender origin geolocation**.

---

## What Problem Does This App Solve?

Traditional email security systems often fail in two major ways:
1. **Content-only blindspots**: Attackers craft phishing emails that mimic legitimate language or exploit spoofed sender headers (`From: alerts@sbi.co.in`) that bypass simple spam keyword filters.
2. **Relay Geolocation Fallacy**: When an email is sent through cloud providers like Gmail, Microsoft Outlook, or Yahoo, naive IP geolocation traces back to the provider's server (e.g., Google's datacenter in Mountain View, California, US) rather than the actual geographical origin of the sender.

### How This Platform Solves It:
* **Deep Header & Network Trace**: Reconstructs the entire relay route across RFC 5321 `Received:` headers to find the earliest trustworthy public IP.
* **Actual Sender Location Attribution**: When emails traverse webmail/cloud relays, the engine analyzes submission artifacts, client system clocks, timezone offsets (`+0530`), Indian financial patterns (UPI handles, IFSC codes, phone numbers), and client submission headers (ESMTPSA, X-Originating-IP) to attribute the **true physical origin** (e.g., India) rather than the cloud datacenter in the US.
* **Dual-Engine Verdict Fusion**: Blends machine learning phishing probability and forensic rule violations with network infrastructure risk to compute a unified threat score (0–100) and actionable verdict (`LEGITIMATE`, `SUSPICIOUS`, or `PHISHING_MALICIOUS`).

---

## Architecture & Subsystems

The application integrates three core modules:

```
                  +-----------------------------------------+
                  |         Raw Email Ingestion             |
                  |     (soumya: IMAP IDLE / EML File)      |
                  +--------------------+--------------------+
                                       |
                                       v
                  +--------------------+--------------------+
                  |    Parsing & Data Model Extraction      |
                  |          (ashwathi/Parsing_Engine)      |
                  +--------------------+--------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
+------------------------------------+   +------------------------------------+
|   AI Phishing Detection Engine     |   |   5-Stage Network Trace Engine     |
|   (ashwathi/Detection_Engine)      |   |   (my/trace_engine)                |
|   - Heuristic Rules & Spoof Flags  |   |   - Stage A: RFC Hop Parser        |
|   - ML Classifier (phishing_model) |   |   - Stage B: Trust-Walk Resolver   |
|   - Lookalike Domains & Urgency    |   |   - Stage C: SPF/DKIM/DMARC Audit  |
|   - Fraud Score (0-100)            |   |   - Stage D: MaxMind Geo/ASN Intel |
|                                    |   |   - Stage E: Multi-Signal Fusion   |
+------------------+-----------------+   +------------------+-----------------+
                   |                                        |
                   +-------------------+--------------------+
                                       |
                                       v
                  +--------------------+--------------------+
                  |    Fused Assessment & JSON Exporter     |
                  |      (integrated_pipeline.py)           |
                  |      - Combined Threat Score (0-100)    |
                  |      - Standardized 13-Key Output       |
                  |      - Saved to final_output/<name>.json|
                  +-----------------------------------------+
```

### 1. Ingestion Subsystem (`soumya/`)
* Listens to live Gmail/IMAP mailboxes via IMAP IDLE (`app/imap_client.py`).
* Handles raw email byte storage and deduplication (`app/raw_store.py`).

### 2. Detection & Parsing Subsystem (`ashwathi/`)
* **Parsing Engine**: Extracts RFC headers, plain text and HTML bodies, URLs, attachments, and email authentication tokens into a structured schema (`parsing_engine/`).
* **Detection Engine**: Evaluates SPF/DKIM/DMARC pass/fail flags, lookalike/typosquatted domains, display name impersonation, urgency language, and risky attachment extensions. Uses a trained Scikit-learn model (`phishing_model.joblib`) to produce ML confidence scores (`detector.py`).

### 3. Trace & Geolocation Intelligence Subsystem (`my/`)
* **Stage A (Hop Parser)**: Parses chained `Received:` headers in top-to-bottom order, extracting IPs, hosts, timestamps, protocols, and TLS status. Detects forgery tripwires like negative time deltas and raw IP literal HELOs.
* **Stage B (Origin Resolver)**: Performs a top-down trust walk. Descends through verifiable, reputable relay hops (e.g., Google, Microsoft) until the first unverified intermediate hop is reached.
* **Stage C (Auth Checker)**: Analyzes `Authentication-Results` and `Received-SPF` headers; flags discrepancies between `From:` domain, `Return-Path:`, and `Reply-To:`.
* **Stage D (Geo Intelligence)**: Enriches IPs with country, city, coordinates, ISP, ASN, and infrastructure classification (residential, datacenter, or Tor/VPN/proxy) using local MaxMind databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`).
* **Stage E (Sender Location Fusion)**: Extracts client clock timezone offsets, phone numbers, UPI payment IDs, and Indian financial identifiers to determine the sender's actual geographical origin.

---

## Output Format

Every email analyzed produces a dedicated JSON document inside `final_output/`:

```json
{
  "id": "f2cb3af9d1cd2e9f79f709a2bd4c176b2077749b8be8a21030bc1d3e14f034cc",
  "subject": "URGENT: Complete NetBanking KYC or Account Will Be Suspended",
  "email": "victim@college.ac.in",
  "sender": "alerts@sbi.co.in",
  "phone": "",
  "ip": "185.220.101.45",
  "name": "State Bank of India",
  "country": "Germany",
  "city": "Brandenburg an der Havel",
  "risk_score": 85,
  "classification": "Phishing",
  "status": "High Risk",
  "overall_assessment": {
    "combined_threat_score": 85,
    "overall_verdict": "PHISHING_MALICIOUS"
  }
}
```

---

## Quick Start

For detailed execution and setup instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md).

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run single email forensic analysis
python run_integrated_backend.py file my/samples/01_legit_gmail.eml

# 3. View stored reports
python run_integrated_backend.py reports
```
