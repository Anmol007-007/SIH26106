# 🧭 Trace Engine + Geo/IP Intelligence — Complete Step-by-Step Playbook
### (SIH26106 — written for a beginner, from zero to demo-ready)

Follow the steps in order. Each step tells you **WHAT** to do, **HOW** to do it
(exact commands / clicks), **WHY** it matters, and **HOW YOU KNOW you're done**.

---

## STEP 0 — Understand what your module actually does (30–45 min, no coding)

**Why:** In SIH, judges ask "explain how this works" — you must be able to answer
without reading code.

**0.1 — Learn what an email really looks like**
- An email is not just "subject + body". It is a plain-text file with dozens of
  hidden **headers** on top (like a courier parcel covered in stamps from every
  sorting office it passed through).
- Open Gmail on your laptop → open any email → click the **⋮ (three dots)** →
  **"Show original"**. That page IS the raw email. Scroll through it slowly.

**0.2 — Find the `Received:` headers in that raw email**
- You'll see several lines starting with `Received: from ... by ...`.
- KEY FACT: every mail server that handles the email **adds one Received header
  on TOP**. So:
  - **Topmost** `Received:` = the LAST server (your Gmail).
  - **Bottommost** `Received:` = the FIRST server (closest to the sender).
- Your trace engine reads these from top to bottom to rebuild the journey.

**0.3 — Learn the 3 authentication words (one line each)**
- **SPF** — "Was the sending IP *allowed* to send mail for that domain?" (a DNS list of permitted IPs)
- **DKIM** — "Was the message *cryptographically signed* by the domain?" (a digital signature)
- **DMARC** — "Do SPF/DKIM identities *match* the From: address, and what to do if not?" (the policy)
- If a mail claims to be from `sbi.co.in` but SPF says FAIL → the IP was not
  authorized → **spoofing**. This is your strongest signal.

**0.4 — Understand the one honest limitation**
- IP geolocation finds the **infrastructure** (which datacenter/ISP/country the
  sending server sits in) — NOT the attacker's house. If the sender used a VPN
  or Tor, we detect *that it's a VPN/Tor* and say so. Memorize this sentence;
  judges will ask.

✅ **Done when:** you can explain to a teammate, in 2 minutes, how Received
headers + SPF let you find and judge the origin IP.

---

## STEP 1 — Set up your machine (20–30 min)

**1.1 — Install Python 3.10+**
- Windows: download from python.org → run installer → **TICK "Add Python to PATH"** (people forget this and nothing works).
- Verify in a terminal / PowerShell:
  ```bash
  python --version        # should print Python 3.10 or higher
  ```

**1.2 — Get the project folder**
- Download/copy the `sih26106-trace-engine/` folder (from this workspace) onto your laptop.
- Open a terminal **inside** that folder:
  ```bash
  cd path/to/sih26106-trace-engine
  dir        # Windows  (ls on Mac/Linux) — you should see trace_cli.py, trace_engine/, samples/
  ```

**1.3 — Create a virtual environment (a private box for this project's packages)**
  ```bash
  python -m venv venv
  venv\Scripts\activate        # Windows
  source venv/bin/activate     # Mac/Linux
  ```
- Your prompt should now start with `(venv)`. Do this every time you open a new terminal.

**1.4 — Install the two optional packages**
  ```bash
  pip install requests geoip2
  ```
- `requests` → lets the code call the free online geo API (ip-api.com).
- `geoip2` → lets the code read offline MaxMind databases (Step 3).
- (The engine still runs with neither — it just returns less geo detail.)

✅ **Done when:** `pip list` shows `requests` and `geoip2` and your prompt shows `(venv)`.

---

## STEP 2 — Run the engine on the sample emails (15 min)

**2.1 — Run the phishing sample**
  ```bash
  python trace_cli.py samples/phishing_spoofed.eml
  ```
- Expected: delivery path with 3 hops, origin traced to `185.220.101.45`
  (Tor exit node, Germany), SPF/DMARC **FAILED**, risk **95/100 HIGH**.

**2.2 — Run the legit sample**
  ```bash
  python trace_cli.py samples/legit_gmail.eml
  ```
- Expected: Google servers, SPF/DKIM/DMARC all pass, risk **10/100 LOW**.

**2.3 — Look at the raw JSON (this is what teammates receive)**
  ```bash
  python trace_cli.py samples/phishing_spoofed.eml --json
  ```
- Skim it next to `docs/output_contract.md` and match the sections:
  `delivery_path`, `origin`, `authentication`, `risk`.

**2.4 — Understand the output by tracing ONE thing through the code**
- Open `trace_engine/hop_parser.py`, read only `find_origin_ip()` (~30 lines).
- Question to answer yourself: *why does it skip `10.0.0.15`?*
  (Answer: it's a private IP — mail was still inside an internal network, so it
  can't be the public origin.)

✅ **Done when:** both samples run and you can say why one is HIGH and one is LOW.

---

## STEP 3 — Add offline GeoLite2 databases (30 min, needs internet once)

**Why:** the free online API allows only 45 lookups/min and needs internet.
SIH demo venues have terrible WiFi — offline databases make your demo bulletproof.

**3.1 — Create a free MaxMind account**
- Go to `https://www.maxmind.com/en/geolite2/signup` → sign up (free) → verify email → set password.

**3.2 — Download two database files**
- Log in → left menu **"Download Files"** (under GeoIP2/GeoLite2).
- Download: **GeoLite2 City** (.mmdb inside a .tar.gz) and **GeoLite2 ASN** (same).
- Extract the archives (7-Zip on Windows) until you get the bare files:
  `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.

**3.3 — Put them where the code looks**
  ```
  sih26106-trace-engine/
  └── geolite2/
      ├── GeoLite2-City.mmdb
      └── GeoLite2-ASN.mmdb
  ```

**3.4 — Verify offline mode works**
  ```bash
  python trace_cli.py samples/phishing_spoofed.eml --offline
  ```
- You should still see country/ASN data (from the local DBs) even though the
  online API was skipped. Turn off WiFi and run it again to be sure.

✅ **Done when:** `--offline` still shows Germany / AS60729 for the phishing sample.

---

## STEP 4 — Test on REAL emails (2–4 hours; this is where you find bugs)

**4.1 — Export real emails from your own Gmail**
- Gmail → open an email → ⋮ → **"Show original"** → **"Download original"** → saves a `.eml` file.
- Collect **15–20 mails** with variety:
  - 5 normal personal mails
  - 5 legit bulk mails (Amazon, IRCTC, bank statements, college mails)
  - 5–10 from your **Spam folder** (the gold mine — real phishing!)
- Put them in a new folder `samples/real/` (DON'T commit these to a public repo —
  they contain your personal data).

**4.2 — Run the engine on each**
  ```bash
  python trace_cli.py samples/real/spam1.eml
  ```

**4.3 — For each result, check 4 things (make a simple table in Excel/Sheets)**
  | file | origin IP found? | geo looks sane? | auth verdict correct? | risk level sensible? |
- "Sane" check: paste the origin IP into `https://ipinfo.io` and compare country/ISP.

**4.4 — When something breaks (it will), debug like this**
- Crash / traceback → copy the error, note which file, send it to me — or read
  the line it points to; usually a weird header format.
- Wrong origin IP → open the `.eml` in Notepad, read the `Received:` headers
  yourself bottom-up, decide what the RIGHT answer is, then check why
  `find_origin_ip()` chose differently.
- No geo data → check if the IP is private (starts with `10.`, `192.168.`, `172.16–31.`).

**4.5 — Tune the risk score if needed**
- Open `trace_engine/analyzer.py` → `_risk_assessment()`. The numbers
  (45, 15, 10...) are just weights. If legit newsletters score MEDIUM too often,
  lower the "datacenter" penalty from 10 → 5. Change one number at a time and re-run.

✅ **Done when:** ≥ 90% of your real mails get a verdict you agree with, and no crashes.

---

## STEP 5 — Hand over the interface to teammates (1 hour + a team call)

**5.1 — TALK TO SOUMYA FIRST (ingestion) — do this EARLY, it's your only hard dependency**
- Tell her exactly this: *"Store the complete raw email, unmodified. In Gmail API
  use `users.messages.get(format='raw')` and base64-decode it; in IMAP fetch
  `RFC822`. Save it as bytes / a `.eml` file. If you store only the parsed body,
  my tracing is impossible because the Received headers are gone."*
- Test it: ask her for one stored email from her pipeline, run your CLI on it.

**5.2 — Give Muskan (queue) the one-line integration**
- Send her `docs/output_contract.md`. Her Celery task is literally:
  ```python
  from trace_engine import analyze_email

  @celery_app.task(name="trace.analyze")
  def trace_task(email_id):
      raw = load_raw_email(email_id)        # from Soumya's store
      report = analyze_email(raw)           # your module
      save_trace_report(email_id, report)   # PostgreSQL JSONB column
  ```
- Tell her: it's a pure function, safe to run in parallel workers, takes 0.2–2 s per mail.

**5.3 — Give Pooja (dashboard) the JSON contract**
- Point her at `docs/output_contract.md`, specifically:
  - **Map:** plot `delivery_path.hops[*].geo.lat/lon` as a line = "route the email travelled"; big marker at `origin.geo`.
  - **"Why flagged?" panel:** just render the `risk.reasons` and `authentication.flags` lists.
  - **Masking:** she masks `message_meta.to` and recipient info inside `hops[*].raw`.
- Give her the `--json` output of both samples as ready-made test fixtures so she
  can build the UI **before** the queue is wired up.

**5.4 — Coordinate the final verdict with... yourself (detection engine is also yours)**
- Decide the combining rule and write it down, e.g.
  `final_score = max(trace_risk_score, content_score)` or `0.4*trace + 0.6*content`.
  `max()` is easiest to defend: "if EITHER the infrastructure OR the content is
  bad, the email is bad."

✅ **Done when:** Muskan's worker runs your function on a mail from Soumya's store
and the JSON lands in PostgreSQL. That's system integration for your part = done.

---

## STEP 6 — Optional upgrades, only if time remains (pick in this order)

**6.1 — Domain age via WHOIS (~1 hr, HIGH demo value)**
- Phishing domains are usually days old; `sbi.co.in` is decades old.
- `pip install python-whois`, look up `authentication.from_domain`'s creation
  date; if < 30 days → add +20 risk and the reason "Sender domain registered X days ago".

**6.2 — AbuseIPDB reputation (~1 hr)**
- Free API key at abuseipdb.com. One GET request per origin IP → returns an
  abuse confidence score (0–100). Add it to the geo record + risk reasons.

**6.3 — Real SPF/DKIM re-verification (~3–4 hrs, only if you're comfortable)**
- `pip install pyspf dkimpy` → actually re-evaluate SPF against DNS and verify
  DKIM signatures yourself instead of trusting the `Authentication-Results` header.
- If you skip it, that's fine — say it's a documented roadmap item.

---

## STEP 7 — Prepare for the demo & judges' questions (2–3 hours)

**7.1 — Build your demo script (rehearse it twice)**
1. Show the legit Gmail sample → LOW, all auth passed. ("This is normal mail.")
2. Show the phishing sample → walk through: forged SBI hop ignored → private IP
   skipped → origin = Tor exit in Germany → SPF FAIL → 95/100 HIGH.
3. Punchline: "The attacker *claimed* to be SBI India; the infrastructure says
   Tor exit node in Germany — and we can prove why, line by line."

**7.2 — Give the PPT team (Tanu/Muskan) these 3 assets**
- Screenshot of the phishing CLI/dashboard output.
- A simple diagram: Email → Received headers → hop chain → origin IP → geo/ASN → risk.
- The limitation sentence (below) as a "What we honestly can and cannot do" slide.

**7.3 — Memorize answers to the 4 questions judges always ask**
- *"Can attackers forge headers?"* → "Yes — anything below the trusted edge. That's
  why we walk from the trusted receiving server downward, cross-check with the
  SPF client-ip, check timestamp consistency, and output a **confidence level**
  instead of pretending certainty."
- *"Does this find the attacker's location?"* → "It finds the **source
  infrastructure**. If that's a VPN/Tor/datacenter we classify it as such — which
  is itself forensic intelligence for LEA coordination."
- *"What if there's no internet?"* → "Geo works fully offline via local MaxMind
  GeoLite2 databases." (Then show `--offline`.)
- *"How accurate is IP geolocation?"* → "Country-level is ~99% reliable;
  city-level is approximate. We treat country + ASN + infrastructure type as the
  reliable signals."

✅ **Done when:** you can run the full demo, offline, in under 3 minutes, and
answer all 4 questions without notes.

---

## 📅 Suggested timeline

| When | Steps |
|---|---|
| Day 1 | Steps 0–2 (understand + run) |
| Day 2 | Step 3 (GeoLite2) + tell Soumya about raw storage (5.1) |
| Days 3–5 | Step 4 (real-email testing + tuning) |
| Week 2 | Step 5 (integration with Muskan & Pooja) |
| Week 2–3 | Step 6 (upgrades) if time allows |
| Final week | Step 7 (demo + PPT support) |

**Golden rule:** a boring module that WORKS in integration beats a fancy module
that isn't wired in. Steps 0–5 are mandatory; 6 is bonus.
