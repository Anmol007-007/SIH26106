# How to Run the Application

This guide provides step-by-step instructions for setting up and running the **Integrated Email Threat Detection & Trace Engine Backend**.

---

## 1. Prerequisites & Environment Setup

Ensure you have **Python 3.10+** installed.

### Clone and Navigate
```bash
git clone https://github.com/Anmol007-007/SIH26106.git
cd SIH26106
```

### Create and Activate Virtual Environment
* **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
* **Linux / macOS**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### Install Dependencies
Install all required libraries using the unified `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 2. Modes of Operation

The backend can be executed using `run_integrated_backend.py` in three primary modes:

### Mode A: Process a Single `.eml` Email File
Analyzes a local raw `.eml` file through all 3 subsystems (Parsing -> Phishing Detection -> Network Trace & Geolocation):
```bash
python run_integrated_backend.py file my/samples/01_legit_gmail.eml
```

#### Output JSON to Terminal
To print the standardized output JSON directly to your terminal:
```bash
python run_integrated_backend.py file my/samples/01_legit_gmail.eml --json
```

---

### Mode B: List Stored Reports
Inspect all processed email security reports stored in `final_output/`:
```bash
python run_integrated_backend.py reports
```

Example Output:
```text
=== Stored Integrated Security Reports (2) ===
[1] File: 01_legit_gmail.json | Verdict: LEGITIMATE (Score: 5) | Origin: India | Subject: Project Discussion on SIH Subm
[2] File: 02_tor_spoofed_phish.json | Verdict: PHISHING_MALICIOUS (Score: 85) | Origin: Brandenburg an der Havel Germany | Subject: URGENT: Complete NetBanking KY
```

---

### Mode C: Real-Time Live IMAP Inbox Monitoring
Monitors a live email inbox (e.g., Gmail) via IMAP IDLE. When a new email arrives, it is ingested in real time and automatically processed through the entire pipeline:

1. Create a `.env` file inside `soumya/` based on `soumya/.env.example`:
   ```ini
   IMAP_SERVER=imap.gmail.com
   IMAP_PORT=993
   EMAIL_ADDRESS=your_email@gmail.com
   EMAIL_PASSWORD=your_app_specific_password
   ```
2. Start the live monitoring listener:
   ```bash
   python run_integrated_backend.py live
   ```
3. Send any email to your configured address. The pipeline will automatically detect, parse, score, and output the report into `final_output/`. Press `Ctrl+C` to stop.

---

## 3. Output Format & Location

All reports are saved inside the `final_output/` directory as individual, clean JSON files:
* **`final_output/<filename>.json`**: Dedicated JSON file for each analyzed email.
* **`final_output/latest_output.json`**: Pointer containing the most recent analysis result.

Each JSON contains the standardized 13 fields:
```json
{
  "id": "77436de00aa0ef592c44cabcefa54f5daeb5369ec7efe440094c5f547dfd70d4",
  "subject": "Project Discussion on SIH Submissions",
  "email": "victim@college.ac.in",
  "sender": "professor.kumar@gmail.com",
  "phone": "",
  "ip": "209.85.128.176",
  "name": "Prof Kumar",
  "country": "India",
  "city": "",
  "risk_score": 5,
  "classification": "Legitimate",
  "status": "Low Risk",
  "overall_assessment": {
    "combined_threat_score": 5,
    "overall_verdict": "LEGITIMATE"
  }
}
```

---

## 4. Running Regression Tests

To run the offline verification suite for the network trace and origin resolution subsystem:
```bash
python my/test_regression.py
```
Expected result: `Result: 4/4 tests passed.`
