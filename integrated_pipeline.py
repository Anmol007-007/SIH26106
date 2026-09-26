import email.utils
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional

ROOT_DIR = Path(__file__).resolve().parent
SOUMYA_DIR = ROOT_DIR / "soumya"
ASHWATHI_PARSING_DIR = ROOT_DIR / "ashwathi" / "Parsing_Engine"
ASHWATHI_DETECTION_DIR = ROOT_DIR / "ashwathi" / "Detection_Engine"
MY_DIR = ROOT_DIR / "my"

for p in (SOUMYA_DIR, ASHWATHI_PARSING_DIR, ASHWATHI_DETECTION_DIR, MY_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.raw_store import save_raw_email
from app.config import STORAGE_DIR as SOUMYA_STORAGE_DIR
from parsing_engine.parser import parse_eml
from detector import run_detection
from trace_engine import analyze_email


class IntegratedBackendPipeline:
    """
    Unified Security Pipeline connecting:
    1. Ingestion (soumya) -> 2. Parsing & Phishing Detection (ashwathi) -> 3. Hop Trace & Origin Risk (my)
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or SOUMYA_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def generate_email_id(self, raw_bytes: bytes) -> str:
        """Generate deterministic SHA-256 ID from raw email bytes."""
        return hashlib.sha256(raw_bytes).hexdigest()

    def process_raw_bytes(self, raw_bytes: bytes, email_id: Optional[str] = None) -> Dict[str, Any]:
        """Process email directly from raw bytes (Stage 1 -> Stage 2 -> Stage 3)."""
        if not email_id:
            email_id = self.generate_email_id(raw_bytes)
        eml_path = save_raw_email(
            raw_email=raw_bytes,
            email_id=email_id,
            storage_dir=self.storage_dir,
        )
        return self.process_eml_file(str(eml_path), email_id=email_id, raw_bytes=raw_bytes)

    def process_eml_file(
        self,
        eml_path: str,
        email_id: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Execute full pipeline flow:
        - Stage 1: Read raw .eml file
        - Stage 2: ashwathi parsing & phishing detection engine
        - Stage 3: my network trace & origin geolocation engine
        - Stage 4: Fused threat score & JSON report generation in final_output/
        """
        eml_file = Path(eml_path).resolve()
        if not eml_file.exists():
            raise FileNotFoundError(f"Email file not found: {eml_file}")

        if raw_bytes is None:
            with open(eml_file, "rb") as f:
                raw_bytes = f.read()

        if not email_id:
            email_id = self.generate_email_id(raw_bytes)

        parsed_email = parse_eml(str(eml_file))
        detection_result = run_detection(parsed_email)
        trace_result = analyze_email(raw_bytes)

        fraud_score = detection_result.get("fraud_score", 0)
        trace_score = trace_result.get("risk", {}).get("trace_risk_score", 0)
        combined_score = round(0.6 * fraud_score + 0.4 * trace_score)

        if combined_score >= 70 or detection_result.get("category") == "phishing":
            overall_verdict = "PHISHING_MALICIOUS"
        elif combined_score >= 35 or detection_result.get("category") == "suspicious":
            overall_verdict = "SUSPICIOUS"
        else:
            overall_verdict = "LEGITIMATE"

        unified_report = {
            "pipeline_version": "1.0.0",
            "email_id": email_id,
            "raw_file_path": str(eml_file),
            "message_meta": trace_result.get("message_meta", {
                "message_id": parsed_email.message_id,
                "subject": parsed_email.subject,
                "from": str(parsed_email.from_addr),
                "date": str(parsed_email.date),
            }),
            "phishing_detection": {
                "fraud_score": fraud_score,
                "category": detection_result.get("category"),
                "confidence": detection_result.get("confidence"),
                "confidence_label": detection_result.get("confidence_label"),
                "flags": detection_result.get("flags", []),
                "ml_confidence": detection_result.get("ml_confidence"),
            },
            "origin_trace": {
                "delivery_path": trace_result.get("delivery_path"),
                "origin": trace_result.get("origin"),
                "authentication": trace_result.get("authentication"),
                "sender_location_estimate": trace_result.get("sender_location_estimate"),
                "risk": trace_result.get("risk"),
            },
            "overall_assessment": {
                "combined_threat_score": combined_score,
                "overall_verdict": overall_verdict,
            },
        }

        from_hdr = str(unified_report.get("message_meta", {}).get("from", ""))
        to_hdr = str(unified_report.get("message_meta", {}).get("to", ""))
        sender_name, sender_email = email.utils.parseaddr(from_hdr)
        _, recipient_email = email.utils.parseaddr(to_hdr)

        sender_loc = (trace_result.get("sender_location_estimate") or {}).get("primary_estimate") or {}
        origin_geo = trace_result.get("origin", {}).get("geo") or {}
        resolved_country = origin_geo.get("country", "") or sender_loc.get("country", "")
        resolved_city = origin_geo.get("city", "") or sender_loc.get("city", "")

        cat = str(detection_result.get("category", "Safe")).capitalize()
        status_label = (
            "High Risk" if combined_score >= 70 or cat.lower() == "phishing"
            else ("Moderate Risk" if combined_score >= 35 or cat.lower() == "suspicious" else "Low Risk")
        )

        phones = (trace_result.get("sender_location_estimate") or {}).get("extracted_artifacts", {}).get("phone_numbers", [])
        phone_val = getattr(parsed_email, "phone", "") or (phones[0] if phones else "")

        final_output_data = {
            "id": email_id,
            "subject": unified_report.get("message_meta", {}).get("subject", ""),
            "email": recipient_email or to_hdr,
            "sender": sender_email or from_hdr,
            "phone": phone_val or "",
            "ip": trace_result.get("origin", {}).get("probable_source_ip", ""),
            "name": sender_name or "",
            "country": resolved_country or "",
            "city": resolved_city or "",
            "risk_score": combined_score,
            "classification": cat,
            "status": status_label,
            "overall_assessment": {
                "combined_threat_score": combined_score,
                "overall_verdict": overall_verdict,
            },
        }

        final_output_dir = ROOT_DIR / "final_output"
        final_output_dir.mkdir(parents=True, exist_ok=True)

        named_output_file = final_output_dir / f"{eml_file.stem}.json"
        with open(named_output_file, "w", encoding="utf-8") as f:
            json.dump(final_output_data, f, indent=2, default=str)

        latest_output_file = final_output_dir / "latest_output.json"
        with open(latest_output_file, "w", encoding="utf-8") as f:
            json.dump(final_output_data, f, indent=2, default=str)

        unified_report["final_output"] = final_output_data
        return unified_report
