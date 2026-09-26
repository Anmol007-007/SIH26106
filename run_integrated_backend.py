import argparse
import json
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from integrated_pipeline import IntegratedBackendPipeline


def run_single_file(eml_path: str, print_json: bool = False):
    pipeline = IntegratedBackendPipeline()
    print(f"=== Processing Email File: {eml_path} ===")
    report = pipeline.process_eml_file(eml_path)
    meta = report["message_meta"]
    phish = report["phishing_detection"]
    trace = report["origin_trace"]
    origin = trace.get("origin", {})
    origin_geo = origin.get("geo") or {}
    risk = trace.get("risk", {})
    overall = report["overall_assessment"]

    print("=" * 75)
    print(f" SUBJECT       : {meta.get('subject')}")
    print(f" FROM          : {meta.get('from')}")
    print(f" MESSAGE ID    : {meta.get('message_id')}")
    print("=" * 75)
    print("\n--- STAGE 2: PHISHING DETECTION (Ashwathi) " + "-" * 30)
    print(f" Fraud Score   : {phish['fraud_score']}/100")
    print(f" Category      : {phish['category'].upper()}")
    print(f" Confidence    : {phish['confidence']} ({phish['confidence_label']})")
    print(f" ML Prob       : {phish['ml_confidence']}")
    print(" Flags Fired   :")
    for flag in phish.get("flags", []):
        print(f"   [!] {flag}")

    print("\n--- STAGE 3: NETWORK TRACE & GEOLOCATION (My) " + "-" * 26)
    print(f" Hops Count    : {trace['delivery_path']['hops_count']}")
    print(f" Origin IP     : {origin.get('probable_source_ip')} (confidence: {origin.get('confidence')})")
    if origin_geo:
        loc_str = f"{origin_geo.get('city')}, {origin_geo.get('country')}".strip(", ") if origin_geo.get('city') else origin_geo.get('country')
        print(f" Sender Origin : {loc_str}")
        if origin_geo.get('relay_country'):
            print(f" Relay Gateway : {origin_geo.get('relay_isp') or origin_geo.get('isp')} ({origin_geo.get('relay_country')}) [Provider Relay]")
        else:
            print(f" ISP / ASN     : {origin_geo.get('isp')} / {origin_geo.get('asn')}")

    print(f" Trace Risk    : {risk.get('trace_risk_score')}/100 ({risk.get('trace_risk_level').upper()})")
    for reason in risk.get("reasons", []):
        print(f"   * {reason}")

    print("\n--- OVERALL INTEGRATED VERDICT " + "-" * 42)
    print(f" Combined Threat Score : {overall['combined_threat_score']}/100")
    print(f" Final Verdict         : {overall['overall_verdict']}")
    print("=" * 75)

    if print_json:
        print("\n--- FINAL OUTPUT JSON ---")
        print(json.dumps(report["final_output"], indent=2))

    return report


def run_live_monitoring():
    from app.config import EMAIL_ADDRESS, EMAIL_PASSWORD
    from app.imap_client import (
        connect_to_mailbox,
        fetch_email,
        get_latest_uid,
        mark_as_read,
        wait_for_new_email,
    )

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("ERROR: EMAIL_ADDRESS and EMAIL_PASSWORD must be configured in soumya/.env")
        sys.exit(1)

    pipeline = IntegratedBackendPipeline()
    client = connect_to_mailbox()
    client.select_folder("INBOX")
    last_seen_uid = get_latest_uid(client)

    print("=== LIVE INTEGRATED BACKEND MONITORING STARTED ===")
    print("Listening for incoming emails on Gmail/IMAP...")
    print(f"Last seen UID: {last_seen_uid}")
    print("Press Ctrl+C to stop.\n" + "=" * 60)

    try:
        while True:
            try:
                responses = wait_for_new_email(client, timeout=60)
            except Exception as e:
                print(f"IMAP connection error: {e}. Reconnecting in 5s...")
                time.sleep(5)
                try:
                    client.logout()
                except Exception:
                    pass
                client = connect_to_mailbox()
                client.select_folder("INBOX")
                continue

            for resp in responses:
                if not isinstance(resp, tuple):
                    continue
                count, event = resp
                if event != b"EXISTS":
                    continue

                client.select_folder("INBOX")
                message_uids = client.search(["ALL"])
                new_uids = [u for u in message_uids if u > last_seen_uid]

                for uid in new_uids:
                    print(f"\n[+] New email detected (UID: {uid}). Processing through integrated pipeline...")
                    raw_email = fetch_email(client, uid)
                    if not raw_email:
                        continue

                    email_id = pipeline.generate_email_id(raw_email)
                    report = pipeline.process_raw_bytes(raw_email, email_id=email_id)
                    mark_as_read(client, uid)
                    last_seen_uid = max(last_seen_uid, uid)

                    print(f" -> Subject: {report['message_meta'].get('subject')}")
                    print(f" -> Phishing Fraud Score: {report['phishing_detection']['fraud_score']}")
                    print(f" -> Network Trace Score: {report['origin_trace']['risk']['trace_risk_score']}")
                    print(f" -> OVERALL VERDICT: {report['overall_assessment']['overall_verdict']}")
                    print("-" * 60)

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Live Integrated Backend Service...")
    finally:
        try:
            client.logout()
        except Exception:
            pass


def list_reports():
    output_dir = ROOT_DIR / "final_output"
    if not output_dir.exists():
        print("No final_output directory found.")
        return

    json_files = sorted([f for f in output_dir.glob("*.json") if f.name != "latest_output.json"])
    print(f"=== Stored Integrated Security Reports ({len(json_files)}) ===")
    for idx, f in enumerate(json_files, 1):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            sub = data.get("subject", "N/A")
            oa = data.get("overall_assessment") or {}
            verdict = oa.get("overall_verdict") or data.get("classification", "N/A")
            score = data.get("risk_score") or oa.get("combined_threat_score", "N/A")
            loc = f"{data.get('city', '')} {data.get('country', '')}".strip() or "Unknown"
            print(f"[{idx}] File: {f.name} | Verdict: {verdict} (Score: {score}) | Origin: {loc} | Subject: {sub[:30]}")
        except Exception as e:
            print(f"[{idx}] File: {f.name} (Error reading: {e})")


def main():
    parser = argparse.ArgumentParser(description="Integrated Threat Detection & Trace Engine Backend")
    subparsers = parser.add_subparsers(dest="command", help="Mode of operation")

    file_parser = subparsers.add_parser("file", help="Process a single .eml file")
    file_parser.add_argument("eml_path", help="Path to .eml file")
    file_parser.add_argument("--json", action="store_true", help="Print report JSON to stdout")

    subparsers.add_parser("live", help="Run live IMAP inbox monitoring & real-time threat pipeline")
    subparsers.add_parser("reports", help="List all processed security reports in final_output folder")

    args = parser.parse_args()

    if args.command == "file":
        run_single_file(args.eml_path, print_json=args.json)
    elif args.command == "live":
        run_live_monitoring()
    elif args.command == "reports":
        list_reports()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
