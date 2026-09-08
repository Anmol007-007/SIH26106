import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

from trace_engine import analyze_email


def extract_location_info(file_path: Path, geolite_dir: str = None, offline: bool = False) -> Dict[str, Any]:
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        report = analyze_email(raw, geolite_dir=geolite_dir, use_online_geo=not offline)

        meta = report.get("message_meta", {})
        origin = report.get("origin", {})
        geo = origin.get("geo") or {}
        risk = report.get("risk", {})

        sender = meta.get("from", "Unknown")
        subject = meta.get("subject", "No Subject")
        source_ip = origin.get("probable_source_ip", "N/A")
        
        city = geo.get("city") or "Unknown City"
        region = geo.get("region") or ""
        country = geo.get("country") or "Unknown Country"
        
        loc_parts = [p for p in [city, region, country] if p and p != "Unknown City"]
        location_str = ", ".join(loc_parts) if loc_parts else country

        return {
            "file": file_path.name,
            "from_email": sender,
            "subject": subject,
            "source_ip": source_ip,
            "city": city,
            "region": region,
            "country": country,
            "full_location": location_str,
            "latitude": geo.get("lat", ""),
            "longitude": geo.get("lon", ""),
            "isp": geo.get("isp", ""),
            "risk_level": risk.get("trace_risk_level", "unknown"),
            "risk_score": risk.get("trace_risk_score", 0),
            "status": "Success"
        }
    except Exception as e:
        return {
            "file": file_path.name,
            "from_email": "Error reading file",
            "subject": "",
            "source_ip": "",
            "city": "",
            "region": "",
            "country": "",
            "full_location": f"Error: {str(e)}",
            "latitude": "",
            "longitude": "",
            "isp": "",
            "risk_level": "error",
            "risk_score": 0,
            "status": f"Failed: {str(e)}"
        }


def process_batch(
    input_path: str,
    output_file: str,
    output_format: str = "csv",
    geolite_dir: str = None,
    offline: bool = False
):
    inp = Path(input_path)
    eml_files: List[Path] = []

    if inp.is_dir():
        eml_files = [f for f in inp.rglob("*") if f.is_file() and f.suffix.lower() == ".eml"]
        if not eml_files:
            eml_files = [f for f in inp.rglob("*") if f.is_file() and not f.name.startswith(".")]
    elif inp.is_file():
        if inp.suffix.lower() in [".txt", ".list"]:
            with open(inp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p_str = line.strip()
                    if p_str and not p_str.startswith("#"):
                        p = Path(p_str)
                        if p.exists() and p.is_file():
                            eml_files.append(p)
                        else:
                            print(f"[!] Warning: File not found: {p_str}", flush=True)
        else:
            eml_files = [inp]
    else:
        print(f"[X] Error: Input '{input_path}' does not exist.", flush=True)
        sys.exit(1)

    if not eml_files:
        print(f"[!] No email files found to process in '{input_path}'.", flush=True)
        return

    print(f"[*] Found {len(eml_files)} email(s) to process. Tracing locations...\n", flush=True)

    results = []
    for idx, eml in enumerate(eml_files, 1):
        print(f"[{idx}/{len(eml_files)}] Processing: {eml.name} ...", end=" ", flush=True)
        res = extract_location_info(eml, geolite_dir=geolite_dir, offline=offline)
        results.append(res)
        print(f"-> {res['from_email']} | Location: {res['full_location']}")

    out_p = Path(output_file)

    if output_format.lower() == "json" or out_p.suffix.lower() == ".json":
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif output_format.lower() == "txt" or out_p.suffix.lower() == ".txt":
        with open(out_p, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("EMAIL LOCATION TRACE REPORT\n")
            f.write("=" * 80 + "\n\n")
            for r in results:
                f.write(f"File       : {r['file']}\n")
                f.write(f"Sender     : {r['from_email']}\n")
                f.write(f"Subject    : {r['subject']}\n")
                f.write(f"Source IP  : {r['source_ip']}\n")
                f.write(f"Location   : {r['full_location']}\n")
                f.write(f"Coordinates: Lat {r['latitude']}, Lon {r['longitude']}\n")
                f.write(f"ISP        : {r['isp']}\n")
                f.write(f"Risk       : {r['risk_level'].upper()} ({r['risk_score']}/100)\n")
                f.write("-" * 80 + "\n")
    else:
        fieldnames = [
            "file", "from_email", "subject", "source_ip", "full_location",
            "city", "region", "country", "latitude", "longitude", "isp",
            "risk_level", "risk_score", "status"
        ]
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)

    print(f"\n[+] Successfully saved {len(results)} records to '{output_file}'!")


def main():
    parser = argparse.ArgumentParser(description="Batch Email Location Extractor & Tracer")
    parser.add_argument(
        "input",
        nargs="?",
        default="spam_mail",
        help="Path to folder containing .eml files OR a .txt file with list of .eml paths (default: spam_mail)"
    )
    parser.add_argument(
        "-o", "--output",
        default="mail_location.csv",
        help="Output file path (default: mail_location.csv or specify .json / .txt / .csv)"
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json", "txt"],
        default="csv",
        help="Output format: csv, json, or txt (default: csv)"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip online IP lookup and use only local GeoLite2"
    )
    parser.add_argument(
        "--geolite-dir",
        default=None,
        help="Folder with GeoLite2 .mmdb files"
    )

    args = parser.parse_args()
    process_batch(
        input_path=args.input,
        output_file=args.output,
        output_format=args.format,
        geolite_dir=args.geolite_dir,
        offline=args.offline
    )


if __name__ == "__main__":
    main()
