from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from trace_engine import analyze_email

def print_single_report(report: dict, is_json: bool = False):
    if is_json:
        print(json.dumps(report, indent=2, default=str))
        return
    m, o, a, r, s = report["message_meta"], report["origin"], report["authentication"], report["risk"], report.get("sender_location_estimate", {})
    print("=" * 72)
    print(f" Subject : {m['subject']}\n From    : {m['from']}\n Date    : {m['date']}")
    print("=" * 72)
    print("\n--- DELIVERY PATH (origin -> inbox) " + "-" * 34)
    for h in report["delivery_path"]["hops"]:
        geo = h.get("geo")
        loc = f"{geo['country']}, {geo['city'] or '?'} | {geo['isp'] or '?'}" if geo else "(no public IP)"
        print(f"  hop {h['index']:>2}: {h['from_host'] or '?':<35} ip={h['from_ip'] or '-':<16} [{'TLS' if h['is_tls'] else 'plain'}]\n          {loc}")
    for n in report["delivery_path"]["notes"]:
        print(f"  [!] {n}")

    print("\n--- PROBABLE ORIGIN (Stage B) " + "-" * 42)
    print(f"  Source IP    : {o['probable_source_ip']} (confidence: {o['confidence']})\n  Origin Basis : {o.get('origin_basis')} | Via Provider: {o.get('via_provider')}")
    if o.get("attribution_note"): print(f"  Note         : {o.get('attribution_note')}")
    g = o.get("geo")
    if g: print(f"  Location     : {g.get('city')}, {g.get('country')} | ISP: {g.get('isp')} | Infra: {g.get('infrastructure_type')}")

    if s and s.get("primary_estimate"):
        pe = s["primary_estimate"]
        print("\n--- SENDER LOCATION ESTIMATE (Stage E) " + "-" * 33)
        print(f"  Estimated Loc: {pe.get('city') or ''} {pe.get('country') or 'Unknown'} ({pe.get('country_code') or 'XX'}) [{pe.get('confidence', '').upper()}]")
        for b in pe.get("basis", []): print(f"    * {b}")

    print("\n--- AUTHENTICATION & TRACE RISK " + "-" * 38)
    print(f"  SPF={a['spf']['result']} | DKIM={a['dkim']['result']} | DMARC={a['dmarc']['result']} => {a['summary'].upper()}")
    print(f"  Risk Score   : {r['trace_risk_score']}/100 ({r['trace_risk_level'].upper()})")
    for reason in r["reasons"]: print(f"   * {reason}")
    print()

def main():
    p = argparse.ArgumentParser(description="SIH26106 Trace Engine CLI & Batch Tracer")
    p.add_argument("input_path", help="Path to .eml file or directory of .eml files")
    p.add_argument("--offline", action="store_true", help="Skip online lookups (local GeoLite2 only)")
    p.add_argument("--geolite-dir", default=None, help="Directory for GeoLite2 databases")
    p.add_argument("--json", action="store_true", help="Output full JSON report")
    p.add_argument("-o", "--output", default=None, help="Save batch output to JSON file")
    args = p.parse_args()

    inp = Path(args.input_path)
    if inp.is_file():
        report = analyze_email(inp.read_bytes(), geolite_dir=args.geolite_dir, use_online_geo=not args.offline)
        print_single_report(report, args.json)
    elif inp.is_dir():
        files = [f for f in inp.rglob("*") if f.is_file() and f.suffix.lower() == ".eml"]
        print(f"[*] Found {len(files)} .eml file(s) in {inp}. Processing...\n")
        results = []
        for i, f in enumerate(files, 1):
            rep = analyze_email(f.read_bytes(), geolite_dir=args.geolite_dir, use_online_geo=not args.offline)
            o = rep["origin"]
            loc = rep.get("sender_location_estimate", {}).get("primary_estimate", {}).get("country") or (o.get("geo") or {}).get("country") or "Unknown"
            print(f"[{i}/{len(files)}] {f.name:<30} IP: {str(o.get('probable_source_ip')):<15} Loc: {loc:<15} Risk: {rep['risk']['trace_risk_score']}/100")
            results.append({"file": f.name, "report": rep})
        if args.output:
            Path(args.output).write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
            print(f"\n[+] Saved {len(results)} reports to {args.output}")
    else:
        print(f"Error: {args.input_path} not found.")

if __name__ == "__main__":
    main()
