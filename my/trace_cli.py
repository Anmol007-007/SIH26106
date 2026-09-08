import argparse
import json
import sys
from trace_engine import analyze_email
def main() -> None:
    ap = argparse.ArgumentParser(description="SIH26106 trace engine CLI")
    ap.add_argument("eml_file", help="path to a raw .eml file")
    ap.add_argument("--offline", action="store_true",
                    help="skip online ip-api.com lookups (use only local GeoLite2)")
    ap.add_argument("--geolite-dir", default=None, help="folder with GeoLite2 .mmdb files")
    ap.add_argument("--json", action="store_true", help="print full JSON report")
    args = ap.parse_args()
    with open(args.eml_file, "rb") as f:
        raw = f.read()
    report = analyze_email(raw, geolite_dir=args.geolite_dir,
                           use_online_geo=not args.offline)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return
    m = report["message_meta"]
    o = report["origin"]
    a = report["authentication"]
    r = report["risk"]
    print("=" * 72)
    print(f" Subject : {m['subject']}")
    print(f" From    : {m['from']}")
    print(f" Date    : {m['date']}")
    print("=" * 72)
    print("\n--- DELIVERY PATH (origin -> inbox) " + "-" * 34)
    for hop in report["delivery_path"]["hops"]:
        geo = hop.get("geo")
        loc = f"{geo['country']}, {geo['city'] or '?'} | {geo['isp'] or '?'} | {geo['infrastructure_type']}" if geo else "(no public IP)"
        tls = "TLS" if hop["is_tls"] else "plain"
        print(f"  hop {hop['index']:>2}: {hop['from_host'] or '?':<35} "
              f"ip={hop['from_ip'] or '-':<16} [{tls}]")
        print(f"          {loc}")
    for note in report["delivery_path"]["notes"]:
        print(f"  [!] {note}")
    print("\n--- PROBABLE ORIGIN " + "-" * 50)
    print(f"  Source IP  : {o['probable_source_ip']}  (confidence: {o['confidence']})")
    g = o["geo"]
    if g:
        print(f"  Location   : {g.get('city')}, {g.get('region')}, {g.get('country')}")
        print(f"  ISP / ASN  : {g.get('isp')} / {g.get('asn')} ({g.get('asn_name')})")
        print(f"  Infra type : {g.get('infrastructure_type')}")
        print(f"  Reverse DNS: {g.get('reverse_dns')}")
    print("\n--- AUTHENTICATION " + "-" * 51)
    print(f"  SPF={a['spf']['result']}  DKIM={a['dkim']['result']}  "
          f"DMARC={a['dmarc']['result']}  =>  {a['summary'].upper()}")
    for f_ in a["flags"]:
        print(f"  [!] {f_}")
    print("\n--- TRACE RISK " + "-" * 55)
    print(f"  Score: {r['trace_risk_score']}/100  ({r['trace_risk_level'].upper()})")
    for reason in r["reasons"]:
        print(f"   * {reason}")
    print()
if __name__ == "__main__":
    sys.exit(main())
