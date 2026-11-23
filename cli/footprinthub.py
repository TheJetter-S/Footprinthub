#!/usr/bin/env python3
# =============================================================================
# FootprintHub — Official Command Line Interface (CLI)
# =============================================================================
# Usage:
#   footprinthub scan example.com --profile passive --format json
#   footprinthub report <scan_id> --format text
#   footprinthub delta <scan_id>
#   footprinthub schedule example.com --frequency daily
# =============================================================================

import argparse
import json
import os
import sys
from typing import Any, Optional
import urllib.error
import urllib.request


DEFAULT_SERVER = os.getenv("FOOTPRINTHUB_SERVER", "http://127.0.0.1:8000")
DEFAULT_API_KEY = os.getenv("FOOTPRINTHUB_API_KEY", "")


def _api_request(
    endpoint: str,
    method: str = "GET",
    data: Optional[dict[str, Any]] = None,
    server: str = DEFAULT_SERVER,
    api_key: str = DEFAULT_API_KEY,
) -> dict[str, Any]:
    url = f"{server.rstrip('/')}/api/v1{endpoint}"
    headers = {"Content-Type": "application/json", "User-Agent": "FootprintHub-CLI/1.0"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload_bytes = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=payload_bytes, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            err_json = json.loads(err_body)
            msg = err_json.get("detail", err_body)
        except Exception:
            msg = err_body
        print(f"[!] Error {e.code}: {msg}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[!] Network error connecting to {server}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def cmd_scan(args: argparse.Namespace) -> None:
    domain = args.domain.strip()
    profile = args.profile.lower()

    if not args.format == "json":
        print(f"[*] Initiating FootprintHub {profile.upper()} scan for: {domain}")

    payload = {
        "domain": domain,
        "profile": profile,
        "authorization_confirmed": True,
    }

    res = _api_request(
        "/scans",
        method="POST",
        data=payload,
        server=args.server,
        api_key=args.key,
    )

    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print(f"[+] Scan successfully queued!")
        print(f"    Scan ID:     {res.get('id')}")
        print(f"    Domain:      {res.get('domain')}")
        print(f"    Profile:     {res.get('profile')}")
        print(f"    Status:      {res.get('status')}")
        print(f"    Track via:   {args.server}/scans/{res.get('id')}")


def cmd_report(args: argparse.Namespace) -> None:
    scan_id = args.scan_id.strip()
    res = _api_request(
        f"/scans/{scan_id}",
        method="GET",
        server=args.server,
        api_key=args.key,
    )

    if args.format == "json":
        print(json.dumps(res, indent=2))
        return

    domain = res.get("domain", "Unknown")
    score = res.get("risk_score", 0)
    grade = "A" if score <= 10 else "B" if score <= 20 else "C" if score <= 50 else "D" if score <= 75 else "F"
    findings = res.get("findings", [])

    print(f"\n=======================================================")
    print(f" FootprintHub Reconnaissance Report: {domain}")
    print(f"=======================================================")
    print(f"Scan ID:        {scan_id}")
    print(f"Profile:        {res.get('profile', 'passive').upper()}")
    print(f"Security Grade: {grade} (Risk Score: {score}/100)")
    print(f"Total Findings: {len(findings)}")
    print(f"-------------------------------------------------------")
    print(f"Top Findings:")
    for f in findings[:8]:
        sev = (f.get("severity") or "INFO").upper()
        conf = f.get("confidence", "likely")
        print(f" [{sev}] ({conf}) {f.get('title')}")
    print(f"=======================================================\n")


def cmd_delta(args: argparse.Namespace) -> None:
    scan_id = args.scan_id.strip()
    res = _api_request(
        f"/scans/{scan_id}/delta",
        method="GET",
        server=args.server,
        api_key=args.key,
    )

    delta = res.get("delta", {})
    if args.format == "json":
        print(json.dumps(res, indent=2))
        return

    print(f"\n=======================================================")
    print(f" Perimeter Differential Delta Report ({res.get('domain')})")
    print(f"=======================================================")
    print(f"Baseline Posture:  {delta.get('posture', 'baseline').upper()}")
    print(f"Risk Score Delta:  {delta.get('risk_score_delta', 0):+d}")
    print(f"Summary:           {delta.get('summary', 'No summary available.')}")
    print(f"-------------------------------------------------------")
    subs = delta.get("subdomains", {})
    if subs.get("added"):
        print(f"New Subdomains ({len(subs['added'])}): {', '.join(subs['added'][:5])}")
    ports = delta.get("ports", {})
    if ports.get("opened"):
        print(f"Newly Opened Ports: {', '.join(str(p['port']) for p in ports['opened'])}")
    cves = delta.get("vulnerabilities", {})
    if cves.get("new_cves"):
        print(f"Newly Introduced CVEs: {', '.join(c['id'] for c in cves['new_cves'])}")
    print(f"=======================================================\n")


def cmd_schedule(args: argparse.Namespace) -> None:
    payload = {
        "domain": args.domain.strip(),
        "frequency": args.frequency.lower(),
        "profile": args.profile.lower(),
    }
    res = _api_request(
        "/schedules",
        method="POST",
        data=payload,
        server=args.server,
        api_key=args.key,
    )
    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print(f"[+] Domain monitoring scheduled successfully:")
        print(f"    ID:        {res.get('id')}")
        print(f"    Domain:    {res.get('domain')}")
        print(f"    Frequency: {res.get('frequency')}")
        print(f"    Next Run:  {res.get('next_run_at')}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="footprinthub",
        description="FootprintHub — Reconnaissance & Attack Surface Management CLI",
    )
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"Server URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--key", default=DEFAULT_API_KEY, help="API Key (default: env FOOTPRINTHUB_API_KEY)")
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    p_scan = subparsers.add_parser("scan", help="Launch a new reconnaissance scan")
    p_scan.add_argument("domain", help="Target domain (e.g. example.com)")
    p_scan.add_argument("--profile", choices=["passive", "standard", "full"], default="passive")
    p_scan.set_defaults(func=cmd_scan)

    # report command
    p_rep = subparsers.add_parser("report", help="Retrieve report summary for a scan")
    p_rep.add_argument("scan_id", help="Scan UUID")
    p_rep.set_defaults(func=cmd_report)

    # delta command
    p_delta = subparsers.add_parser("delta", help="View changes compared to previous scan")
    p_delta.add_argument("scan_id", help="Scan UUID")
    p_delta.set_defaults(func=cmd_delta)

    # schedule command
    p_sched = subparsers.add_parser("schedule", help="Register a recurring domain monitoring schedule")
    p_sched.add_argument("domain", help="Target domain")
    p_sched.add_argument("--frequency", choices=["daily", "weekly", "monthly"], default="daily")
    p_sched.add_argument("--profile", choices=["passive", "standard", "full"], default="passive")
    p_sched.set_defaults(func=cmd_schedule)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

