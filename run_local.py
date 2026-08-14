#!/usr/bin/env python3
"""WP-Nuclei Local Tester -- run nuclei against a LOCAL WordPress install.

No Docker SDK. No Docker at all. Just runs `nuclei` CLI against
the target URL you provide.

Usage:
    python run_local.py --url http://localhost --yaml-dir ./test_yamls
    python run_local.py --url http://localhost --file ./test_yamls/health_check.yaml
    python run_local.py --url http://localhost --file ./test_yamls/sqli.yaml --auth admin:password
    python run_local.py --url http://localhost --file ./test_yamls/sqli.yaml --cookie "wordpress_=abc"
"""

import argparse
import json
import os
import shutil
import subprocess
import sys


def parse_simple_yaml(path):
    """Return metadata dict from a nuclei YAML."""
    try:
        import yaml as _yaml
        with open(os.path.abspath(path), "r", encoding="utf-8") as fh:
            data = _yaml.safe_load(fh)
    except Exception:
        return { "rule_id": "parse_error", "severity": "unknown",
                 "slug": "unknown", "name": "failed to parse" }

    if not data or not isinstance(data, dict):
        return None

    rule_id = data.get("id", "unknown")
    if isinstance(rule_id, dict):
        rule_id = rule_id.get("id", "unknown")
    rule_id = str(rule_id).replace(" ", "_")

    info = data.get("info", {}) or {}
    name     = str(info.get("name", ""))
    severity = str(info.get("severity", ""))

    meta     = info.get("metadata", {}) or {}
    slug     = str(meta.get("slug", "")) or str(meta.get("plugin", ""))

    if not slug:
        basename = os.path.basename(path)
        # strip extension and take first token before hyphen
        slug = basename.split("-")[0] if basename else "unknown"

    return {
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "slug": slug,
    }


def run_nuclei(nuclei_path, url, yaml_file, timeout=120, cookie=None, extra_headers=None):
    """Invoke nucleus CLI; return (matched: bool, data: dict)."""
    cmd = [nuclei_path, "-u", url, "-t", yaml_file,
           "-jsonl", "-timeout", str(timeout), "-silent"]

    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])
    if extra_headers:
        for h in extra_headers:
            cmd.extend(["-H", h])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return False, { "error": f"timed out after {timeout}s" }
    except FileNotFoundError:
        return False, { "error": f"nuclei not found: {nuclei_path}" }

    if res.returncode != 0:
        return False, {"error": f"nuclei exited {res.returncode}: {res.stderr.strip()[:500]}"}

    events = []
    for line in res.stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if events:
        summaries = []
        for e in events[:10]:
            info = e.get("info", {})
            summaries.append(info.get("severity", "?"))

        criticals = sum(sev == "critical" for sev in summaries)
        highs = sum(sev == "high" for sev in summaries)
        return True, {
            "matched": True,
            "count": len(events),
            "events": events,
            "summary": f"{len(events)} match(es): {criticals}x critical, {highs}x high",
        }
    return False, {
        "matched": False,
        "count": 0,
        "events": [],
        "summary": "No matches",
    }


def wp_auth_login(url, username, password):
    """Post to wp-login.php and return cookie string on success."""
    try:
        import requests as _req
        with _req.Session() as s:
            r = s.post(
                f"{url}/wp-login.php",
                data={"log": username, "pwd": password,
                      "wp-submit": "Log+In", "testcookie": 1},
                allow_redirects=True, timeout=30,
            )
            if r.status_code == 200:
                parts = [f"{c.name}={c.value}" for c in s.cookies]
                return "; ".join(parts)
    except Exception as exc:
        print(f"    Login error: {exc}")
    return None


def test_single(nuclei_path, url, yaml_file, cookie=None, username=None, password=None,
                headers=None, dry_run=False):
    """Test one YAML file and print results."""
    print(f"\n{'='*65}")
    print(f"  Rule   : {os.path.basename(yaml_file)}")
    print(f"  Target : {url}")
    print(f"{'='*65}")

    meta = parse_simple_yaml(yaml_file)
    if meta:
        print(f"  ID     : {meta.get('rule_id', '?')}")
        print(f"  Slug   : {meta.get('slug', '?')}")
        print(f"  Severity: {meta.get('severity', '?')}")
        print(f"  Name   : {meta.get('name', '?')[:70]}")

    if dry_run:
        print("\n  [dry-run] Skipped nuclei scan")
        return "dry_run"

    if username and password:
        print(f"\n  Logging in as {username} ...")
        cookies = wp_auth_login(url, username, password)
        if cookies:
            cookie = cookies
            print("  Login success")
        else:
            print("  Login FAILED -- continuing without auth")

    matched, data = run_nuclei(nuclei_path, url, yaml_file, 120, cookie, headers)

    if "error" in data:
        print(f"\n  X Nuclei error: {data['error']}")
        return "failed"

    if matched:
        print(f"\n  V MATCHED: {data['count']} hit(s)")
        print(f"    {data['summary']}")
        for i, ev in enumerate(data.get("events", [])[:10], 1):
            tmpl   = ev.get("template-id", ev.get("template", "-"))
            info   = ev.get("info", {})
            name   = info.get("name", info.get("template", "-"))
            sev    = info.get("severity", "-")
            matcher = ev.get("matcher-name", "-")
            print(f"    {i:2d}. [{sev:>7s}] {name[:60]}  matcher={matcher}")
        return "verified"
    else:
        print(f"\n  X No matches")
        return "rejected"


def test_dir(nuclei_path, url, yaml_dir, cookie=None, username=None, password=None,
             headers=None, dry_run=False):
    """Test every YAML in a directory."""
    files = sorted(
        f for f in os.listdir(yaml_dir)
        if f.lower().endswith((".yaml", ".yml"))
    )
    print(f"\n  Found {len(files)} YAML file(s) in {yaml_dir}")
    print(f"  URL : {url}  |  Nuclei : {nuclei_path}")

    counts = {}
    for fname in files:
        status = test_single(nuclei_path, url, os.path.join(yaml_dir, fname),
                             cookie=cookie, username=username, password=password,
                             headers=headers, dry_run=dry_run)
        counts[status] = counts.get(status, 0) + 1

    print(f"\n{'='*65}")
    print("  SUMMARY")
    print(f"{'='*65}")
    for k in ("verified", "rejected", "failed", "dry_run"):
        if k in counts:
            symbol = {"verified": "V", "rejected": "X", "failed": "!", "dry_run": "~"}[k]
            print(f"    {symbol} {k:10s}: {counts[k]}")
    print(f"{'='*65}")


# ══════════════════════ CLI ══════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="WP-Nuclei Local Tester -- nuclei CLI against local WordPress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # scan a directory
  python run_local.py --url http://localhost:8081 --yaml-dir ./test_yamls

  # single file, no auth
  python run_local.py --url http://localhost:8081 --file ./test_yamls/health_check.yaml

  # single file, auth via login
  python run_local.py --url http://localhost:8081 --file sqli.yaml --username admin --password admin

  # single file, auth via cookie header
  python run_local.py --url http://localhost:8081 --file sqli.yaml --cookie "wordpress_sec=abc"

  # dry-run (parse only)
  python run_local.py --url http://localhost:8081 --yaml-dir ./test_yamls --dry-run

  # custom nuclei path
  python run_local.py --url http://localhost:8081 --file x.yaml --nuclei C:/Users/NEMATO~1/go/bin/nuclei.exe
""",
    )
    ap.add_argument("--url",      required=True, help="WordPress URL (http://host:port)")
    ap.add_argument("--file", "-f",           help="Single YAML file")
    ap.add_argument("--yaml-dir", "-d",       help="Directory of YAML files")
    ap.add_argument("--nuclei",   default="nuclei", help="Nuclei path (default: nuclei)")
    ap.add_argument("--cookie",   "-c",       help="Cookie header value for auth")
    ap.add_argument("--username", "-u",       help="WP username (auto-login for cookies)")
    ap.add_argument("--password", "-p",       help="WP password")
    ap.add_argument("--header",   "-H", action="append", help="Extra HTTP header (repeatable)")
    ap.add_argument("--dry-run",  action="store_true",   help="Parse YAML, skip nuclei")
    a = ap.parse_args()

    if a.file and a.yaml_dir:
        print("ERROR: --file and --yaml-dir are mutual"); sys.exit(1)
    if not a.file and not a.yaml_dir:
        print("ERROR: provide --file or --yaml-dir"); sys.exit(1)

    # verify nuclei binary
    where = shutil.which(a.nuclei)
    if not where and not os.path.exists(a.nuclei):
        print(f"ERROR: nuclei not found: {a.nuclei}"); sys.exit(1)

    print(f"\n  Target: {a.url}")
    # quick reachability check
    try:
        import requests as _req
        r = _req.get(f"{a.url}/", timeout=5, allow_redirects=True)
        if r.status_code == 200:
            print(f"  WordPress reachable (HTTP {r.status_code})")
        else:
            print(f"  Warning: HTTP {r.status_code}")
    except Exception:
        print("  Warning: cannot reach URL -- continuing anyway")

    if a.file:
        test_single(a.nuclei, a.url, a.file, a.cookie, a.username, a.password, a.header, a.dry_run)
    else:
        test_dir(a.nuclei, a.url, a.yaml_dir, a.cookie, a.username, a.password, a.header, a.dry_run)


if __name__ == "__main__":
    main()
