#!/usr/bin/env python3
"""Check WordPress.org plugin/theme slugs from YAML files.

Scans a directory of nuclei YAML templates, extracts slugs,
and checks whether each slug exists in the WordPress.org repository.

Usage:
    python check_plugins.py --dir ./test_yamls
    python check_plugins.py --dir ./nuclei-templates/wordpress
"""

import argparse
import os
import sys

import requests
import yaml


_GENERIC_TAGS = {
    "cve", "wordpress", "wp-plugin", "wp-theme", "production",
    "medium", "low", "high", "critical", "info", "local", "network",
    "manual", "panel", "default-logins", "misconfig", "exposure",
    "iot", "mask", "tech", "microsoft", "jira", "grafana", "tomcat",
    "jenkins", "wordpress-core", "wordpress-themes", "wordpress-plugins",
    "rce", "sqli", "xss", "csrf", "lfi", "rfi", "ssrf", "dos",
    "unauth", "auth", "exposure", "sensitive", "default",
}


def _get_nested(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def extract_slug(data):
    slug = _get_nested(data, "variables", "slug")
    if slug:
        return str(slug)
    slug = _get_nested(data, "info", "metadata", "slug")
    if slug:
        return str(slug)
    for var_name, var_value in (data.get("variables") or {}).items():
        if var_name.lower() in ("slug", "plugin", "theme", "target_slug", "wp_slug"):
            return str(var_value)
    tags = _get_nested(data, "info", "tags")
    if tags:
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        for tag in tags:
            tag = str(tag).strip().lower()
            if tag and tag not in _GENERIC_TAGS:
                return tag
    return None


def check_slug(slug, timeout=15):
    """Check if a plugin/theme slug exists in WordPress.org."""
    url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            versions = list(data.get("versions", {}).keys())
            versions = [v for v in versions if v != "trunk"]
            return {
                "found": True,
                "name": data.get("name", slug),
                "versions": len(versions),
                "latest": data.get("version", "?"),
                "sample": versions[:5],
            }
        else:
            return {"found": False, "status": resp.status_code}
    except Exception as e:
        return {"found": False, "error": str(e)}


def main():
    ap = argparse.ArgumentParser(description="Check WP.org slugs from YAML files")
    ap.add_argument("--dir", required=True, help="Directory of YAML files")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of files")
    args = ap.parse_args()

    root = os.path.abspath(args.dir)
    if not os.path.isdir(root):
        print(f"ERROR: directory not found: {root}")
        sys.exit(1)

    yaml_files = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith((".yaml", ".yml")):
                yaml_files.append(os.path.join(dirpath, fn))
    yaml_files.sort()
    if args.limit > 0:
        yaml_files = yaml_files[: args.limit]

    slugs = []
    for path in yaml_files:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        slug = extract_slug(data)
        if slug:
            slugs.append((os.path.relpath(path, root), slug))

    unique_slugs = sorted(set(slug for _, slug in slugs))
    print(f"\nFound {len(unique_slugs)} unique slugs in {len(yaml_files)} YAML files\n")
    print("=" * 60)

    found = []
    not_found = []
    errors = []

    for slug in unique_slugs:
        result = check_slug(slug)
        if result.get("found"):
            found.append((slug, result))
        elif "error" in result:
            errors.append((slug, result["error"]))
        else:
            not_found.append((slug, result.get("status", "?")))

    print(f"\nSummary: {len(found)} found, {len(not_found)} not found, {len(errors)} errors\n")

    if found:
        print("-" * 60)
        print("FOUND SLUGS:")
        print("-" * 60)
        for slug, r in found:
            print(f"  {slug}")
            print(f"    name={r['name']}, versions={r['versions']}, latest={r['latest']}")
            if r["sample"]:
                print(f"    sample: {r['sample']}")

    if not_found:
        print("\n" + "-" * 60)
        print("NOT FOUND SLUGS (HTTP error or missing):")
        print("-" * 60)
        for slug, status in not_found:
            print(f"  {slug}  -> HTTP {status}")

    if errors:
        print("\n" + "-" * 60)
        print("ERRORS:")
        print("-" * 60)
        for slug, err in errors:
            print(f"  {slug}  -> {err}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
