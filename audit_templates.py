#!/usr/bin/env python3
"""Audit nuclei-templates for wp_rule_factory compatibility.

Recursively scans the nuclei-templates directory and reports which YAML files
have the required fields (slug + vulnerable_version) and which do not.

Usage:
    python audit_templates.py --dir ./nuclei-templates
"""

import argparse
import os
import re
import sys

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

_VERSION_RE = re.compile(r"(<=|<|=)\s*([0-9]+(?:\.[0-9]+){1,3})")


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


def extract_vulnerable_version(data):
    keys = [
        ("variables", "vulnerable_version"),
        ("variables", "vuln_version"),
        ("variables", "affected_version"),
        ("info", "metadata", "vulnerable_version"),
        ("info", "metadata", "vuln_version"),
        ("info", "metadata", "affected_version"),
    ]
    for key_path in keys:
        val = _get_nested(data, *key_path)
        if val:
            return str(val)
    variables = data.get("variables", {})
    for var_name in ("vulnerable_version", "vuln_version", "affected_version"):
        if var_name in variables:
            return str(variables[var_name])
    name = _get_nested(data, "info", "name")
    if name:
        m = _VERSION_RE.search(str(name))
        if m:
            return f"{m.group(1)} {m.group(2)}"
    return None


def audit_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return None, "parse_error"

    if not isinstance(data, dict):
        return None, "invalid_yaml"

    slug = extract_slug(data)
    vuln_ver = extract_vulnerable_version(data)

    missing = []
    if not slug:
        missing.append("slug")
    if not vuln_ver:
        missing.append("vulnerable_version")

    if missing:
        return None, "missing: " + ", ".join(missing)

    return {
        "slug": slug,
        "vulnerable_version": vuln_ver,
    }, "ok"


def main():
    ap = argparse.ArgumentParser(description="Audit nuclei-templates for required fields")
    ap.add_argument("--dir", required=True, help="Root directory of nuclei templates")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of files to scan (0=all)")
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

    print(f"\nScanning {len(yaml_files)} YAML files in: {root}\n")
    print("=" * 70)

    valid = []
    invalid = []
    parse_errors = []

    for path in yaml_files:
        rel = os.path.relpath(path, root)
        result, status = audit_file(path)
        if status == "ok":
            valid.append((rel, result))
        elif status == "parse_error":
            parse_errors.append(rel)
        else:
            invalid.append((rel, status))

    print(f"\nTotal YAML files : {len(yaml_files)}")
    print(f"Valid (ready)    : {len(valid)}")
    print(f"Invalid (missing): {len(invalid)}")
    print(f"Parse errors     : {len(parse_errors)}")

    if invalid:
        print("\n" + "-" * 70)
        print("INVALID FILES (missing required fields):")
        print("-" * 70)
        for rel, reason in invalid:
            print(f"  {rel}")
            print(f"    -> {reason}")

    if parse_errors:
        print("\n" + "-" * 70)
        print("PARSE ERRORS:")
        print("-" * 70)
        for rel in parse_errors:
            print(f"  {rel}")

    if valid:
        print("\n" + "-" * 70)
        print("SAMPLE VALID FILES (first 20):")
        print("-" * 70)
        for rel, meta in valid[:20]:
            print(f"  {rel}")
            print(f"    slug={meta['slug']}, vuln={meta['vulnerable_version']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
