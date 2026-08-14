#!/usr/bin/env python3
"""WP-Nuclei-Rule-Factory — Automated Nuclei Rule Validation & Packaging for WordPress.

Usage:
    python wp_rule_factory.py --yaml-dir /path/to/yamls --config config.json --output /path/to/output
"""

import argparse
import json
import os
import sys
from datetime import datetime

from wp_rule_factory.yaml_parser import parse_yaml_directory
from wp_rule_factory.logger import Logger
from wp_rule_factory.utils import load_json_file

# Lazy imports — only loaded when actually needed (not for --dry-run)
_WordfenceClient = None
_WordPressRepo = None
_DockerEnvironment = None
_NucleiScanner = None
_Packager = None


def _get_wordfence_client():
    global _WordfenceClient
    if _WordfenceClient is None:
        from wp_rule_factory.wordfence_client import WordfenceClient as _WC
        _WordfenceClient = _WC
    return _WordfenceClient


def _get_wp_repo():
    global _WordPressRepo
    if _WordPressRepo is None:
        from wp_rule_factory.wp_repo import WordPressRepo as _WR
        _WordPressRepo = _WR
    return _WordPressRepo


def _get_docker_env():
    global _DockerEnvironment
    if _DockerEnvironment is None:
        from wp_rule_factory.docker_cli import DockerEnvironment as _DE
        _DockerEnvironment = _DE
    return _DockerEnvironment


def _get_nuclei_scanner():
    global _NucleiScanner
    if _NucleiScanner is None:
        from wp_rule_factory.nuclei_scanner import NucleiScanner as _NS
        _NucleiScanner = _NS
    return _NucleiScanner


def _get_packager():
    global _Packager
    if _Packager is None:
        from wp_rule_factory.packager import Packager as _PK
        _Packager = _PK
    return _Packager


def parse_args():
    parser = argparse.ArgumentParser(
        description="WP-Nuclei-Rule-Factory: Validate & package WordPress Nuclei rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--yaml-dir",
        required=True,
        help="Directory containing Nuclei YAML rule files",
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON configuration file (default: config.json)",
    )
    parser.add_argument(
        "--output",
        help="Output directory for verified packages (overrides config)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse YAML files only, do not execute tests",
    )
    return parser.parse_args()


def load_config(config_path: str, cli_output: str | None = None) -> dict:
    default_config = {
        "docker_image": "wordpress:latest",
        "mysql_image": "mysql:8.0",
        "mysql_database": "testdb",
        "nuclei_path": "nuclei",
        "nuclei_docker_image": "projectdiscovery/nuclei:latest",
        "nuclei_timeout": 120,
        "wf_api_token": "",
        "wf_db_file": "wordfence_production_db.json",
        "wf_db_url": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
        "wf_db_max_age_hours": 72,
        "wp_plugin_download_url": "https://downloads.wordpress.org/plugin/{slug}.{version}.zip",
        "wp_theme_download_url": "https://downloads.wordpress.org/theme/{slug}.{version}.zip",
        "wp_plugin_info_url": "https://api.wordpress.org/plugins/info/1.0/{slug}.json",
        "request_delay_seconds": 1.0,
        "max_retries": 3,
        "retry_backoff_factor": 2.0,
        "container_startup_timeout": 120,
        "default_output_dir": "./verified_packages",
    }

    file_config = load_json_file(config_path) if os.path.exists(config_path) else {}
    config = {**default_config, **file_config}

    if cli_output:
        config["default_output_dir"] = cli_output

    return config


def main():
    args = parse_args()
    config = load_config(args.config, args.output)

    yaml_dir = os.path.abspath(args.yaml_dir)
    output_dir = os.path.abspath(config["default_output_dir"])

    if not os.path.isdir(yaml_dir):
        print(f"[ERROR] YAML directory not found: {yaml_dir}")
        sys.exit(1)

    logger = Logger(output_dir)
    logger.info("SYSTEM", "start", f"WP-Nuclei-Rule-Factory v1.0.0 started")
    logger.info("SYSTEM", "start", f"YAML dir: {yaml_dir}, Output: {output_dir}")

    # ── Stage 1: Parse YAML files ───────────────────────────────────
    logger.info("SYSTEM", "parsing", f"Scanning YAML files in: {yaml_dir}")
    parsed_rules = parse_yaml_directory(yaml_dir, logger)
    logger.info("SYSTEM", "parsing", f"Parsed {len(parsed_rules)} rules from YAML files")

    if not parsed_rules:
        logger.info("SYSTEM", "complete", "No valid rules found. Exiting.")
        logger.print_summary()
        return

    if args.dry_run:
        logger.info("SYSTEM", "dry-run", "Dry-run mode: skipping testing & packaging")
        for rule in parsed_rules:
            logger.log_rule(rule["rule_id"], "dry_parsed", "parsing",
                            f"slug={rule.get('slug')}, vuln={rule.get('vulnerable_version')}")
        logger.print_summary()
        return

    # ── Stage 2: Initialize services ────────────────────────────────
    logger.info("SYSTEM", "init", "Initializing Wordfence client")
    WFC = _get_wordfence_client()
    wf_client = WFC(
        api_token=config["wf_api_token"],
        db_file=config["wf_db_file"],
        db_url=config["wf_db_url"],
        db_max_age_hours=config["wf_db_max_age_hours"],
        delay=config["request_delay_seconds"],
        max_retries=config["max_retries"],
        backoff=config["retry_backoff_factor"],
        logger=logger,
    )

    WPR = _get_wp_repo()
    wp_repo = WPR(
        plugin_url_template=config["wp_plugin_download_url"],
        theme_url_template=config["wp_theme_download_url"],
        plugin_info_url=config["wp_plugin_info_url"],
        delay=config["request_delay_seconds"],
        max_retries=config["max_retries"],
        backoff=config["retry_backoff_factor"],
        logger=logger,
    )

    NS = _get_nuclei_scanner()
    nuclei_scanner = NS(
        nuclei_path=config["nuclei_path"],
        timeout=config["nuclei_timeout"],
        logger=logger,
    )

    # Docker-based nuclei settings (optional)
    nuclei_docker_image = config.get("nuclei_docker_image")
    use_docker_nuclei = bool(nuclei_docker_image)
    if use_docker_nuclei and logger:
        logger.info("SYSTEM", "init",
                    f"Using Docker-based nuclei: {nuclei_docker_image}")

    PK = _get_packager()
    packager = PK(output_dir=output_dir, logger=logger)

    # ── Stage 3: Process each rule ──────────────────────────────────
    for idx, rule in enumerate(parsed_rules, 1):
        rule_id = rule["rule_id"]
        rule_yaml_path = rule["yaml_path"]
        logger.info(rule_id, "start", f"[{idx}/{len(parsed_rules)}] Processing rule")

        try:
            # 3a. Resolve versions from Wordfence
            logger.info(rule_id, "wordfence", f"Querying Wordfence for slug={rule['slug']}")
            wf_result = wf_client.find_vulnerability(
                slug=rule["slug"],
                vulnerable_hint=rule.get("vulnerable_version"),
            )

            if not wf_result:
                logger.log_rule(rule_id, "rejected", "wordfence",
                                f"No vulnerability data found for slug={rule['slug']}")
                continue

            vulnerable_version = wf_result["vulnerable_version"]
            patched_version = wf_result["patched_version"]
            logger.info(rule_id, "wordfence",
                        f"Resolved: vulnerable={vulnerable_version}, patched={patched_version}")

            # 3b. Download both versions
            logger.info(rule_id, "download", f"Downloading {rule['slug']} v{vulnerable_version}")
            vuln_zip, vuln_sha256 = wp_repo.download_version(
                slug=rule["slug"],
                version=vulnerable_version,
                asset_type=rule.get("asset_type", "plugin"),
            )
            if not vuln_zip:
                logger.log_rule(rule_id, "rejected", "download",
                                f"Failed to download vulnerable version {vulnerable_version}")
                continue

            logger.info(rule_id, "download", f"Downloading {rule['slug']} v{patched_version}")
            patched_zip, patched_sha256 = wp_repo.download_version(
                slug=rule["slug"],
                version=patched_version,
                asset_type=rule.get("asset_type", "plugin"),
            )
            if not patched_zip:
                logger.log_rule(rule_id, "rejected", "download",
                                f"Failed to download patched version {patched_version}")
                continue

            # 3c. Test vulnerable version
            logger.info(rule_id, "nuclei", "Building Docker env for VULNERABLE version")
            DE = _get_docker_env()
            docker_vuln = DE(
                docker_image=config["docker_image"],
                mysql_image=config["mysql_image"],
                database=config["mysql_database"],
                startup_timeout=config["container_startup_timeout"],
                logger=logger,
            )
            with docker_vuln as env:
                installed = env.install_plugin_or_theme(
                    slug=rule["slug"],
                    zip_path=vuln_zip,
                    asset_type=rule.get("asset_type", "plugin"),
                )
                if not installed:
                    logger.log_rule(rule_id, "failed", "docker",
                                    "Failed to install vulnerable asset")
                    continue
                cookie_header = None
                if rule.get("auth"):
                    auth = rule["auth"]
                    cookie_header = env.create_user(
                        auth["username"], auth["password"], auth.get("role", "administrator"))
                    if not cookie_header:
                        logger.log_rule(rule_id, "failed", "docker",
                                        "Failed to create/login test user for authenticated rule")
                        continue
                target_url = env.get_url()
                logger.info(rule_id, "nuclei", f"Running Nuclei scan on VULNERABLE: {target_url}")
                vuln_match = nuclei_scanner.scan(
                    target_url=target_url,
                    template_path=rule_yaml_path,
                    auth_config=rule.get("auth"),
                    cookie_header=cookie_header,
                    docker_image=nuclei_docker_image if use_docker_nuclei else None,
                    docker_network=env.network_name if use_docker_nuclei else None,
                    docker_wp_container_name=env.wp_container_name if use_docker_nuclei else None,
                )

                if not vuln_match or not vuln_match.get("matched"):
                    logger.log_rule(rule_id, "rejected", "nuclei",
                                    "No match on vulnerable version — rule may be invalid")
                    continue

                logger.info(rule_id, "nuclei", f"VULNERABLE scan MATCHED ✓ ({vuln_match['matched_count']} hits)")

            # 3d. Test patched version
            logger.info(rule_id, "nuclei", "Building Docker env for PATCHED version")
            DE2 = _get_docker_env()
            docker_patched = DE2(
                docker_image=config["docker_image"],
                mysql_image=config["mysql_image"],
                database=config["mysql_database"],
                startup_timeout=config["container_startup_timeout"],
                logger=logger,
            )
            with docker_patched as env:
                installed = env.install_plugin_or_theme(
                    slug=rule["slug"],
                    zip_path=patched_zip,
                    asset_type=rule.get("asset_type", "plugin"),
                )
                if not installed:
                    logger.log_rule(rule_id, "failed", "docker",
                                    "Failed to install patched asset")
                    continue
                cookie_header = None
                if rule.get("auth"):
                    auth = rule["auth"]
                    cookie_header = env.create_user(
                        auth["username"], auth["password"], auth.get("role", "administrator"))
                    if not cookie_header:
                        logger.log_rule(rule_id, "failed", "docker",
                                        "Failed to create/login test user for authenticated rule")
                        continue
                target_url = env.get_url()
                logger.info(rule_id, "nuclei", f"Running Nuclei scan on PATCHED: {target_url}")
                patched_match = nuclei_scanner.scan(
                    target_url=target_url,
                    template_path=rule_yaml_path,
                    auth_config=rule.get("auth"),
                    cookie_header=cookie_header,
                    docker_image=nuclei_docker_image if use_docker_nuclei else None,
                    docker_network=env.network_name if use_docker_nuclei else None,
                    docker_wp_container_name=env.wp_container_name if use_docker_nuclei else None,
                )

                if patched_match and patched_match.get("matched"):
                    logger.log_rule(rule_id, "rejected", "nuclei",
                                    f"Match on PATCHED version — likely false positive ({patched_match['matched_count']} hits)")
                    continue

                logger.info(rule_id, "nuclei", "PATCHED scan CLEAN ✓ (no matches)")

            # 3e. Package
            cve = wf_result.get("cve", "")
            packager.create_package(
                rule_id=rule_id,
                rule_yaml_path=rule_yaml_path,
                vulnerable_zip=vuln_zip,
                vulnerable_sha256=vuln_sha256,
                patched_zip=patched_zip,
                patched_sha256=patched_sha256,
                metadata={
                    "slug": rule["slug"],
                    "vulnerable_version": vulnerable_version,
                    "patched_version": patched_version,
                    "cve": cve,
                    "cwe": wf_result.get("cwe", ""),
                    "title": wf_result.get("title", ""),
                    "severity": wf_result.get("severity", ""),
                    "nuclei_vuln_summary": vuln_match["summary"],
                    "nuclei_patched_summary": "No matches — clean",
                    "test_timestamp": datetime.utcnow().isoformat() + "Z",
                },
            )

            logger.log_rule(rule_id, "verified", "complete",
                            f"✓ VERIFIED: {vulnerable_version} → {patched_version} | CVE: {cve}")

        except Exception as exc:
            logger.log_rule(rule_id, "failed", "exception",
                            f"Unexpected error: {exc}")
            continue

    # ── Done ────────────────────────────────────────────────────────
    logger.info("SYSTEM", "complete", "All rules processed.")
    logger.print_summary()


if __name__ == "__main__":
    main()
