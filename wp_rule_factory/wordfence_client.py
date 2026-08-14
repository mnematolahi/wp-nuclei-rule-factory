"""Wordfence Intelligence API client.

Downloads and caches the Production vulnerability feed, then resolves
exact vulnerable / patched versions for a given WordPress plugin/theme slug
using the same algorithm as the existing wp_sast_dataset_generator.py.
"""

import json
import os
import time
from datetime import datetime
from typing import Any

import requests
from packaging.version import parse as vparse, InvalidVersion


# ── Helpers ─────────────────────────────────────────────────────────
def _safe_parse(v: str):
    try:
        return vparse(v)
    except InvalidVersion:
        return None


def _find_versions_in_range(all_versions: list[str], from_version: str,
                            from_inclusive: bool, to_version: str,
                            to_inclusive: bool) -> list:
    """Filter released versions to those within a given affected_versions range."""
    matches = []
    for v in all_versions:
        vp = _safe_parse(v)
        if vp is None:
            continue

        if from_version != "*":
            fv = _safe_parse(from_version)
            if fv is None:
                continue
            if vp < fv or (vp == fv and not from_inclusive):
                continue

        if to_version != "*":
            tv = _safe_parse(to_version)
            if tv is None:
                continue
            if vp > tv or (vp == tv and not to_inclusive):
                continue

        matches.append(vp)
    return matches


# ── Client ──────────────────────────────────────────────────────────
class WordfenceClient:
    """Cached Wordfence Intelligence API client with rate limiting & retries."""

    def __init__(self, api_token: str, db_file: str, db_url: str,
                 db_max_age_hours: int = 72, delay: float = 1.0,
                 max_retries: int = 3, backoff: float = 2.0, logger=None):
        self._api_token = api_token
        self._db_file = db_file
        self._db_url = db_url
        self._db_max_age_hours = db_max_age_hours
        self._delay = delay
        self._max_retries = max_retries
        self._backoff = backoff
        self._logger = logger
        self._db: dict[str, Any] | None = None
        self._last_request = 0.0

    # ── Initialization ──────────────────────────────────────────
    def _load_or_download_db(self) -> dict[str, Any]:
        """Load cached DB or download fresh from Wordfence."""
        # Try existing cache
        if os.path.exists(self._db_file):
            age_hours = (datetime.now().timestamp() - os.path.getmtime(self._db_file)) / 3600
            if age_hours < self._db_max_age_hours:
                try:
                    with open(self._db_file, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if data:
                        if self._logger:
                            self._logger.info("SYSTEM", "wordfence",
                                              f"Using cached DB ({self._db_file}), age={age_hours:.1f}h")
                        return data
                except Exception:
                    pass
            elif self._logger:
                self._logger.info("SYSTEM", "wordfence",
                                  f"Cache is {age_hours:.1f}h old (> {self._db_max_age_hours}h), re-downloading")

        return self._download_db()

    def _download_db(self) -> dict[str, Any]:
        """Download Production feed from Wordfence with progress logging."""
        if self._logger:
            self._logger.info("SYSTEM", "wordfence", "Downloading Production feed from Wordfence...")

        session = requests.Session()
        headers = {"Authorization": f"Bearer {self._api_token}", "Accept": "application/json"}

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = session.get(self._db_url, headers=headers, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if self._logger:
                        self._logger.info("SYSTEM", "wordfence",
                                          f"Downloaded: {len(data)} records")
                    # Persist
                    with open(self._db_file, "w", encoding="utf-8") as fh:
                        json.dump(data, fh)
                    return data

                if resp.status_code in (429, 503):
                    wait = self._backoff ** attempt
                    if self._logger:
                        self._logger.warn("SYSTEM", "wordfence",
                                          f"HTTP {resp.status_code}, retrying in {wait}s (attempt {attempt}/{self._max_retries})")
                    time.sleep(wait)
                    continue

                if self._logger:
                    self._logger.error("SYSTEM", "wordfence",
                                       f"HTTP {resp.status_code}: {resp.text[:200]}")
                return {}

            except Exception as exc:
                if self._logger:
                    self._logger.error("SYSTEM", "wordfence", f"Download error: {exc}")
                if attempt < self._max_retries:
                    time.sleep(self._backoff ** attempt)

        return {}

    def ensure_db(self) -> dict[str, Any]:
        """Guarantee the database is loaded; returns it."""
        if self._db is None:
            self._db = self._load_or_download_db()
        return self._db

    # ── Rate limiting ───────────────────────────────────────────
    def _wait_rate(self):
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request = time.monotonic()

    # ── Version resolution (borrowed from wp_sast_dataset_generator) ──
    def _get_released_versions(self, slug: str) -> dict[str, str]:
        """Query WordPress.org plugin-info API for all released versions."""
        url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
        self._wait_rate()
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                return {}
            data = resp.json()
            if not isinstance(data, dict) or "error" in data:
                return {}
            versions = data.get("versions", {})
            return {v: url for v, url in versions.items() if v.lower() != "trunk"}
        except Exception:
            return {}

    def _resolve_vulnerable_version(self, released: list[str],
                                     affected_versions: dict) -> str | None:
        """Find the highest released version still inside the affected range(s)."""
        best = None
        for range_info in affected_versions.values():
            matches = _find_versions_in_range(
                released,
                range_info.get("from_version", "*"),
                range_info.get("from_inclusive", True),
                range_info.get("to_version", "*"),
                range_info.get("to_inclusive", True),
            )
            if matches:
                candidate = max(matches)
                if best is None or candidate > best:
                    best = candidate
        return str(best) if best is not None else None

    def _resolve_patched_version(self, released: list[str],
                                  patched_versions: list[str]) -> str | None:
        """Find the lowest patched version that was actually released."""
        valid = []
        for pv in patched_versions:
            if pv in released:
                parsed = _safe_parse(pv)
                if parsed is not None:
                    valid.append(parsed)
        if not valid:
            return None
        return str(min(valid))

    # ── Public API ──────────────────────────────────────────────
    def find_vulnerability(self, slug: str,
                           vulnerable_hint: str | None = None) -> dict | None:
        """Find and resolve exact versions for a given WordPress slug.

        Parameters
        ----------
        slug : str
            WordPress plugin or theme slug.
        vulnerable_hint : str | None
            Optional version string hint from the YAML (e.g. "<= 2.3.1").
            Used to disambiguate when multiple CVE records exist.

        Returns
        -------
        dict or None
            {
                "vulnerable_version": "2.3.1",
                "patched_version": "2.3.2",
                "cve": "CVE-2024-...",
                "cwe": "CWE-89",
                "title": "SQL Injection in ...",
                "severity": "high",
            }
            or None if no matching vulnerability found.
        """
        db = self.ensure_db()
        candidates = []

        for vuln_id, vuln_info in db.items():
            sw_list = vuln_info.get("software", [])
            for sw in sw_list:
                if sw.get("slug") != slug:
                    continue
                if not sw.get("patched", False):
                    continue

                patched_versions = sw.get("patched_versions", [])
                affected_versions = sw.get("affected_versions", {})
                if not (patched_versions and affected_versions):
                    continue

                # Get CVSS
                cvss = vuln_info.get("cvss") or {}
                score = cvss.get("score")

                candidates.append({
                    "id": vuln_id,
                    "title": vuln_info.get("title", ""),
                    "cve": vuln_info.get("cve", ""),
                    "cwe": (vuln_info.get("cwe") or {}).get("name", "Unknown"),
                    "severity": cvss.get("rating", ""),
                    "score": float(score) if score is not None else 0.0,
                    "patched_versions": patched_versions,
                    "affected_versions": affected_versions,
                })
                break  # one match per vuln_id

        if not candidates:
            return None

        # Prefer high-severity candidates
        candidates.sort(key=lambda c: c["score"], reverse=True)

        # If hint provided, try to match
        if vulnerable_hint and len(candidates) > 1:
            hint_clean = vulnerable_hint.strip().lstrip("<=").lstrip("<").strip()
            hint_parsed = _safe_parse(hint_clean)
            if hint_parsed:
                # Find candidate whose affected range contains the hint version
                for c in candidates:
                    for rng in c["affected_versions"].values():
                        to_ver = rng.get("to_version", "*")
                        if to_ver != "*":
                            tv = _safe_parse(to_ver)
                            if tv and hint_parsed <= tv:
                                candidates = [c]
                                break
                    if len(candidates) == 1:
                        break

        best = candidates[0]

        # Resolve exact versions
        released_map = self._get_released_versions(slug)
        released_list = list(released_map.keys())

        if not released_list:
            if self._logger:
                self._logger.warn("SYSTEM", "wordfence",
                                  f"No released versions found for slug={slug}")
            return None

        vulnerable_version = self._resolve_vulnerable_version(
            released_list, best["affected_versions"])
        patched_version = self._resolve_patched_version(
            released_list, best["patched_versions"])

        if not vulnerable_version or not patched_version:
            if self._logger:
                self._logger.warn("SYSTEM", "wordfence",
                                  f"Could not resolve exact versions for {slug}: "
                                  f"vuln={vulnerable_version}, patched={patched_version}")
            return None

        if vulnerable_version == patched_version:
            if self._logger:
                self._logger.warn("SYSTEM", "wordfence",
                                  f"Resolved same version {vulnerable_version} for both "
                                  f"vulnerable and patched — skipping")
            return None

        return {
            "vulnerable_version": vulnerable_version,
            "patched_version": patched_version,
            "cve": best["cve"],
            "cwe": best["cwe"],
            "title": best["title"],
            "severity": best["severity"],
        }
