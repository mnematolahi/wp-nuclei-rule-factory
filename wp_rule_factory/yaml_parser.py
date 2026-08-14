"""YAML parser for Nuclei WordPress rules.

Extracts slug, vulnerable/patched versions, rule ID, and auth requirements
from Nuclei YAML template files. Supports common conventions:

  • ``variables:`` block with keys: ``slug``, ``vulnerable_version``, ``patched_version``
  • ``info:`` block with ``metadata:`` containing same keys
  • ``id:`` or ``info.name:`` for rule identifier
  • ``info.tags:`` for WordPress plugin/theme slug inference
  • ``info.name:`` for version range extraction (e.g. "Plugin <= 1.2.3")
"""

import os
import re
from typing import Any

import yaml


# Tags that are generic and should NOT be treated as plugin/theme slugs
_GENERIC_TAGS = {
    "cve", "wordpress", "wp-plugin", "wp-theme", "production",
    "medium", "low", "high", "critical", "info", "local", "network",
    "manual", "panel", "default-logins", "misconfig", "exposure",
    "iot", "mask", "tech", "microsoft", "jira", "grafana", "tomcat",
    "jenkins", "wordpress-core", "wordpress-themes", "wordpress-plugins",
    "rce", "sqli", "xss", "csrf", "lfi", "rfi", "ssrf", "dos",
    "unauth", "auth", "exposure", "sensitive", "default",
}


def _safe_load_yaml(path: str) -> dict[str, Any] | None:
    """Load a YAML file, returning None on any error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:
        return None


def _get_nested(d: dict, *keys: str, default=None):
    """Walk nested dict keys; return default if any key is missing."""
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def _extract_slug(data: dict) -> str | None:
    """Try to extract the WordPress slug from common Nuclei YAML locations."""
    # Direct variable
    slug = _get_nested(data, "variables", "slug")
    if slug:
        return str(slug)

    # Metadata block inside info
    slug = _get_nested(data, "info", "metadata", "slug")
    if slug:
        return str(slug)

    # Matchers may reference a variable — look for {{slug}} patterns
    # and use the variable default if defined
    for var_name, var_value in (data.get("variables") or {}).items():
        if var_name.lower() in ("slug", "plugin", "theme", "target_slug", "wp_slug"):
            return str(var_value)

    # Try to infer from info.tags (e.g. wp-plugin, wp-theme tags)
    tags = _get_nested(data, "info", "tags")
    if tags:
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        for tag in tags:
            tag = str(tag).strip().lower()
            if tag and tag not in _GENERIC_TAGS:
                return tag

    return None


_VERSION_RE = re.compile(r"(<=|<|=)\s*([0-9]+(?:\.[0-9]+){1,3})")


def _extract_vulnerable_version(data: dict) -> str | None:
    """Extract vulnerable version from variables, metadata, or info.name."""
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

    # Also check if variables itself is a string (literal in template)
    variables = data.get("variables", {})
    for var_name in ("vulnerable_version", "vuln_version", "affected_version"):
        if var_name in variables:
            return str(variables[var_name])

    # Try to extract from info.name (e.g. "Plugin <= 1.2.3 - Description")
    name = _get_nested(data, "info", "name")
    if name:
        m = _VERSION_RE.search(str(name))
        if m:
            return f"{m.group(1)} {m.group(2)}"

    return None


def _extract_patched_version(data: dict) -> str | None:
    """Extract patched/safe version from variables or metadata."""
    keys = [
        ("variables", "patched_version"),
        ("variables", "safe_version"),
        ("variables", "fixed_version"),
        ("info", "metadata", "patched_version"),
        ("info", "metadata", "safe_version"),
        ("info", "metadata", "fixed_version"),
    ]
    for key_path in keys:
        val = _get_nested(data, *key_path)
        if val:
            return str(val)

    return None


def _extract_rule_id(data: dict) -> str:
    """Extract the unique rule identifier."""
    # Standard Nuclei `id` field
    rid = data.get("id") or _get_nested(data, "info", "name")
    if rid:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(rid))
        return safe.strip("_") or "unknown_rule"
    # Last resort: use the template-id from info
    return data.get("template-id", "unknown_rule")


def _detect_asset_type(data: dict) -> str:
    """Detect whether the rule targets a plugin or theme."""
    info = data.get("info", {})
    metadata = info.get("metadata", {}) if isinstance(info, dict) else {}

    asset_type = metadata.get("asset_type", metadata.get("type", ""))
    if asset_type in ("plugin", "theme"):
        return asset_type

    # Check tags for wp-plugin / wp-theme
    tags = _get_nested(data, "info", "tags")
    if tags:
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        tag_str = " ".join(str(t) for t in tags).lower()
        if "wp-theme" in tag_str or "wordpress-theme" in tag_str:
            return "theme"

    # Heuristic: check name / description
    name = str(info.get("name", "")).lower()
    description = str(info.get("description", "")).lower()
    combined = name + " " + description
    if "theme" in combined:
        return "theme"
    return "plugin"


def _extract_auth_config(data: dict) -> dict | None:
    """Extract authentication requirements from the YAML."""
    metadata = _get_nested(data, "info", "metadata") or {}
    auth = metadata.get("auth", metadata.get("authentication"))

    if auth is None:
        # Check variables
        auth_var = data.get("variables", {}).get("auth_type", data.get("variables", {}).get("authentication"))
        if auth_var:
            auth = {"type": str(auth_var)}

    if isinstance(auth, dict):
        return {
            "type": auth.get("type", "basic"),
            "role": auth.get("role", "administrator"),
            "username": auth.get("username", "nuclei_test"),
            "password": auth.get("password", "nuclei_test_2024!"),
        }

    if isinstance(auth, str):
        return {"type": auth, "role": "administrator", "username": "nuclei_test", "password": "nuclei_test_2024!"}

    return None


def parse_single_yaml(yaml_path: str) -> dict | None:
    """Parse a single Nuclei YAML file and extract rule metadata.

    Returns a dict with keys:
      - rule_id, slug, vulnerable_version, patched_version,
        asset_type, auth, yaml_path
    Returns None if essential fields (rule_id, slug) are missing.
    """
    abspath = os.path.abspath(yaml_path)

    data = _safe_load_yaml(abspath)
    if data is None:
        return None

    slug = _extract_slug(data)
    if not slug:
        return None

    rule_id = _extract_rule_id(data)
    vulnerable_version = _extract_vulnerable_version(data)
    patched_version = _extract_patched_version(data)
    asset_type = _detect_asset_type(data)
    auth = _extract_auth_config(data)

    return {
        "rule_id": rule_id,
        "slug": slug,
        "vulnerable_version": vulnerable_version,
        "patched_version": patched_version,
        "asset_type": asset_type,
        "auth": auth,
        "yaml_path": abspath,
    }


def parse_yaml_directory(yaml_dir: str, logger=None) -> list[dict]:
    """Parse all YAML files in a directory (non-recursive).

    Returns a list of parsed rule dicts. Rules that fail to parse
    are logged and skipped.
    """
    parsed = []

    if not os.path.isdir(yaml_dir):
        if logger:
            logger.error("SYSTEM", "parsing", f"Directory not found: {yaml_dir}")
        return parsed

    yaml_files = sorted(
        f for f in os.listdir(yaml_dir)
        if f.lower().endswith((".yaml", ".yml"))
    )

    for filename in yaml_files:
        full_path = os.path.join(yaml_dir, filename)
        result = parse_single_yaml(full_path)

        if result is None:
            if logger:
                logger.warn("SYSTEM", "parsing", f"Skipped {filename}: failed to parse or missing slug")
            continue

        missing = []
        if not result.get("slug"):
            missing.append("slug")
        if not result.get("vulnerable_version"):
            missing.append("vulnerable_version")

        if missing:
            if logger:
                logger.log_rule(
                    result["rule_id"], "rejected", "parsing",
                    f"Missing required fields: {', '.join(missing)} in {filename}",
                )
            continue

        if logger:
            logger.info(
                result["rule_id"], "parsing",
                f"Parsed {filename}: slug={result['slug']}, "
                f"vuln={result['vulnerable_version']}, "
                f"patched={result.get('patched_version', 'auto')}",
            )

        parsed.append(result)

    return parsed
