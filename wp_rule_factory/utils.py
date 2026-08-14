"""Shared utility functions for WP-Nuclei-Rule-Factory."""

import hashlib
import json
import os
import re
import secrets
import string


def load_json_file(filepath: str) -> dict:
    """Load a JSON file; return empty dict on any error."""
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_json_file(filepath: str, data: dict) -> None:
    """Save data as JSON with indentation."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(8192)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def random_password(length: int = 16) -> str:
    """Generate a cryptographically random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def safe_filename(name: str) -> str:
    """Sanitize a string for safe use as a filename."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", name).strip("_")


def is_http_url(url: str) -> bool:
    """Check if a string is a valid HTTP(S) URL."""
    return bool(re.match(r"^https?://", url))


def validate_nuclei_json_output(output_text: str) -> list[dict]:
    """Parse Nuclei JSONL output into a list of result dicts.
    
    Nuclei outputs one JSON object per line when -json flag is used.
    Empty output or parse errors return an empty list.
    """
    results = []
    for line in output_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results
