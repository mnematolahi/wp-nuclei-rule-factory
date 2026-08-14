"""Output packager for WP-Nuclei-Rule-Factory.

Creates verified rule packages that contain:
  - The original (verified) Nuclei YAML with `verified: true` added
  - The vulnerable version ZIP
  - The patched version ZIP
  - A comprehensive metadata.json file
"""

import os
import shutil
from datetime import datetime
from typing import Any

import yaml

from .utils import save_json_file, safe_filename


class Packager:
    """Creates verified Nuclei rule packages."""

    def __init__(self, output_dir: str, logger=None):
        self._output_dir = os.path.abspath(output_dir)
        self._logger = logger
        os.makedirs(self._output_dir, exist_ok=True)

    def create_package(self, rule_id: str, rule_yaml_path: str,
                       vulnerable_zip: str, vulnerable_sha256: str,
                       patched_zip: str, patched_sha256: str,
                       metadata: dict[str, Any]) -> str:
        """Create a verified rule package directory.

        Parameters
        ----------
        rule_id : str
            Unique rule identifier (used in directory name).
        rule_yaml_path : str
            Path to the original Nuclei YAML template.
        vulnerable_zip : str
            Path to the downloaded vulnerable version ZIP.
        vulnerable_sha256 : str
            SHA-256 hash of the vulnerable ZIP.
        patched_zip : str
            Path to the downloaded patched version ZIP.
        patched_sha256 : str
            SHA-256 hash of the patched ZIP.
        metadata : dict
            Additional metadata (slug, versions, CVE, summaries, etc.)

        Returns
        -------
        str
            Path to the created package directory.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_id = safe_filename(rule_id)
        package_dir = os.path.join(
            self._output_dir, f"{safe_id}_verified_{timestamp}")
        os.makedirs(package_dir, exist_ok=True)

        if self._logger:
            self._logger.info(rule_id, "packaging",
                              f"Creating package: {package_dir}")

        # 1. Copy & annotate YAML
        yaml_dest = os.path.join(package_dir, "rule.yaml")
        self._annotate_and_copy_yaml(rule_yaml_path, yaml_dest, metadata)

        # 2. Copy ZIPs
        vuln_dest = os.path.join(package_dir, "vulnerable.zip")
        patched_dest = os.path.join(package_dir, "patched.zip")
        shutil.copy2(vulnerable_zip, vuln_dest)
        shutil.copy2(patched_zip, patched_dest)

        if self._logger:
            self._logger.info(rule_id, "packaging", "Copied ZIP artifacts")

        # 3. Write metadata.json
        full_metadata = {
            "rule_id": rule_id,
            "verified": True,
            "packaged_at": datetime.utcnow().isoformat() + "Z",
            "vulnerable_sha256": vulnerable_sha256,
            "patched_sha256": patched_sha256,
            **metadata,
        }
        metadata_path = os.path.join(package_dir, "metadata.json")
        save_json_file(metadata_path, full_metadata)

        if self._logger:
            self._logger.info(rule_id, "packaging",
                              f"Package created ✓ ({package_dir})")

        return package_dir

    def _annotate_and_copy_yaml(self, src: str, dest: str,
                                 metadata: dict[str, Any]) -> None:
        """Copy the YAML and add `verified: true` and `nuclei_validated_at` to metadata."""
        try:
            with open(src, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception:
            # Fallback: just copy the raw file
            shutil.copy2(src, dest)
            return

        if not isinstance(data, dict):
            data = {}

        # Ensure info → metadata exists
        if "info" not in data or not isinstance(data.get("info"), dict):
            data["info"] = {}
        if "metadata" not in data["info"] or not isinstance(data["info"].get("metadata"), dict):
            data["info"]["metadata"] = {}

        # Annotation
        data["info"]["metadata"]["nuclei_verified"] = True
        data["info"]["metadata"]["nuclei_validated_at"] = datetime.utcnow().isoformat() + "Z"
        data["info"]["metadata"]["nuclei_vulnerable_version"] = metadata.get("vulnerable_version", "")
        data["info"]["metadata"]["nuclei_patched_version"] = metadata.get("patched_version", "")
        if metadata.get("cve"):
            data["info"]["metadata"]["cve"] = metadata["cve"]

        # Write
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, default_flow_style=False,
                           allow_unicode=True, sort_keys=False)

        # Append verified comment at top if it doesn't start with one
        with open(dest, "r", encoding="utf-8") as fh:
            content = fh.read()

        header = (
            f"# Nuclei-Verified: true\n"
            f"# Validated at: {datetime.utcnow().isoformat()}Z\n"
            f"# Vulnerable: {metadata.get('slug', '?')} v{metadata.get('vulnerable_version', '?')} → "
            f"Patched: v{metadata.get('patched_version', '?')}\n"
        )

        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(header + content)
