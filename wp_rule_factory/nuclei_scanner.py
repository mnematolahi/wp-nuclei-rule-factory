"""Nuclei scanner integration for WP-Nuclei-Rule-Factory.

Runs nuclei CLI commands against a target WordPress instance, parses
the JSONL output, and determines whether matches were found.
Uses Docker CLI for reliable operation on all platforms.
"""

import os
import subprocess
from typing import Any

from .utils import validate_nuclei_json_output


class NucleiScanner:
    """Runs Nuclei scans and interprets results."""

    def __init__(self, nuclei_path: str = "nuclei",
                 timeout: int = 120, logger=None):
        self._nuclei_path = nuclei_path
        self._timeout = timeout
        self._logger = logger

    def scan(self, target_url: str, template_path: str,
             auth_config: dict[str, Any] | None = None,
             cookie_header: str | None = None,
             docker_image: str | None = None,
             docker_network: str | None = None,
             docker_wp_container_name: str | None = None) -> dict | None:
        """Run a Nuclei scan and return match results.

        Parameters
        ----------
        target_url : str
            URL of the WordPress target (e.g. http://localhost:32768).
        template_path : str
            Path to the Nuclei YAML template.
        auth_config : dict | None
            Authentication config.
        cookie_header : str | None
            Pre-obtained cookie string for authenticated requests.
        docker_image : str | None
            If provided, run nuclei via Docker.
        docker_network : str | None
            Docker network name to connect the nuclei container to.
        docker_wp_container_name : str | None
            WordPress container name for internal DNS resolution.

        Returns
        -------
        dict or None
        """
        if not os.path.exists(template_path):
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   f"Template not found: {template_path}")
            return None

        cookie = cookie_header

        if docker_image:
            return self._scan_docker(
                target_url, template_path, cookie,
                docker_image, docker_network, docker_wp_container_name
            )

        return self._scan_host(target_url, template_path, cookie)

    def _scan_host(self, target_url: str, template_path: str,
                   cookie: str | None) -> dict | None:
        """Run nuclei as a local subprocess."""
        cmd = [self._nuclei_path, "-u", target_url, "-t", template_path,
               "-jsonl", "-timeout", str(self._timeout)]

        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        if self._logger:
            self._logger.info("SYSTEM", "nuclei", f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._timeout + 30)
        except subprocess.TimeoutExpired:
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   f"Nuclei timed out after {self._timeout + 30}s")
            return None
        except FileNotFoundError:
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   f"Nuclei binary not found: {self._nuclei_path}")
            return None

        return self._parse_nuclei_output(result.stdout, result.stderr,
                                         result.returncode)

    def _scan_docker(self, target_url: str, template_path: str,
                     cookie: str | None, docker_image: str,
                     network_name: str | None,
                     wp_container_name: str | None) -> dict | None:
        """Run nuclei in the WordPress network using a read-only template mount."""
        # Determine target URL
        if network_name and wp_container_name:
            internal_url = f"http://{wp_container_name}:80"
            if self._logger:
                self._logger.info("SYSTEM", "nuclei",
                                  f"Internal URL: {internal_url}")
                self._logger.info("SYSTEM", "nuclei",
                                  f"Network: {network_name}")
        else:
            internal_url = target_url
            if self._logger:
                self._logger.warn("SYSTEM", "nuclei",
                                  f"No network provided, using: {internal_url}")

        template_container_path = "/tmp/nuclei-template.yaml"
        try:
            nuclei_cmd = ["docker", "run", "--rm"]
            if network_name:
                nuclei_cmd.extend(["--network", network_name])
            nuclei_cmd.extend([
                "-v", f"{os.path.abspath(template_path)}:{template_container_path}:ro",
                docker_image,
                "-u", internal_url,
                "-t", template_container_path,
                "-jsonl",
                "-no-color",
                "-duc",
                "-timeout", str(self._timeout),
            ])
            if cookie:
                nuclei_cmd.extend(["-H", f"Cookie: {cookie}"])

            if self._logger:
                self._logger.info("SYSTEM", "nuclei",
                                  f"Executing nuclei in container")

            exec_result = subprocess.run(
                nuclei_cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout + 30)

            stdout = exec_result.stdout
            stderr = exec_result.stderr
            returncode = exec_result.returncode

            if self._logger and stderr.strip():
                lines = stderr.strip().split("\n")
                status_lines = [
                    l
                    for l in lines
                    if not l.startswith("{") and l.strip()
                ]
                if status_lines:
                    self._logger.info(
                        "SYSTEM", "nuclei",
                        f"Nuclei status: {' | '.join(status_lines[:10])}")

            if not stdout.strip():
                if self._logger:
                    self._logger.warn("SYSTEM", "nuclei",
                                      "No JSON output from nuclei")

        except subprocess.TimeoutExpired:
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   "Container operation timed out")
            return None
        except Exception as exc:
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   f"Docker execution failed: {exc}")
            return None
        return self._parse_nuclei_output(stdout, stderr, returncode)

    def _parse_nuclei_output(self, stdout: str, stderr: str,
                             returncode: int) -> dict | None:
        """Parse nuclei stdout/stderr/returncode into a result dict."""
        if stderr.strip():
            if self._logger:
                self._logger.warn("SYSTEM", "nuclei",
                                  f"Nuclei stderr: {stderr[:500]}")

        if returncode != 0:
            if self._logger:
                self._logger.error("SYSTEM", "nuclei",
                                   f"Nuclei failed with exit code {returncode}: {stderr[:500]}")
            return None

        results = validate_nuclei_json_output(stdout)

        if not results:
            return {
                "matched": False,
                "matched_count": 0,
                "results": [],
                "summary": "No matches — target is not vulnerable "
                           "(or template did not fire)",
            }

        severities = {}
        for r in results:
            sev = r.get("info", {}).get("severity", "unknown")
            severities[sev] = severities.get(sev, 0) + 1

        summary_parts = [
            f"{cnt}x {sev}"
            for sev, cnt in sorted(severities.items())
        ]
        summary = (
            f"{len(results)} match(es): "
            f"{', '.join(summary_parts)}"
        )

        if self._logger:
            self._logger.info("SYSTEM", "nuclei",
                              f"Scan result: {summary}")

        return {
            "matched": True,
            "matched_count": len(results),
            "results": results,
            "summary": summary,
        }
