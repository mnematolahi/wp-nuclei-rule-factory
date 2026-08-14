"""Structured logger for WP-Nuclei-Rule-Factory.

Produces JSON Lines log files and a human-readable summary report.
Tracks per-rule status for final reporting.
"""

import json
import os
import sys
from datetime import datetime
from typing import Literal

RuleStatus = Literal["verified", "rejected", "failed", "dry_parsed"]


class Logger:
    """JSON Lines logger with rule-status tracking and summary reporting."""

    def __init__(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self._log_path = os.path.join(output_dir, f"run_{timestamp}.jsonl")
        self._summary_path = os.path.join(output_dir, f"run_{timestamp}_summary.txt")

        self._log_fh = open(self._log_path, "w", encoding="utf-8")
        self._rules: dict[str, tuple[RuleStatus, str]] = {}

        self._counts = {
            "total_parsed": 0,
            "verified": 0,
            "rejected": 0,
            "failed": 0,
        }

    # ── Writing ─────────────────────────────────────────────────
    def _write_entry(self, entry: dict) -> None:
        entry.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
        self._log_fh.write(json.dumps(entry, default=str) + "\n")
        self._log_fh.flush()

    # ── Public logging methods ──────────────────────────────────
    def info(self, rule_id: str, stage: str, message: str) -> None:
        self._write_entry({
            "level": "INFO",
            "rule_id": rule_id,
            "stage": stage,
            "message": message,
        })

    def warn(self, rule_id: str, stage: str, message: str) -> None:
        self._write_entry({
            "level": "WARN",
            "rule_id": rule_id,
            "stage": stage,
            "message": message,
        })

    def error(self, rule_id: str, stage: str, message: str) -> None:
        self._write_entry({
            "level": "ERROR",
            "rule_id": rule_id,
            "stage": stage,
            "message": message,
        })

    def log_rule(self, rule_id: str, status: RuleStatus,
                 stage: str, message: str) -> None:
        """Record the final status for a rule and increment counters."""
        self._rules[rule_id] = (status, message)

        if status == "verified":
            self._counts["verified"] += 1
            level = "SUCCESS"
        elif status == "rejected":
            self._counts["rejected"] += 1
            level = "REJECTED"
        elif status == "failed":
            self._counts["failed"] += 1
            level = "FAILED"
        else:
            level = "INFO"

        self._write_entry({
            "level": level,
            "rule_id": rule_id,
            "status": status,
            "stage": stage,
            "message": message,
        })

    # ── Summary ─────────────────────────────────────────────────
    def print_summary(self) -> None:
        """Print and save a human-readable summary."""
        total = len(self._rules)  # all rules that were processed (any status)

        lines = [
            "=" * 60,
            "  WP-Nuclei-Rule-Factory — Run Summary",
            "=" * 60,
            f"  Total rules processed:  {total}",
            f"  ✓ Verified:             {self._counts['verified']}",
            f"  ✗ Rejected:             {self._counts['rejected']}",
            f"  ⚠ Failed (errors):      {self._counts['failed']}",
            "=" * 60,
        ]

        # Per-rule details
        if self._rules:
            lines.append("")
            lines.append("Per-rule results:")
            lines.append("-" * 60)
            for rule_id, (status, msg) in sorted(self._rules.items()):
                symbol = {"verified": "✓", "rejected": "✗", "failed": "⚠"}.get(status, "?")
                lines.append(f"  {symbol} [{status.upper():8s}] {rule_id}  |  {msg}")

        lines.append("")
        lines.append(f"  Log file: {self._log_path}")
        lines.append("=" * 60 + "\n")

        summary_text = "\n".join(lines)

        try:
            print("\n" + summary_text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(
                ("\n" + summary_text + "\n").encode("utf-8", "replace")
            )
            sys.stdout.buffer.flush()

        # Save to file
        with open(self._summary_path, "w", encoding="utf-8") as fh:
            fh.write(summary_text)

    # ── Cleanup ─────────────────────────────────────────────────
    def close(self) -> None:
        """Close the log file handle."""
        try:
            self._log_fh.close()
        except Exception:
            pass
