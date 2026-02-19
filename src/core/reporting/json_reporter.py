"""JSON report generator for scan results."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.core.reporting.base import BaseReporter, ReportData


class JSONReporter(BaseReporter):
    """Generates JSON reports from scan data.

    Enhanced version with:
    - Full vulnerability details
    - Risk scoring integration
    - Plugin summaries
    - Statistics and distribution
    """

    def __init__(
        self,
        indent: int = 2,
        include_response: bool = True,
        include_evidence: bool = True,
    ):
        """Initialize JSON reporter.

        Args:
            indent: JSON indentation level
            include_response: Whether to include full response text
            include_evidence: Whether to include detection evidence
        """
        super().__init__()
        self.indent = indent
        self.include_response = include_response
        self.include_evidence = include_evidence

    def generate(self, data: ReportData, output_path: str) -> bool:
        """Generate JSON report to file.

        Args:
            data: Report data containing scan results
            output_path: Path to write the JSON report

        Returns:
            True if report was generated successfully
        """
        try:
            content = self.generate_to_string(data)
            Path(output_path).write_text(content, encoding="utf-8")
            return True
        except Exception as e:
            print(f"Error generating JSON report: {e}")
            return False

    def generate_to_string(self, data: ReportData) -> str:
        """Generate JSON report as string.

        Args:
            data: Report data containing scan results

        Returns:
            JSON formatted report string
        """
        report_dict = self._build_report_dict(data)
        return json.dumps(report_dict, indent=self.indent, ensure_ascii=False, default=str)

    def _build_report_dict(self, data: ReportData) -> dict[str, Any]:
        """Build the complete report dictionary."""
        return {
            "scan_id": data.scan_id,
            "success": True,
            "start_time": data.start_time.isoformat(),
            "end_time": data.end_time.isoformat(),
            "duration_seconds": round(data.duration_seconds, 2),
            "duration_human": self._format_duration(data.duration_seconds),
            "config": {
                "target_url": data.target_url,
                "model": data.model,
                "scan_mode": data.scan_mode,
                **data.config,
            },
            "local_llm": data.local_llm,
            "summary": {
                "total_attacks": data.total_attacks,
                "executed_attacks": data.total_attacks,
                "vulnerabilities_found": data.total_vulnerabilities,
                "success_rate": round(data.success_rate, 2),
                "risk_distribution": data.risk_distribution,
                "duration": self._format_duration(data.duration_seconds),
            },
            "plugins": [self._build_plugin_dict(p) for p in data.plugin_summaries],
            "vulnerabilities": [
                self._build_vulnerability_dict(v) for v in data.vulnerabilities
            ],
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "reporter_version": "1.0.0",
                "tool": "DeepLLMScanner",
            },
        }

    def _build_plugin_dict(self, plugin) -> dict[str, Any]:
        """Build plugin summary dictionary."""
        result = plugin.to_dict()
        # Add human-readable success rate
        result["success_rate_percent"] = f"{plugin.success_rate * 100:.1f}%"
        return result

    def _build_vulnerability_dict(self, vuln) -> dict[str, Any]:
        """Build vulnerability record dictionary."""
        result = {
            "id": vuln.id,
            "plugin_id": vuln.plugin_id,
            "category": vuln.category,
            "payload": vuln.payload,
            "confidence": vuln.confidence,
            "confidence_percent": f"{vuln.confidence * 100:.0f}%",
        }

        # Conditionally include response
        if self.include_response:
            result["response"] = vuln.response
        else:
            result["response_preview"] = self._truncate_text(vuln.response, 500)

        # Conditionally include evidence
        if self.include_evidence:
            result["evidence"] = vuln.evidence

        # Include risk scoring if available
        if vuln.risk_score is not None:
            result["risk_score"] = {
                "score": vuln.risk_score,
                "level": vuln.risk_level,
                "priority": vuln.priority,
            }

        # Include validation status if available
        if vuln.validation_passed is not None:
            result["validation"] = {
                "passed": vuln.validation_passed,
                "reproducible": vuln.validation_passed,
            }

        # Include timestamp if available
        if vuln.detected_at:
            result["detected_at"] = vuln.detected_at

        return result


class CompactJSONReporter(JSONReporter):
    """Compact JSON reporter with minimal data."""

    def __init__(self):
        """Initialize compact reporter."""
        super().__init__(indent=None, include_response=False, include_evidence=False)


class FullJSONReporter(JSONReporter):
    """Full JSON reporter with all details."""

    def __init__(self):
        """Initialize full reporter."""
        super().__init__(indent=2, include_response=True, include_evidence=True)
