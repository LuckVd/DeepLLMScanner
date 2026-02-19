"""HTML report generator for scan results."""

import base64
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.core.reporting.base import BaseReporter, ReportData


class HTMLReporter(BaseReporter):
    """Generates HTML reports from scan data.

    Features:
    - Visual dashboard with charts
    - Sortable/filterable vulnerability table
    - Risk distribution visualization
    - Collapsible vulnerability details
    - Print-friendly styling
    """

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize HTML reporter.

        Args:
            template_dir: Directory containing templates
        """
        super().__init__(template_dir)
        self._template_cache: Optional[str] = None

    def generate(self, data: ReportData, output_path: str) -> bool:
        """Generate HTML report to file.

        Args:
            data: Report data containing scan results
            output_path: Path to write the HTML report

        Returns:
            True if report was generated successfully
        """
        try:
            content = self.generate_to_string(data)
            Path(output_path).write_text(content, encoding="utf-8")
            return True
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return False

    def generate_to_string(self, data: ReportData) -> str:
        """Generate HTML report as string.

        Args:
            data: Report data containing scan results

        Returns:
            HTML formatted report string
        """
        template = self._get_template()
        return self._render_template(template, data)

    def _get_template(self) -> str:
        """Get HTML template content."""
        if self._template_cache:
            return self._template_cache

        # Try to load from file
        if self.template_dir:
            template_path = Path(self.template_dir) / "report.html"
            if template_path.exists():
                self._template_cache = template_path.read_text(encoding="utf-8")
                return self._template_cache

        # Use embedded template
        self._template_cache = self._get_embedded_template()
        return self._template_cache

    def _get_embedded_template(self) -> str:
        """Get embedded HTML template."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeepLLMScanner Report - {{scan_id}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 24px;
        }
        .header h1 { font-size: 28px; margin-bottom: 8px; }
        .header .subtitle { opacity: 0.8; font-size: 14px; }
        .header .meta { display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }
        .header .meta-item { display: flex; align-items: center; gap: 8px; }
        .header .meta-label { opacity: 0.7; font-size: 12px; }

        /* Dashboard Cards */
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .card-title { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .card-value { font-size: 32px; font-weight: 700; }
        .card-value.critical { color: #dc2626; }
        .card-value.high { color: #ea580c; }
        .card-value.medium { color: #ca8a04; }
        .card-value.low { color: #16a34a; }
        .card-value.success { color: #16a34a; }

        /* Risk Distribution */
        .risk-chart { display: flex; gap: 8px; margin-top: 12px; }
        .risk-bar { height: 8px; border-radius: 4px; transition: width 0.3s; }
        .risk-bar.critical { background: #dc2626; }
        .risk-bar.high { background: #ea580c; }
        .risk-bar.medium { background: #ca8a04; }
        .risk-bar.low { background: #16a34a; }

        /* Plugins Section */
        .section { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .section-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .plugin-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
        .plugin-card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; }
        .plugin-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        .plugin-name { font-weight: 600; }
        .plugin-badge { font-size: 12px; padding: 2px 8px; border-radius: 12px; background: #f3f4f6; }
        .plugin-badge.has-vulns { background: #fef3c7; color: #92400e; }
        .plugin-stats { display: flex; gap: 16px; font-size: 13px; color: #666; }

        /* Vulnerabilities Table */
        .vuln-table { width: 100%; border-collapse: collapse; }
        .vuln-table th, .vuln-table td { text-align: left; padding: 12px 16px; border-bottom: 1px solid #e5e7eb; }
        .vuln-table th { font-size: 12px; text-transform: uppercase; color: #666; background: #f9fafb; }
        .vuln-table tr:hover { background: #f9fafb; }
        .vuln-payload { font-family: monospace; font-size: 13px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .confidence-bar { width: 60px; height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; }
        .confidence-fill { height: 100%; border-radius: 3px; }
        .risk-badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 500; }
        .risk-badge.critical { background: #fef2f2; color: #dc2626; }
        .risk-badge.high { background: #fff7ed; color: #ea580c; }
        .risk-badge.medium { background: #fefce8; color: #ca8a04; }
        .risk-badge.low { background: #f0fdf4; color: #16a34a; }

        /* Vulnerability Detail */
        .vuln-detail { display: none; background: #f9fafb; padding: 16px; }
        .vuln-detail.show { display: block; }
        .detail-section { margin-bottom: 12px; }
        .detail-label { font-size: 12px; color: #666; margin-bottom: 4px; }
        .detail-content { font-family: monospace; font-size: 12px; background: white; padding: 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow: auto; }
        .evidence-list { list-style: none; }
        .evidence-list li { padding: 4px 0; font-size: 13px; }

        /* Expand Button */
        .expand-btn { background: none; border: none; color: #2563eb; cursor: pointer; font-size: 13px; }
        .expand-btn:hover { text-decoration: underline; }

        /* Empty State */
        .empty-state { text-align: center; padding: 48px; color: #666; }
        .empty-icon { font-size: 48px; margin-bottom: 16px; }

        /* Print Styles */
        @media print {
            body { background: white; }
            .card, .section { box-shadow: none; border: 1px solid #ddd; }
            .expand-btn { display: none; }
            .vuln-detail { display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>DeepLLMScanner Report</h1>
            <div class="subtitle">Security scan results for {{target_url}}</div>
            <div class="meta">
                <div class="meta-item">
                    <span class="meta-label">Scan ID</span>
                    <span>{{scan_id}}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Model</span>
                    <span>{{model}}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Mode</span>
                    <span>{{scan_mode}}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Duration</span>
                    <span>{{duration}}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Generated</span>
                    <span>{{generated_at}}</span>
                </div>
            </div>
        </div>

        <!-- Dashboard -->
        <div class="dashboard">
            <div class="card">
                <div class="card-title">Total Attacks</div>
                <div class="card-value">{{total_attacks}}</div>
            </div>
            <div class="card">
                <div class="card-title">Vulnerabilities</div>
                <div class="card-value {{vuln_class}}">{{vulnerabilities_found}}</div>
            </div>
            <div class="card">
                <div class="card-title">Success Rate</div>
                <div class="card-value">{{success_rate}}%</div>
            </div>
            <div class="card">
                <div class="card-title">Risk Distribution</div>
                <div class="risk-chart">
                    <div class="risk-bar critical" style="width: {{critical_pct}}%"></div>
                    <div class="risk-bar high" style="width: {{high_pct}}%"></div>
                    <div class="risk-bar medium" style="width: {{medium_pct}}%"></div>
                    <div class="risk-bar low" style="width: {{low_pct}}%"></div>
                </div>
            </div>
        </div>

        <!-- Plugins Section -->
        <div class="section">
            <h2 class="section-title">Plugin Results</h2>
            <div class="plugin-grid">
                {{plugin_cards}}
            </div>
        </div>

        <!-- Vulnerabilities Section -->
        <div class="section">
            <h2 class="section-title">Vulnerabilities Found ({{vulnerabilities_found}})</h2>
            {{vuln_table}}
        </div>
    </div>

    <script>
        function toggleDetail(id) {
            const detail = document.getElementById('detail-' + id);
            if (detail) {
                detail.classList.toggle('show');
            }
        }
    </script>
</body>
</html>'''

    def _render_template(self, template: str, data: ReportData) -> str:
        """Render template with data."""
        # Calculate percentages for risk distribution
        total = max(data.total_vulnerabilities, 1)
        dist = data.risk_distribution

        # Prepare template variables
        variables = {
            "scan_id": data.scan_id,
            "target_url": data.target_url,
            "model": data.model,
            "scan_mode": data.scan_mode,
            "duration": self._format_duration(data.duration_seconds),
            "generated_at": self._format_timestamp(datetime.now()),
            "total_attacks": data.total_attacks,
            "vulnerabilities_found": data.total_vulnerabilities,
            "success_rate": f"{data.success_rate * 100:.1f}",
            "vuln_class": self._get_vuln_class(data.total_vulnerabilities),
            "critical_pct": (dist["critical"] / total) * 100,
            "high_pct": (dist["high"] / total) * 100,
            "medium_pct": (dist["medium"] / total) * 100,
            "low_pct": (dist["low"] / total) * 100,
            "plugin_cards": self._render_plugin_cards(data),
            "vuln_table": self._render_vuln_table(data),
        }

        # Simple template substitution
        result = template
        for key, value in variables.items():
            result = result.replace("{{" + key + "}}", str(value))

        return result

    def _get_vuln_class(self, count: int) -> str:
        """Get CSS class based on vulnerability count."""
        if count == 0:
            return "success"
        elif count <= 2:
            return "low"
        elif count <= 5:
            return "medium"
        elif count <= 10:
            return "high"
        else:
            return "critical"

    def _render_plugin_cards(self, data: ReportData) -> str:
        """Render plugin summary cards."""
        if not data.plugin_summaries:
            return '<div class="empty-state"><p>No plugins executed</p></div>'

        cards = []
        for plugin in data.plugin_summaries:
            has_vulns = plugin.vulnerabilities_found > 0
            badge_class = "has-vulns" if has_vulns else ""

            card = f'''<div class="plugin-card">
                <div class="plugin-header">
                    <span class="plugin-name">{plugin.plugin_id}</span>
                    <span class="plugin-badge {badge_class}">{plugin.vulnerabilities_found} vulns</span>
                </div>
                <div class="plugin-stats">
                    <span>Attacks: {plugin.total_attacks}</span>
                    <span>Rate: {plugin.success_rate * 100:.1f}%</span>
                </div>
            </div>'''
            cards.append(card)

        return "\n".join(cards)

    def _render_vuln_table(self, data: ReportData) -> str:
        """Render vulnerabilities table."""
        if not data.vulnerabilities:
            return '''<div class="empty-state">
                <div class="empty-icon">✓</div>
                <p>No vulnerabilities found</p>
            </div>'''

        rows = []
        for i, vuln in enumerate(data.vulnerabilities):
            risk_level = vuln.risk_level or "info"
            confidence_pct = int(vuln.confidence * 100)
            confidence_color = self._get_confidence_color(vuln.confidence)

            row = f'''<tr>
                <td><span class="risk-badge {risk_level}">{risk_level.upper()}</span></td>
                <td>{vuln.plugin_id}</td>
                <td class="vuln-payload" title="{self._escape_html(vuln.payload)}">{self._truncate_text(vuln.payload, 50)}</td>
                <td>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {confidence_pct}%; background: {confidence_color}"></div>
                    </div>
                </td>
                <td>{vuln.confidence * 100:.0f}%</td>
                <td>
                    <button class="expand-btn" onclick="toggleDetail('{i}')">Details</button>
                </td>
            </tr>
            <tr>
                <td colspan="6" class="vuln-detail" id="detail-{i}">
                    {self._render_vuln_detail(vuln)}
                </td>
            </tr>'''
            rows.append(row)

        header = '''<table class="vuln-table">
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Plugin</th>
                    <th>Payload</th>
                    <th colspan="2">Confidence</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>'''

        footer = "</tbody></table>"

        return header + "\n".join(rows) + footer

    def _render_vuln_detail(self, vuln) -> str:
        """Render vulnerability detail section."""
        sections = []

        # Response
        sections.append(f'''<div class="detail-section">
            <div class="detail-label">Response</div>
            <div class="detail-content">{self._escape_html(vuln.response[:2000])}</div>
        </div>''')

        # Evidence
        if vuln.evidence:
            evidence_items = []
            for key, value in vuln.evidence.items():
                if value and (isinstance(value, list) and len(value) > 0 or not isinstance(value, list)):
                    evidence_items.append(f"<li><strong>{key}:</strong> {self._escape_html(str(value)[:500])}</li>")

            if evidence_items:
                sections.append(f'''<div class="detail-section">
                    <div class="detail-label">Evidence</div>
                    <ul class="evidence-list">{"".join(evidence_items)}</ul>
                </div>''')

        # Risk Score
        if vuln.risk_score is not None:
            sections.append(f'''<div class="detail-section">
                <div class="detail-label">Risk Score</div>
                <div class="detail-content">Score: {vuln.risk_score:.2f} | Level: {vuln.risk_level} | Priority: {vuln.priority}</div>
            </div>''')

        return "\n".join(sections)

    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level."""
        if confidence >= 0.9:
            return "#dc2626"  # Red - high confidence vulnerability
        elif confidence >= 0.7:
            return "#ea580c"  # Orange
        elif confidence >= 0.5:
            return "#ca8a04"  # Yellow
        else:
            return "#16a34a"  # Green - low confidence

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
