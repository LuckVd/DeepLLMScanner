"""Reporting module for DeepLLMScanner scan results."""

from src.core.reporting.base import BaseReporter, ReportData, VulnerabilityRecord, PluginSummary
from src.core.reporting.json_reporter import JSONReporter
from src.core.reporting.html_reporter import HTMLReporter

__all__ = [
    "BaseReporter",
    "ReportData",
    "VulnerabilityRecord",
    "PluginSummary",
    "JSONReporter",
    "HTMLReporter",
]
