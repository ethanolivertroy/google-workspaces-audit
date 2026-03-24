"""ISMAP (Japan) compliance report generator."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_ISO27001_SECTIONS: dict[str, str] = {
    "A.5": "Information Security Policies",
    "A.6": "Organisation of Information Security",
    "A.7": "Human Resource Security",
    "A.8": "Asset Management",
    "A.9": "Access Control",
    "A.10": "Cryptography",
    "A.11": "Physical and Environmental Security",
    "A.12": "Operations Security",
    "A.13": "Communications Security",
    "A.14": "System Acquisition, Development and Maintenance",
    "A.15": "Supplier Relationships",
    "A.16": "Information Security Incident Management",
    "A.17": "Business Continuity Management",
    "A.18": "Compliance",
}


def _iso_section(control_id: str) -> str:
    """Extract ISO 27001 Annex A section from control ID like A.9.2.1."""
    parts = control_id.split(".")
    if len(parts) >= 2 and parts[0].upper() == "A":
        return f"A.{parts[1]}"
    return "A.9"


@register_reporter
class ISMAPReportGenerator(ReportGenerator):
    """Generate an ISMAP compliance report based on ISO 27001 controls."""

    name = "ismap_report"
    display_name = "ISMAP Compliance Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        ismap_findings = [f for f in findings if f.framework == "ISMAP"]

        status_counts = Counter(f.status for f in ismap_findings)
        total = len(ismap_findings)
        passed = status_counts.get("pass", 0)
        failed = status_counts.get("fail", 0)
        manual = status_counts.get("manual", 0)

        # Group by ISO 27001 section
        by_section: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in ismap_findings:
            section = _iso_section(f.control_id)
            by_section[section].append(f)

        lines: list[str] = []
        _a = lines.append

        _a("# ISMAP Compliance Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a("**Framework:** Information System Security Management and Assessment Program (ISMAP)")
        _a("**Reference Standard:** ISO/IEC 27001:2022 / JIS Q 27001")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total Controls Assessed | {total} |")
        _a(f"| Conforming | {passed} |")
        _a(f"| Non-conforming | {failed} |")
        _a(f"| Manual Assessment Required | {manual} |")
        if total > 0:
            _a(f"| Conformance Rate | {passed * 100 // total}% |")
        _a("")

        _a("## Overview")
        _a("")
        _a("ISMAP (Information System Security Management and Assessment Program) is the")
        _a("Japanese government's cloud security evaluation framework. It incorporates")
        _a("ISO/IEC 27001, 27002, and 27017 requirements with additional government-specific")
        _a("controls. This report assesses the Google Workspace configuration against")
        _a("applicable ISMAP controls.")
        _a("")

        _a("## ISO 27001 Control Assessment")
        _a("")

        for section in sorted(by_section.keys()):
            section_findings = by_section[section]
            section_name = _ISO27001_SECTIONS.get(section, "Other Controls")
            section_passed = sum(1 for f in section_findings if f.status == "pass")

            _a(f"### {section} - {section_name}")
            _a("")
            _a(f"**Results:** {section_passed}/{len(section_findings)} controls conforming")
            _a("")
            _a("| Control | Title | Status | Severity | Observation |")
            _a("|---------|-------|--------|----------|-------------|")

            for f in sorted(section_findings, key=lambda x: x.control_id):
                status_label = {
                    "pass": "Conforming",
                    "fail": "Non-conforming",
                    "manual": "Requires Review",
                }.get(f.status, f.status.title())
                _a(f"| {f.control_id} | {f.title} | {status_label} | {f.severity.title()} | {f.comments} |")
            _a("")

        # Non-conformities
        failed_findings = [f for f in ismap_findings if f.status == "fail"]
        if failed_findings:
            _a("## Non-conformities")
            _a("")
            _a("The following controls require corrective action:")
            _a("")
            _a("| # | Control | Finding | Severity | Corrective Action |")
            _a("|---|---------|---------|----------|-------------------|")
            for i, f in enumerate(failed_findings, 1):
                _a(f"| {i} | {f.control_id} | {f.title} | {f.severity.title()} | _[To be documented]_ |")
            _a("")

        # Manual review items
        manual_findings = [f for f in ismap_findings if f.status == "manual"]
        if manual_findings:
            _a("## Manual Assessment Items")
            _a("")
            _a("The following controls require manual assessment by the ISMAP assessor:")
            _a("")
            for f in manual_findings:
                _a(f"- **{f.control_id}** - {f.title}: {f.comments}")
            _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "ismap",
            "ismap_compliance_report.md",
        )
