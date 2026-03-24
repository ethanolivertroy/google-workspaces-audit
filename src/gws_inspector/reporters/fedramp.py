"""FedRAMP compliance report generator."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_NIST_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "IA": "Identification and Authentication",
    "AU": "Audit and Accountability",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "AT": "Awareness and Training",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "CA": "Security Assessment and Authorization",
}


def _control_family(control_id: str) -> str:
    """Extract the NIST family prefix from a control ID like AC-2, IA-5(1)."""
    parts = control_id.split("-")
    if parts:
        prefix = parts[0].upper()
        return prefix
    return "XX"


@register_reporter
class FedRAMPReportGenerator(ReportGenerator):
    """Generate a FedRAMP compliance report mapped to NIST 800-53."""

    name = "fedramp_report"
    display_name = "FedRAMP Compliance Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        fedramp_findings = [f for f in findings if f.framework == "FedRAMP"]

        # Group by NIST control family
        by_family: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in fedramp_findings:
            family = _control_family(f.control_id)
            by_family[family].append(f)

        total = len(fedramp_findings)
        passed = sum(1 for f in fedramp_findings if f.status == "pass")
        failed = sum(1 for f in fedramp_findings if f.status == "fail")
        manual = sum(1 for f in fedramp_findings if f.status == "manual")

        lines: list[str] = []
        _a = lines.append

        _a("# FedRAMP Compliance Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a(f"**Baseline:** FedRAMP Moderate (NIST SP 800-53 Rev. 5)")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Count |")
        _a("|--------|-------|")
        _a(f"| Total Controls Assessed | {total} |")
        _a(f"| Passed | {passed} |")
        _a(f"| Failed | {failed} |")
        _a(f"| Manual Review Required | {manual} |")
        if total > 0:
            _a(f"| Pass Rate | {passed * 100 // total}% |")
        _a("")

        # Sort families in canonical order, falling back to alphabetical
        priority_families = ["AC", "IA", "AU", "SC", "SI"]
        sorted_families = sorted(
            by_family.keys(),
            key=lambda fam: (
                priority_families.index(fam) if fam in priority_families else len(priority_families),
                fam,
            ),
        )

        for family in sorted_families:
            family_findings = by_family[family]
            family_name = _NIST_FAMILIES.get(family, "Other Controls")
            family_passed = sum(1 for f in family_findings if f.status == "pass")
            family_failed = sum(1 for f in family_findings if f.status == "fail")
            family_manual = sum(1 for f in family_findings if f.status == "manual")

            _a(f"## {family} - {family_name}")
            _a("")
            _a(f"**Results:** {family_passed} passed | {family_failed} failed | {family_manual} manual")
            _a("")
            _a("| Control | Title | Status | Severity | Details |")
            _a("|---------|-------|--------|----------|---------|")

            for f in sorted(family_findings, key=lambda x: x.control_id):
                status_icon = {"pass": "PASS", "fail": "FAIL", "manual": "MANUAL"}.get(f.status, f.status.upper())
                _a(f"| {f.control_id} | {f.title} | {status_icon} | {f.severity.title()} | {f.comments} |")

            _a("")

        # POA&M section for failures
        failed_findings = [f for f in fedramp_findings if f.status == "fail"]
        if failed_findings:
            _a("## Plan of Action and Milestones (POA&M)")
            _a("")
            _a("The following controls require remediation for FedRAMP authorization:")
            _a("")
            _a("| # | Control | Finding | Severity | Recommended Milestone |")
            _a("|---|---------|---------|----------|----------------------|")
            for i, f in enumerate(failed_findings, 1):
                milestone = {
                    "critical": "30 days",
                    "high": "90 days",
                    "medium": "180 days",
                    "low": "365 days",
                }.get(f.severity, "180 days")
                _a(f"| {i} | {f.control_id} | {f.title} | {f.severity.title()} | {milestone} |")
            _a("")

        _a("## Manual Verification Required")
        _a("")
        manual_findings = [f for f in fedramp_findings if f.status == "manual"]
        if manual_findings:
            _a("The following controls cannot be fully assessed automatically and require")
            _a("manual verification by the assessor:")
            _a("")
            for f in manual_findings:
                _a(f"- **{f.control_id}** - {f.title}: {f.comments}")
        else:
            _a("No manual verification items for this framework.")
        _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "fedramp",
            "fedramp_compliance_report.md",
        )
