"""CIS Google Workspace Benchmark report generator."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_CIS_SECTIONS: dict[str, str] = {
    "1": "Directory Settings",
    "2": "Gmail Settings",
    "3": "Google Drive and Docs",
    "4": "Google Calendar",
    "5": "Google Groups",
    "6": "Mobile Management",
    "7": "Google Sites",
    "8": "Security and Admin Settings",
}


def _cis_section(control_id: str) -> str:
    """Extract section number from CIS recommendation ID like 1.1.1, 2.3.4."""
    parts = control_id.split(".")
    if parts:
        return parts[0]
    return "1"


@register_reporter
class CISReportGenerator(ReportGenerator):
    """Generate a CIS Google Workspace Foundations Benchmark report."""

    name = "cis_report"
    display_name = "CIS Benchmark Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        cis_findings = [f for f in findings if f.framework == "CIS"]

        status_counts = Counter(f.status for f in cis_findings)
        total = len(cis_findings)
        passed = status_counts.get("pass", 0)
        failed = status_counts.get("fail", 0)
        manual = status_counts.get("manual", 0)

        # Overall CIS score: pass / (pass + fail) as percentage (excludes manual/N/A)
        scoreable = passed + failed
        cis_score = (passed * 100 // scoreable) if scoreable > 0 else 0

        # Group by section
        by_section: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in cis_findings:
            section = _cis_section(f.control_id)
            by_section[section].append(f)

        lines: list[str] = []
        _a = lines.append

        _a("# CIS Google Workspace Foundations Benchmark Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a("**Benchmark:** CIS Google Workspace Foundations Benchmark v1.0+")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total Recommendations Assessed | {total} |")
        _a(f"| Pass | {passed} |")
        _a(f"| Fail | {failed} |")
        _a(f"| Manual Review Required | {manual} |")
        _a(f"| **CIS Score** | **{cis_score}%** ({passed}/{scoreable} scored) |")
        _a("")

        _a("## Score Breakdown")
        _a("")
        if cis_score >= 90:
            _a(f"**CIS Score: {cis_score}%** - Excellent compliance posture.")
        elif cis_score >= 70:
            _a(f"**CIS Score: {cis_score}%** - Good compliance with some gaps to address.")
        elif cis_score >= 50:
            _a(f"**CIS Score: {cis_score}%** - Moderate compliance. Significant improvements needed.")
        else:
            _a(f"**CIS Score: {cis_score}%** - Below baseline. Immediate attention required.")
        _a("")

        # Section summary table
        _a("### Score by Section")
        _a("")
        _a("| Section | Description | Pass | Fail | Manual | Score |")
        _a("|---------|-------------|------|------|--------|-------|")
        for sec_num in sorted(by_section.keys(), key=lambda x: int(x) if x.isdigit() else 99):
            sec_findings = by_section[sec_num]
            sec_name = _CIS_SECTIONS.get(sec_num, "Other")
            sec_passed = sum(1 for f in sec_findings if f.status == "pass")
            sec_failed = sum(1 for f in sec_findings if f.status == "fail")
            sec_manual = sum(1 for f in sec_findings if f.status == "manual")
            sec_scoreable = sec_passed + sec_failed
            sec_score = f"{sec_passed * 100 // sec_scoreable}%" if sec_scoreable > 0 else "N/A"
            _a(f"| {sec_num} | {sec_name} | {sec_passed} | {sec_failed} | {sec_manual} | {sec_score} |")
        _a("")

        # Detailed sections 1-8
        for sec_num in sorted(by_section.keys(), key=lambda x: int(x) if x.isdigit() else 99):
            sec_findings = by_section[sec_num]
            sec_name = _CIS_SECTIONS.get(sec_num, "Other")

            _a(f"## Section {sec_num}: {sec_name}")
            _a("")
            _a("| Recommendation | Title | Scored | Status | Severity | Details |")
            _a("|----------------|-------|--------|--------|----------|---------|")

            for f in sorted(sec_findings, key=lambda x: x.control_id):
                scored = "Scored" if f.status in ("pass", "fail") else "Not Scored"
                status_label = {
                    "pass": "PASS",
                    "fail": "FAIL",
                    "manual": "MANUAL",
                    "not_applicable": "N/A",
                }.get(f.status, f.status.upper())
                _a(
                    f"| {f.control_id} | {f.title} | {scored} "
                    f"| {status_label} | {f.severity.title()} | {f.comments} |"
                )
            _a("")

        # Failed recommendations detail
        failed_findings = [f for f in cis_findings if f.status == "fail"]
        if failed_findings:
            _a("## Failed Recommendations")
            _a("")
            _a("The following CIS recommendations are not met and should be remediated:")
            _a("")
            for f in sorted(failed_findings, key=lambda x: x.control_id):
                sec = _cis_section(f.control_id)
                sec_name = _CIS_SECTIONS.get(sec, "")
                _a(f"### {f.control_id} - {f.title}")
                _a("")
                _a(f"- **Section:** {sec} - {sec_name}")
                _a(f"- **Severity:** {f.severity.title()}")
                _a(f"- **Current State:** {f.comments}")
                _a(f"- **Remediation:** _[Review CIS Benchmark for detailed remediation steps]_")
                _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "cis",
            "cis_benchmark_report.md",
        )
