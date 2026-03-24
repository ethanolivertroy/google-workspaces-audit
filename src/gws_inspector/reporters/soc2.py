"""SOC 2 Type II compliance report generator."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_TSC_CATEGORIES: dict[str, str] = {
    "CC6": "Logical and Physical Access Controls",
    "CC7": "System Operations",
    "CC1": "Control Environment",
    "CC2": "Communication and Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}


def _tsc_category(control_id: str) -> str:
    """Extract TSC category from control ID like CC6.1, CC7.2."""
    for prefix in sorted(_TSC_CATEGORIES.keys(), key=len, reverse=True):
        if control_id.upper().startswith(prefix):
            return prefix
    return "CC6"


@register_reporter
class SOC2ReportGenerator(ReportGenerator):
    """Generate a SOC 2 Type II compliance report (CC6/CC7 focus)."""

    name = "soc2_report"
    display_name = "SOC 2 Compliance Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        soc2_findings = [f for f in findings if f.framework == "SOC2"]

        status_counts = Counter(f.status for f in soc2_findings)
        total = len(soc2_findings)
        passed = status_counts.get("pass", 0)
        failed = status_counts.get("fail", 0)
        manual = status_counts.get("manual", 0)

        # Group by TSC category
        by_category: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in soc2_findings:
            cat = _tsc_category(f.control_id)
            by_category[cat].append(f)

        lines: list[str] = []
        _a = lines.append

        _a("# SOC 2 Type II Compliance Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a(f"**Trust Services Criteria:** Security (Common Criteria)")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total Criteria Assessed | {total} |")
        _a(f"| Controls Operating Effectively | {passed} |")
        _a(f"| Exceptions Noted | {failed} |")
        _a(f"| Manual Testing Required | {manual} |")
        _a("")

        # Overall assessment
        _a("## Overall Assessment")
        _a("")
        if failed == 0:
            _a("Based on automated testing, no exceptions were noted for the assessed criteria.")
            _a("Controls appear to be suitably designed and operating effectively for the")
            _a("Google Workspace environment.")
        elif failed <= 3:
            _a("Minor exceptions were noted. The overall control environment is adequate")
            _a("with specific areas requiring remediation before the audit period.")
        else:
            _a("Multiple exceptions were identified. Significant remediation is required")
            _a("to achieve a clean SOC 2 Type II opinion.")
        _a("")

        # Detailed assessment by category (focus on CC6 and CC7)
        category_order = ["CC6", "CC7", "CC1", "CC2", "CC3", "CC4", "CC5", "CC8", "CC9"]
        for cat in category_order:
            cat_findings = by_category.get(cat)
            if not cat_findings:
                continue
            cat_name = _TSC_CATEGORIES.get(cat, "Other")
            cat_passed = sum(1 for f in cat_findings if f.status == "pass")
            cat_failed = sum(1 for f in cat_findings if f.status == "fail")

            _a(f"## {cat} - {cat_name}")
            _a("")
            _a(f"**Results:** {cat_passed} effective | {cat_failed} exceptions | {len(cat_findings)} total")
            _a("")

            _a("| Criterion | Title | Status | Severity | Observation |")
            _a("|-----------|-------|--------|----------|-------------|")
            for f in sorted(cat_findings, key=lambda x: x.control_id):
                status_label = {
                    "pass": "Effective",
                    "fail": "Exception",
                    "manual": "Manual Test",
                }.get(f.status, f.status.title())
                _a(f"| {f.control_id} | {f.title} | {status_label} | {f.severity.title()} | {f.comments} |")
            _a("")

            # Strengths and areas for improvement per category
            strengths = [f for f in cat_findings if f.status == "pass"]
            weaknesses = [f for f in cat_findings if f.status == "fail"]

            if strengths:
                _a(f"### {cat} Strengths")
                _a("")
                for f in strengths:
                    _a(f"- {f.title}: {f.comments}")
                _a("")

            if weaknesses:
                _a(f"### {cat} Areas for Improvement")
                _a("")
                for f in weaknesses:
                    _a(f"- **{f.title}**: {f.comments}")
                _a("")

        # Management response section
        failed_findings = [f for f in soc2_findings if f.status == "fail"]
        if failed_findings:
            _a("## Management Response Required")
            _a("")
            _a("The following exceptions require management response and remediation plan:")
            _a("")
            for i, f in enumerate(failed_findings, 1):
                _a(f"### Exception {i}: {f.title}")
                _a("")
                _a(f"- **Criterion:** {f.control_id}")
                _a(f"- **Severity:** {f.severity.title()}")
                _a(f"- **Observation:** {f.comments}")
                _a(f"- **Management Response:** _[To be completed]_")
                _a(f"- **Remediation Timeline:** _[To be completed]_")
                _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "soc2",
            "soc2_compliance_report.md",
        )
