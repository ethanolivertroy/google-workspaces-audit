"""DISA STIG compliance checklist report generator."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_STATUS_MAP = {
    "pass": "Not a Finding",
    "fail": "Open",
    "manual": "Not Reviewed",
    "not_applicable": "Not Applicable",
    "error": "Not Reviewed",
}

_SEVERITY_CAT = {
    "critical": "CAT I",
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
    "info": "CAT III",
}


@register_reporter
class STIGReportGenerator(ReportGenerator):
    """Generate a DISA STIG compliance checklist."""

    name = "stig_report"
    display_name = "DISA STIG Compliance Checklist"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        stig_findings = [f for f in findings if f.framework == "DISA STIG"]

        status_counts = Counter(f.status for f in stig_findings)
        total = len(stig_findings)
        not_a_finding = status_counts.get("pass", 0)
        stig_open = status_counts.get("fail", 0)
        not_reviewed = status_counts.get("manual", 0) + status_counts.get("error", 0)
        not_applicable = status_counts.get("not_applicable", 0)

        # Separate automated vs manual findings
        automated = [f for f in stig_findings if f.status != "manual"]
        manual = [f for f in stig_findings if f.status == "manual"]

        # CAT breakdown
        cat_counts: Counter[str] = Counter()
        for f in stig_findings:
            if f.status == "fail":
                cat_counts[_SEVERITY_CAT.get(f.severity, "CAT II")] += 1

        lines: list[str] = []
        _a = lines.append

        _a("# DISA STIG Compliance Checklist")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a(f"**STIG:** Google Workspace Security Technical Implementation Guide")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Status | Count |")
        _a("|--------|-------|")
        _a(f"| Not a Finding | {not_a_finding} |")
        _a(f"| Open | {stig_open} |")
        _a(f"| Not Reviewed | {not_reviewed} |")
        _a(f"| Not Applicable | {not_applicable} |")
        _a(f"| **Total** | **{total}** |")
        _a("")

        if cat_counts:
            _a("### Open Findings by Category")
            _a("")
            _a("| Category | Count | Description |")
            _a("|----------|-------|-------------|")
            for cat in ("CAT I", "CAT II", "CAT III"):
                desc = {
                    "CAT I": "High severity - must be resolved immediately",
                    "CAT II": "Medium severity - should be resolved promptly",
                    "CAT III": "Low severity - should be resolved as resources allow",
                }.get(cat, "")
                _a(f"| {cat} | {cat_counts.get(cat, 0)} | {desc} |")
            _a("")

        _a("## Automated Assessment Results")
        _a("")
        if automated:
            _a("| V-ID | Title | Category | Status | Finding Details |")
            _a("|------|-------|----------|--------|-----------------|")
            for f in sorted(automated, key=lambda x: x.control_id):
                cat = _SEVERITY_CAT.get(f.severity, "CAT II")
                status = _STATUS_MAP.get(f.status, "Not Reviewed")
                _a(f"| {f.control_id} | {f.title} | {cat} | {status} | {f.comments} |")
            _a("")
        else:
            _a("No automated STIG checks were performed.")
            _a("")

        _a("## Manual Verification Required")
        _a("")
        if manual:
            _a("The following STIG checks require manual verification by the ISSM/ISSO:")
            _a("")
            _a("| V-ID | Title | Category | Check Procedure |")
            _a("|------|-------|----------|-----------------|")
            for f in sorted(manual, key=lambda x: x.control_id):
                cat = _SEVERITY_CAT.get(f.severity, "CAT II")
                _a(f"| {f.control_id} | {f.title} | {cat} | {f.comments} |")
            _a("")
        else:
            _a("No manual verification items identified.")
            _a("")

        # Remediation actions for open findings
        open_findings = [f for f in stig_findings if f.status == "fail"]
        if open_findings:
            _a("## Remediation Actions")
            _a("")
            _a("The following open findings require remediation:")
            _a("")
            for i, f in enumerate(open_findings, 1):
                cat = _SEVERITY_CAT.get(f.severity, "CAT II")
                _a(f"### {i}. {f.control_id} ({cat})")
                _a("")
                _a(f"**Finding:** {f.title}")
                _a(f"**Details:** {f.comments}")
                _a(f"**Fix Action:** _[To be documented by ISSO]_")
                _a("")

        _a("---")
        _a("")
        _a("**ISSM/ISSO Signature:** _________________________ **Date:** _______________")
        _a("")
        _a(f"*Checklist generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "disa_stig",
            "stig_compliance_checklist.md",
        )
