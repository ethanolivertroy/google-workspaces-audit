"""PCI DSS v4.0 compliance report generator."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_PCI_REQUIREMENTS: dict[str, str] = {
    "7": "Restrict Access to System Components and Cardholder Data by Business Need to Know",
    "7.1": "Processes and mechanisms for restricting access are defined and understood",
    "7.2": "Access to system components and data is appropriately defined and assigned",
    "7.3": "Access to system components and data is managed via an access control system",
    "8": "Identify Users and Authenticate Access to System Components",
    "8.1": "Processes and mechanisms for identifying users and authenticating access are defined",
    "8.2": "User identification and related accounts are strictly managed",
    "8.3": "Strong authentication for users and administrators is established and managed",
    "8.4": "Multi-factor authentication (MFA) is implemented to secure access",
    "8.5": "Multi-factor authentication (MFA) systems are configured to prevent misuse",
    "8.6": "Use of application and system accounts is strictly managed",
}


def _pci_requirement(control_id: str) -> str:
    """Extract top-level PCI requirement from control ID like 8.3.1."""
    parts = control_id.split(".")
    if parts:
        return parts[0]
    return "8"


def _pci_sub_requirement(control_id: str) -> str:
    """Extract sub-requirement like 8.3 from 8.3.1."""
    parts = control_id.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return control_id


@register_reporter
class PCIDSSReportGenerator(ReportGenerator):
    """Generate a PCI DSS v4.0 compliance report (Requirements 7 & 8)."""

    name = "pci_dss_report"
    display_name = "PCI DSS Compliance Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        pci_findings = [f for f in findings if f.framework == "PCI-DSS"]

        status_counts = Counter(f.status for f in pci_findings)
        total = len(pci_findings)
        passed = status_counts.get("pass", 0)
        failed = status_counts.get("fail", 0)
        manual = status_counts.get("manual", 0)

        # Group by sub-requirement
        by_sub_req: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in pci_findings:
            sub = _pci_sub_requirement(f.control_id)
            by_sub_req[sub].append(f)

        lines: list[str] = []
        _a = lines.append

        _a("# PCI DSS v4.0 Compliance Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a("**Scope:** Requirements 7 (Access Control) & 8 (Authentication)")
        _a("**Version:** PCI DSS v4.0")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total Requirements Assessed | {total} |")
        _a(f"| In Place | {passed} |")
        _a(f"| Not In Place | {failed} |")
        _a(f"| Manual Validation Required | {manual} |")
        if total > 0:
            _a(f"| Compliance Rate | {passed * 100 // total}% |")
        _a("")

        _a("## Scope")
        _a("")
        _a("This assessment covers PCI DSS v4.0 Requirements 7 and 8 as they apply")
        _a("to the Google Workspace identity and access management configuration.")
        _a("These requirements address access control and authentication, which are")
        _a("directly assessable through Google Workspace administrative settings.")
        _a("")

        # Detailed assessment grouped by requirement
        for req_num in ("7", "8"):
            req_name = _PCI_REQUIREMENTS.get(req_num, "")
            req_findings = [f for f in pci_findings if _pci_requirement(f.control_id) == req_num]

            if not req_findings:
                continue

            req_passed = sum(1 for f in req_findings if f.status == "pass")
            _a(f"## Requirement {req_num}: {req_name}")
            _a("")
            _a(f"**Overall:** {req_passed}/{len(req_findings)} in place")
            _a("")

            # Group by sub-requirement within this requirement
            sub_reqs: dict[str, list[ComplianceFinding]] = defaultdict(list)
            for f in req_findings:
                sub = _pci_sub_requirement(f.control_id)
                sub_reqs[sub].append(f)

            for sub in sorted(sub_reqs.keys()):
                sub_findings = sub_reqs[sub]
                sub_name = _PCI_REQUIREMENTS.get(sub, "")
                sub_title = f"### {sub}" + (f" - {sub_name}" if sub_name else "")
                _a(sub_title)
                _a("")
                _a("| Requirement | Title | Status | Severity | Details |")
                _a("|-------------|-------|--------|----------|---------|")

                for f in sorted(sub_findings, key=lambda x: x.control_id):
                    status_label = {
                        "pass": "In Place",
                        "fail": "Not In Place",
                        "manual": "Validate",
                    }.get(f.status, f.status.title())
                    _a(f"| {f.control_id} | {f.title} | {status_label} | {f.severity.title()} | {f.comments} |")
                _a("")

        # Gap analysis
        failed_findings = [f for f in pci_findings if f.status == "fail"]
        if failed_findings:
            _a("## Gap Analysis")
            _a("")
            _a("The following requirements are **Not In Place** and represent compliance gaps:")
            _a("")
            _a("| # | Requirement | Gap Description | Severity | Risk |")
            _a("|---|-------------|-----------------|----------|------|")
            for i, f in enumerate(failed_findings, 1):
                risk = {
                    "critical": "Immediate remediation required",
                    "high": "High risk - remediate before next assessment",
                    "medium": "Moderate risk - plan remediation",
                    "low": "Low risk - address as part of continuous improvement",
                }.get(f.severity, "Assess risk")
                _a(f"| {i} | {f.control_id} | {f.title} | {f.severity.title()} | {risk} |")
            _a("")

        # Remediation plan
        if failed_findings:
            _a("## Remediation Plan")
            _a("")
            _a("| Priority | Requirement | Remediation Action | Target Date | Owner |")
            _a("|----------|-------------|-------------------|-------------|-------|")
            for i, f in enumerate(failed_findings, 1):
                priority = {
                    "critical": "P1 - Immediate",
                    "high": "P2 - Urgent",
                    "medium": "P3 - Planned",
                    "low": "P4 - Scheduled",
                }.get(f.severity, "P3")
                _a(f"| {priority} | {f.control_id} | {f.comments} | _[TBD]_ | _[TBD]_ |")
            _a("")
            _a("> All gaps must be remediated before the next PCI DSS assessment.")
            _a("> Compensating controls may be documented if direct compliance is not feasible.")
            _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "pci_dss",
            "pci_dss_compliance_report.md",
        )
