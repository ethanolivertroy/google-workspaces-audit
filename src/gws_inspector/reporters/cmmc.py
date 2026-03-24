"""CMMC Level 2 compliance report generator."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator

_CMMC_DOMAINS: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Security Assessment",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical Protection",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "RE": "Recovery",
    "RM": "Risk Management",
    "SA": "Situational Awareness",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Points deducted per severity for SPRS estimate
_SEVERITY_DEDUCTION = {
    "critical": 5,
    "high": 3,
    "medium": 1,
    "low": 1,
    "info": 0,
}


def _practice_domain(control_id: str) -> str:
    """Extract CMMC domain prefix from a practice ID like AC.L2-3.1.1."""
    parts = control_id.split(".")
    if parts:
        return parts[0].upper()
    return "XX"


@register_reporter
class CMMCReportGenerator(ReportGenerator):
    """Generate a CMMC Level 2 compliance report with SPRS score estimate."""

    name = "cmmc_report"
    display_name = "CMMC Compliance Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        cmmc_findings = [f for f in findings if f.framework == "CMMC"]

        status_counts = Counter(f.status for f in cmmc_findings)
        total = len(cmmc_findings)
        passed = status_counts.get("pass", 0)
        failed = status_counts.get("fail", 0)
        manual = status_counts.get("manual", 0)

        # SPRS score estimate: start at 110, subtract per failure
        sprs_score = 110
        for f in cmmc_findings:
            if f.status == "fail":
                sprs_score -= _SEVERITY_DEDUCTION.get(f.severity, 1)
        sprs_score = max(sprs_score, -203)  # SPRS floor

        # Group by domain
        by_domain: dict[str, list[ComplianceFinding]] = defaultdict(list)
        for f in cmmc_findings:
            domain = _practice_domain(f.control_id)
            by_domain[domain].append(f)

        lines: list[str] = []
        _a = lines.append

        _a("# CMMC Level 2 Compliance Report")
        _a("")
        _a(f"**Generated:** {ts}")
        _a(f"**Domain:** {data.domain}")
        _a(f"**Target Level:** CMMC Level 2 (Advanced)")
        _a("")
        _a("## Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total Practices Assessed | {total} |")
        _a(f"| Met (Pass) | {passed} |")
        _a(f"| Not Met (Fail) | {failed} |")
        _a(f"| Requires Verification | {manual} |")
        _a(f"| **Estimated SPRS Score** | **{sprs_score}** |")
        _a("")

        _a("## SPRS Score Estimate")
        _a("")
        _a(f"The Supplier Performance Risk System (SPRS) score is estimated at **{sprs_score}** out of 110.")
        _a("")
        if sprs_score >= 110:
            _a("All assessed practices are met. Full score achieved for assessed controls.")
        elif sprs_score >= 80:
            _a("Score indicates strong compliance posture with minor gaps to address.")
        elif sprs_score >= 50:
            _a("Score indicates moderate compliance. Significant remediation needed before assessment.")
        else:
            _a("Score indicates substantial gaps. Major remediation effort required.")
        _a("")
        _a("> **Note:** This is an automated estimate based on Google Workspace controls only.")
        _a("> The actual SPRS score encompasses all CUI-handling systems and requires a")
        _a("> comprehensive assessment by a C3PAO.")
        _a("")

        _a("## Level 2 Readiness Assessment")
        _a("")
        readiness_pct = (passed * 100 // total) if total > 0 else 0
        _a(f"**Overall Readiness: {readiness_pct}%** ({passed}/{total} practices met)")
        _a("")
        if readiness_pct >= 90:
            _a("Assessment readiness: **HIGH** - Minor items to address before C3PAO assessment.")
        elif readiness_pct >= 70:
            _a("Assessment readiness: **MODERATE** - Several practices need remediation.")
        else:
            _a("Assessment readiness: **LOW** - Significant work required before assessment.")
        _a("")

        _a("## Practice-by-Practice Assessment")
        _a("")

        for domain in sorted(by_domain.keys()):
            domain_findings = by_domain[domain]
            domain_name = _CMMC_DOMAINS.get(domain, "Other")
            domain_passed = sum(1 for f in domain_findings if f.status == "pass")

            _a(f"### {domain} - {domain_name}")
            _a("")
            _a(f"**Domain Score:** {domain_passed}/{len(domain_findings)} practices met")
            _a("")
            _a("| Practice | Title | Status | Severity | Details |")
            _a("|----------|-------|--------|----------|---------|")

            for f in sorted(domain_findings, key=lambda x: x.control_id):
                status_label = {
                    "pass": "MET",
                    "fail": "NOT MET",
                    "manual": "VERIFY",
                }.get(f.status, f.status.upper())
                _a(f"| {f.control_id} | {f.title} | {status_label} | {f.severity.title()} | {f.comments} |")

            _a("")

        # POA&M template
        failed_findings = [f for f in cmmc_findings if f.status == "fail"]
        if failed_findings:
            _a("## Plan of Action & Milestones (POA&M)")
            _a("")
            _a("The following practices are not met and require remediation planning:")
            _a("")
            _a("| # | Practice | Finding | Severity | Estimated Effort | Target Date |")
            _a("|---|----------|---------|----------|-----------------|-------------|")
            for i, f in enumerate(failed_findings, 1):
                effort = {
                    "critical": "Immediate",
                    "high": "1-2 weeks",
                    "medium": "2-4 weeks",
                    "low": "4-8 weeks",
                }.get(f.severity, "TBD")
                target = {
                    "critical": "ASAP",
                    "high": "30 days",
                    "medium": "90 days",
                    "low": "180 days",
                }.get(f.severity, "TBD")
                _a(f"| {i} | {f.control_id} | {f.title} | {f.severity.title()} | {effort} | {target} |")
            _a("")
            _a("> POA&M items must be tracked and resolved prior to or during the CMMC assessment.")
            _a("> Operational POA&Ms may be accepted for Level 2 conditional certification.")
            _a("")

        _a("---")
        _a(f"*Report generated by gws-inspector on {ts}*")

        output.save_markdown(
            "\n".join(lines),
            "compliance",
            "cmmc",
            "cmmc_compliance_report.md",
        )
