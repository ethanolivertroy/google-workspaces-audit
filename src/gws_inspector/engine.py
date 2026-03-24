"""Audit engine — orchestrates collect → analyze → report → archive."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime

from gws_inspector.analyzers import get_analyzers
from gws_inspector.client import GWSClient
from gws_inspector.collector import GWSDataCollector
from gws_inspector.models import AuditResult, ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import get_reporters

logger = logging.getLogger(__name__)


class AuditEngine:
    """Top-level orchestrator for a Google Workspace compliance audit."""

    def __init__(
        self,
        client: GWSClient,
        output: OutputManager,
        *,
        frameworks: list[str] | None = None,
    ) -> None:
        self._client = client
        self._output = output
        self._frameworks = frameworks

    def run(self) -> AuditResult:
        """Execute the full 3-phase audit."""
        # Phase 1: Collect
        logger.info("=== PHASE 1: Core Data Retrieval ===")
        collector = GWSDataCollector(self._client)
        data = collector.collect()
        self._save_raw_data(data)

        # Phase 2: Analyze
        logger.info("=== PHASE 2: Analysis ===")
        findings = self._run_analyzers(data)
        self._save_analysis(data, findings)

        # Phase 3: Report
        logger.info("=== PHASE 3: Compliance Reporting ===")
        self._run_reporters(findings, data)

        # Archive
        archive = self._output.create_archive()

        result = AuditResult(
            findings=findings,
            data=data,
            api_call_count=self._client.api_call_count,
            timestamp=datetime.now().isoformat(),
            domain=self._client.domain,
        )
        self._print_summary(result, archive)
        return result

    def _run_analyzers(self, data: GWSData) -> list[ComplianceFinding]:
        analyzers = get_analyzers(self._frameworks)
        all_findings: list[ComplianceFinding] = []
        for analyzer in analyzers:
            logger.info("Running %s analyzer...", analyzer.display_name)
            try:
                all_findings.extend(analyzer.analyze(data))
            except Exception as e:
                logger.error("Error in %s analyzer: %s", analyzer.name, e)
        return all_findings

    def _run_reporters(self, findings: list[ComplianceFinding], data: GWSData) -> None:
        for reporter in get_reporters():
            logger.info("Generating %s report...", reporter.display_name)
            try:
                reporter.generate(findings, data, self._output)
            except Exception as e:
                logger.error("Error in %s reporter: %s", reporter.name, e)

    def _save_raw_data(self, data: GWSData) -> None:
        save = self._output.save_json
        save(data.users, "all_users.json")
        save(data.groups, "groups.json")
        save(data.org_units, "org_units.json")
        save(data.roles, "roles.json")
        save(data.role_assignments, "role_assignments.json")
        save(data.domains, "domains.json")
        save(data.mobile_devices, "mobile_devices.json")
        save(data.customer, "customer.json")
        save(data.super_admins, "super_admins.json")
        save(data.delegated_admins, "delegated_admins.json")
        save(data.admin_activities, "admin_activities.json")
        save(data.login_activities, "login_activities.json")
        save(data.drive_activities, "drive_activities.json")
        save(data.token_activities, "token_activities.json")
        save(data.two_step_verification_policies, "two_step_verification_policies.json")
        save(data.password_policies, "password_policies.json")
        save(data.session_policies, "session_policies.json")
        save(data.alerts, "alerts.json")
        save(data.chrome_policies, "chrome_policies.json")
        save(data.devices, "devices.json")

    def _save_analysis(self, data: GWSData, findings: list[ComplianceFinding]) -> None:
        from gws_inspector.analyzers.common import (
            analyze_admins,
            analyze_monitoring,
            analyze_users,
        )

        save = self._output.save_json

        users_analysis = analyze_users(data)
        save(users_analysis.inactive_users, "inactive_users.json", "analysis")

        admins_analysis = analyze_admins(data)
        save(asdict(admins_analysis), "admin_analysis.json", "analysis")

        monitoring = analyze_monitoring(data)
        save(asdict(monitoring), "monitoring_analysis.json", "analysis")

        save([f.to_dict() for f in findings], "all_findings.json", "analysis")

        frameworks = {f.framework for f in findings}
        for fw in frameworks:
            fw_findings = [f for f in findings if f.framework == fw]
            summary = {
                "framework": fw,
                "total": len(fw_findings),
                "passed": len([f for f in fw_findings if f.status == "pass"]),
                "failed": len([f for f in fw_findings if f.status == "fail"]),
                "manual": len([f for f in fw_findings if f.status == "manual"]),
                "findings": [f.to_dict() for f in fw_findings],
            }
            save(summary, f"{fw.lower().replace(' ', '_')}_analysis.json", "analysis")

    @staticmethod
    def _print_summary(result: AuditResult, archive: object) -> None:
        passed = len([f for f in result.findings if f.status == "pass"])
        failed = len([f for f in result.findings if f.status == "fail"])
        manual = len([f for f in result.findings if f.status == "manual"])
        frameworks = {f.framework for f in result.findings}

        print("\n" + "=" * 50)
        print("Google Workspace Security Audit Complete!")
        print("=" * 50)
        print(f"\nDomain:            {result.domain}")
        print(f"API calls:         {result.api_call_count}")
        print(f"Frameworks:        {', '.join(sorted(frameworks))}")
        print(f"Findings:          {len(result.findings)} total")
        print(f"  Pass: {passed}  |  Fail: {failed}  |  Manual: {manual}")
        print(f"\nArchive: {archive}")
