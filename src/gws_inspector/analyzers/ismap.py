"""ISMAP (ISO 27001) framework analyzer for Google Workspace."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_monitoring,
    analyze_password_policies,
    analyze_users,
    is_2sv_enforced,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "ismap"


@register_analyzer
class ISMAPAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against ISMAP (ISO 27001) controls."""

    name = "ismap"
    display_name = "ISMAP (ISO 27001)"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._a_9_1_1_access_policies(data))
        findings.extend(self._a_9_2_1_user_deregistration(data))
        findings.extend(self._a_9_2_4_password_strength(data))
        findings.extend(self._a_9_4_2_mfa(data))
        findings.extend(self._a_9_4_3_lockout(data))
        findings.extend(self._a_12_4_1_event_logging(data))
        return findings

    # ── A.9.1.1: Access control policy (groups exist) ─────────────

    def _a_9_1_1_access_policies(self, data: GWSData) -> list[ComplianceFinding]:
        group_count = len(data.groups)

        if group_count > 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="A.9.1.1",
                title="Access Control Policy",
                severity="info",
                status="pass",
                comments=(
                    f"{group_count} group(s) configured for access control. "
                    "Verify groups align with documented access control policies."
                ),
                details={"group_count": group_count},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="A.9.1.1",
            title="Access Control Policy",
            severity="medium",
            status="fail",
            comments=(
                "No groups found. ISO 27001 A.9.1.1 requires an access control policy "
                "with role-based groupings. Create Google Groups to manage access by role."
            ),
            details={"group_count": 0},
        )]

    # ── A.9.2.1: User deregistration (inactive accounts) ─────────

    def _a_9_2_1_user_deregistration(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="A.9.2.1",
                title="User Registration and De-registration",
                severity="info",
                status="pass",
                comments=(
                    "No inactive accounts detected. User de-registration process "
                    "appears to be managed appropriately."
                ),
                details={
                    "active_users": user_analysis.active_users,
                    "suspended_users": user_analysis.suspended_users,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="A.9.2.1",
            title="User Registration and De-registration",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} account(s) inactive for 90+ days. "
                "ISO 27001 A.9.2.1 requires a formal process for removing "
                "access rights when they are no longer needed."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── A.9.2.4: Password strength (min 8 + strong) ──────────────

    def _a_9_2_4_password_strength(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 8:
                issues.append(f"Minimum length is {policy.min_length} (require >= 8)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="A.9.2.4",
                    title="Management of Secret Authentication Information",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' meets ISMAP requirements "
                        f"(min length: {policy.min_length}, strong passwords enforced)."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="A.9.2.4",
                    title="Management of Secret Authentication Information",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' does not meet "
                        f"ISMAP requirements: {'; '.join(issues)}."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "issues": issues,
                    },
                ))

        return findings

    # ── A.9.4.2: Secure log-on — MFA ─────────────────────────────

    def _a_9_4_2_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="A.9.4.2",
                title="Secure Log-On Procedures",
                severity="info",
                status="pass",
                comments=(
                    "2-Step Verification is enforced, providing secure log-on "
                    "procedures per ISO 27001 A.9.4.2."
                ),
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="A.9.4.2",
            title="Secure Log-On Procedures",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "ISO 27001 A.9.4.2 requires secure log-on procedures including MFA."
            ),
            details={},
        )]

    # ── A.9.4.3: Password management / lockout (manual) ──────────

    def _a_9_4_3_lockout(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="A.9.4.3",
            title="Password Management System",
            severity="info",
            status="manual",
            comments=(
                "Google Workspace enforces account lockout after repeated failed login attempts "
                "by default. This is managed by Google and cannot be configured. "
                "Verify this meets your organization's password management policy."
            ),
            details={},
        )]

    # ── A.12.4.1: Event logging ───────────────────────────────────

    def _a_12_4_1_event_logging(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="A.12.4.1",
                title="Event Logging",
                severity="info",
                status="pass",
                comments=(
                    "Audit event logging is active. "
                    f"Admin events: {monitoring.admin_audit_events}, "
                    f"Login events: {monitoring.login_audit_events}, "
                    f"Drive events: {monitoring.drive_audit_events}."
                ),
                details={
                    "admin_audit_events": monitoring.admin_audit_events,
                    "login_audit_events": monitoring.login_audit_events,
                    "drive_audit_events": monitoring.drive_audit_events,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="A.12.4.1",
            title="Event Logging",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "ISO 27001 A.12.4.1 requires event logs recording user activities, "
                "exceptions, faults, and information security events."
            ),
            details={},
        )]
