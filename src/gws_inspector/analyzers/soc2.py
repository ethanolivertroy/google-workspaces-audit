"""SOC 2 framework analyzer for Google Workspace."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_monitoring,
    analyze_session_policies,
    analyze_users,
    is_2sv_enforced,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "soc2"


@register_analyzer
class SOC2Analyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against SOC 2 Trust Services Criteria."""

    name = "soc2"
    display_name = "SOC 2"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._cc6_1_mfa(data))
        findings.extend(self._cc6_2_user_lifecycle(data))
        findings.extend(self._cc6_3_rbac(data))
        findings.extend(self._cc6_6_session_controls(data))
        findings.extend(self._cc6_7_trusted_origins(data))
        findings.extend(self._cc6_8_unauthorized_access(data))
        findings.extend(self._cc7_2_monitoring(data))
        return findings

    # ── CC6.1: Logical and physical access — MFA ──────────────────

    def _cc6_1_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="CC6.1",
                title="Logical Access Security — MFA",
                severity="info",
                status="pass",
                comments="2-Step Verification is enforced, satisfying SOC 2 MFA requirements.",
                details={},
            )]

        users_without_2sv = analyze_users(data).users_without_2sv
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC6.1",
            title="Logical Access Security — MFA",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                f"{len(users_without_2sv)} user(s) lack 2SV enrollment. "
                "SOC 2 CC6.1 requires logical access controls including MFA."
            ),
            details={"users_without_2sv_count": len(users_without_2sv)},
        )]

    # ── CC6.2: User lifecycle management ──────────────────────────

    def _cc6_2_user_lifecycle(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="CC6.2",
                title="User Lifecycle Management",
                severity="info",
                status="pass",
                comments=(
                    "No inactive accounts detected. User provisioning and deprovisioning "
                    "appears to be managed appropriately."
                ),
                details={
                    "active_users": user_analysis.active_users,
                    "suspended_users": user_analysis.suspended_users,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC6.2",
            title="User Lifecycle Management",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} account(s) have been inactive for 90+ days. "
                "SOC 2 requires timely removal of access when no longer needed."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── CC6.3: Role-based access control (groups exist) ───────────

    def _cc6_3_rbac(self, data: GWSData) -> list[ComplianceFinding]:
        group_count = len(data.groups)

        if group_count > 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="CC6.3",
                title="Role-Based Access Control",
                severity="info",
                status="pass",
                comments=(
                    f"{group_count} group(s) defined for role-based access control. "
                    "Verify groups align with the principle of least privilege."
                ),
                details={"group_count": group_count},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC6.3",
            title="Role-Based Access Control",
            severity="medium",
            status="fail",
            comments=(
                "No groups found. SOC 2 expects role-based access controls. "
                "Use Google Groups to manage permissions by role."
            ),
            details={"group_count": 0},
        )]

    # ── CC6.6: Session controls ───────────────────────────────────

    def _cc6_6_session_controls(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            max_hours = 24
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="CC6.6",
                    title="Session Management",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h (limit: {max_hours}h)."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="CC6.6",
                    title="Session Management",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding {max_hours}h. "
                        "SOC 2 expects session timeouts to limit unauthorized access."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))

        return findings

    # ── CC6.7: Trusted origins (manual) ───────────────────────────

    def _cc6_7_trusted_origins(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC6.7",
            title="Restriction of Data Transmission",
            severity="info",
            status="manual",
            comments=(
                "Verify that data transmission is restricted to trusted origins. "
                "Review Google Workspace sharing settings, DLP rules, and "
                "context-aware access policies to ensure data is only transmitted "
                "to authorized destinations."
            ),
            details={},
        )]

    # ── CC6.8: Unauthorized access prevention (alerts) ────────────

    def _cc6_8_unauthorized_access(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)
        has_alerts = bool(monitoring.alert_types)

        if has_alerts:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="CC6.8",
                title="Unauthorized Access Prevention",
                severity="info",
                status="pass",
                comments=(
                    f"Alert Center is active with {len(monitoring.alert_types)} alert type(s). "
                    "Automated detection of unauthorized access attempts is in place."
                ),
                details={"alert_types": monitoring.alert_types},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC6.8",
            title="Unauthorized Access Prevention",
            severity="medium",
            status="fail",
            comments=(
                "No alerts configured in the Alert Center. "
                "SOC 2 CC6.8 requires controls to prevent, detect, and act upon "
                "unauthorized access."
            ),
            details={},
        )]

    # ── CC7.2: Monitoring ─────────────────────────────────────────

    def _cc7_2_monitoring(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="CC7.2",
                title="System Monitoring",
                severity="info",
                status="pass",
                comments=(
                    "Audit logging is active for monitoring system components. "
                    f"Admin events: {monitoring.admin_audit_events}, "
                    f"Login events: {monitoring.login_audit_events}."
                ),
                details={
                    "admin_audit_events": monitoring.admin_audit_events,
                    "login_audit_events": monitoring.login_audit_events,
                    "drive_audit_events": monitoring.drive_audit_events,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="CC7.2",
            title="System Monitoring",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "SOC 2 CC7.2 requires monitoring system components for anomalies."
            ),
            details={},
        )]
