"""CMMC 2.0 (Level 2) framework analyzer for Google Workspace."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_admins,
    analyze_monitoring,
    analyze_password_policies,
    analyze_session_policies,
    analyze_users,
    is_2sv_enforced,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "cmmc"


@register_analyzer
class CMMCAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against CMMC 2.0 Level 2 practices."""

    name = "cmmc"
    display_name = "CMMC 2.0 (Level 2)"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._ac_l2_3_1_1_user_management(data))
        findings.extend(self._ac_l2_3_1_5_least_privilege(data))
        findings.extend(self._ac_l2_3_1_8_lockout(data))
        findings.extend(self._ac_l2_3_1_10_session_lock(data))
        findings.extend(self._ia_l2_3_5_3_mfa(data))
        findings.extend(self._ia_l2_3_5_7_password_complexity(data))
        findings.extend(self._ia_l2_3_5_8_password_reuse(data))
        findings.extend(self._au_l2_3_3_1_audit_records(data))
        findings.extend(self._au_l2_3_3_4_audit_alerts(data))
        return findings

    # ── AC.L2-3.1.1: User management ─────────────────────────────

    def _ac_l2_3_1_1_user_management(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AC.L2-3.1.1",
                title="Authorized Access Control",
                severity="info",
                status="pass",
                comments=(
                    f"All {user_analysis.active_users} active user accounts show recent login activity. "
                    "No stale accounts detected."
                ),
                details={
                    "total_users": user_analysis.total_users,
                    "active_users": user_analysis.active_users,
                    "suspended_users": user_analysis.suspended_users,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AC.L2-3.1.1",
            title="Authorized Access Control",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} account(s) inactive for 90+ days. "
                "CMMC requires limiting system access to authorized users and processes."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── AC.L2-3.1.5: Least privilege (admin ratio) ───────────────

    def _ac_l2_3_1_5_least_privilege(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)

        # Flag if admin-to-user ratio exceeds 10% or super admins > 3
        issues: list[str] = []
        if admin_analysis.super_admin_count > 3:
            issues.append(
                f"Super admin count ({admin_analysis.super_admin_count}) exceeds recommended maximum of 3"
            )
        if admin_analysis.admin_to_user_ratio > 10:
            issues.append(
                f"Admin-to-user ratio ({admin_analysis.admin_to_user_ratio:.1f}%) exceeds 10%"
            )

        if not issues:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AC.L2-3.1.5",
                title="Least Privilege",
                severity="info",
                status="pass",
                comments=(
                    f"Admin privilege distribution is within acceptable limits. "
                    f"Super admins: {admin_analysis.super_admin_count}, "
                    f"total admins: {admin_analysis.total_admins}, "
                    f"ratio: {admin_analysis.admin_to_user_ratio:.1f}%."
                ),
                details={
                    "super_admin_count": admin_analysis.super_admin_count,
                    "total_admins": admin_analysis.total_admins,
                    "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AC.L2-3.1.5",
            title="Least Privilege",
            severity="high",
            status="fail",
            comments=(
                f"Least privilege concerns: {'; '.join(issues)}. "
                "CMMC requires employing the principle of least privilege."
            ),
            details={
                "super_admin_count": admin_analysis.super_admin_count,
                "total_admins": admin_analysis.total_admins,
                "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                "issues": issues,
            },
        )]

    # ── AC.L2-3.1.8: Unsuccessful logon attempts / lockout ───────

    def _ac_l2_3_1_8_lockout(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AC.L2-3.1.8",
            title="Unsuccessful Logon Attempts",
            severity="info",
            status="manual",
            comments=(
                "Google Workspace enforces account lockout after repeated failed login attempts "
                "by default. This behavior is managed by Google and cannot be configured. "
                "Verify this meets your CMMC lockout policy requirements."
            ),
            details={},
        )]

    # ── AC.L2-3.1.10: Session lock ───────────────────────────────

    def _ac_l2_3_1_10_session_lock(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            max_hours = 12
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="AC.L2-3.1.10",
                    title="Session Lock",
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
                    control_id="AC.L2-3.1.10",
                    title="Session Lock",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding {max_hours}h. "
                        "CMMC requires session lock after a defined period of inactivity."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))

        return findings

    # ── IA.L2-3.5.3: Multi-factor authentication ─────────────────

    def _ia_l2_3_5_3_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="IA.L2-3.5.3",
                title="Multi-Factor Authentication",
                severity="info",
                status="pass",
                comments="2-Step Verification is enforced, satisfying CMMC MFA requirements.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="IA.L2-3.5.3",
            title="Multi-Factor Authentication",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "CMMC Level 2 requires MFA for all users accessing CUI."
            ),
            details={},
        )]

    # ── IA.L2-3.5.7: Password complexity ─────────────────────────

    def _ia_l2_3_5_7_password_complexity(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 12:
                issues.append(f"Minimum length is {policy.min_length} (require >= 12)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA.L2-3.5.7",
                    title="Password Complexity",
                    severity="info",
                    status="pass",
                    comments=f"Password complexity for OU '{policy.org_unit}' meets CMMC requirements.",
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA.L2-3.5.7",
                    title="Password Complexity",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password complexity for OU '{policy.org_unit}' is insufficient: "
                        f"{'; '.join(issues)}."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "issues": issues,
                    },
                ))

        return findings

    # ── IA.L2-3.5.8: Password reuse ──────────────────────────────

    def _ia_l2_3_5_8_password_reuse(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            if not policy.allow_password_reuse:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA.L2-3.5.8",
                    title="Password Reuse",
                    severity="info",
                    status="pass",
                    comments=f"Password reuse is prohibited for OU '{policy.org_unit}'.",
                    details={"org_unit": policy.org_unit, "allow_password_reuse": False},
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA.L2-3.5.8",
                    title="Password Reuse",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Password reuse is allowed for OU '{policy.org_unit}'. "
                        "CMMC requires prohibiting password reuse for a specified number of generations."
                    ),
                    details={"org_unit": policy.org_unit, "allow_password_reuse": True},
                ))

        return findings

    # ── AU.L2-3.3.1: Audit records ────────────────────────────────

    def _au_l2_3_3_1_audit_records(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AU.L2-3.3.1",
                title="System Auditing",
                severity="info",
                status="pass",
                comments=(
                    "Audit logging is active. "
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
            control_id="AU.L2-3.3.1",
            title="System Auditing",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "CMMC requires creating and retaining audit records to enable monitoring, "
                "analysis, investigation, and reporting."
            ),
            details={},
        )]

    # ── AU.L2-3.3.4: Audit alerts ────────────────────────────────

    def _au_l2_3_3_4_audit_alerts(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)
        has_alerts = bool(monitoring.alert_types)

        if has_alerts:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AU.L2-3.3.4",
                title="Audit Alert Notification",
                severity="info",
                status="pass",
                comments=(
                    f"Alert Center has {len(monitoring.alert_types)} alert type(s) configured. "
                    "Alert-based notification is available."
                ),
                details={"alert_types": monitoring.alert_types},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AU.L2-3.3.4",
            title="Audit Alert Notification",
            severity="medium",
            status="fail",
            comments=(
                "No alerts detected in the Alert Center. "
                "CMMC requires alerting when audit processing failures occur."
            ),
            details={},
        )]
