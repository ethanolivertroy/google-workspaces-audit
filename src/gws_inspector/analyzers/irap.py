"""IRAP (ISM + Essential Eight) framework analyzer for Google Workspace."""

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

_FRAMEWORK = "irap"


@register_analyzer
class IRAPAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against IRAP (ISM + Essential Eight) controls."""

    name = "irap"
    display_name = "IRAP (ISM + Essential Eight)"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._ism_0974_mfa(data))
        findings.extend(self._ism_0421_password_complexity(data))
        findings.extend(self._ism_1546_session_timeout(data))
        findings.extend(self._ism_1175_admin_privileges(data))
        findings.extend(self._ism_0407_logging(data))
        findings.extend(self._ism_1648_inactive_accounts(data))
        findings.extend(self._e8_mfa(data))
        findings.extend(self._e8_restrict_admin(data))
        findings.extend(self._e8_application_control(data))
        return findings

    # ── ISM-0974: Multi-factor authentication ─────────────────────

    def _ism_0974_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="ISM-0974",
                title="Multi-Factor Authentication",
                severity="info",
                status="pass",
                comments=(
                    "2-Step Verification is enforced, satisfying ISM-0974 MFA requirements."
                ),
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="ISM-0974",
            title="Multi-Factor Authentication",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "ISM-0974 requires multi-factor authentication for all users."
            ),
            details={},
        )]

    # ── ISM-0421: Password complexity (min 14 chars) ─────────────

    def _ism_0421_password_complexity(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 14:
                issues.append(
                    f"Minimum length is {policy.min_length} (ISM requires >= 14)"
                )
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="ISM-0421",
                    title="Password Complexity",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' meets ISM-0421 "
                        f"requirements (min length: {policy.min_length})."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="ISM-0421",
                    title="Password Complexity",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' does not meet "
                        f"ISM-0421 requirements: {'; '.join(issues)}."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "issues": issues,
                    },
                ))

        return findings

    # ── ISM-1546: Session timeout ─────────────────────────────────

    def _ism_1546_session_timeout(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            max_hours = 12
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="ISM-1546",
                    title="Session Timeout",
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
                    control_id="ISM-1546",
                    title="Session Timeout",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding {max_hours}h. "
                        "ISM-1546 requires sessions to time out after a period of inactivity."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))

        return findings

    # ── ISM-1175: Admin privileges ────────────────────────────────

    def _ism_1175_admin_privileges(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)
        count = admin_analysis.super_admin_count

        if count <= 3:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="ISM-1175",
                title="Restricting Administrative Privileges",
                severity="info",
                status="pass",
                comments=(
                    f"Super admin count ({count}) is within the recommended maximum of 3. "
                    f"Admin-to-user ratio: {admin_analysis.admin_to_user_ratio:.1f}%."
                ),
                details={
                    "super_admin_count": count,
                    "total_admins": admin_analysis.total_admins,
                    "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="ISM-1175",
            title="Restricting Administrative Privileges",
            severity="high",
            status="fail",
            comments=(
                f"Super admin count ({count}) exceeds the recommended maximum of 3. "
                "ISM-1175 requires restricting privileged access to the minimum necessary."
            ),
            details={
                "super_admin_count": count,
                "total_admins": admin_analysis.total_admins,
                "super_admins": [
                    u.get("primaryEmail") for u in admin_analysis.super_admin_users
                ],
            },
        )]

    # ── ISM-0407: Logging ─────────────────────────────────────────

    def _ism_0407_logging(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="ISM-0407",
                title="Event Logging",
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
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="ISM-0407",
            title="Event Logging",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "ISM-0407 requires logging of events for security monitoring."
            ),
            details={},
        )]

    # ── ISM-1648: Inactive accounts ───────────────────────────────

    def _ism_1648_inactive_accounts(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="ISM-1648",
                title="Inactive Account Management",
                severity="info",
                status="pass",
                comments="No inactive user accounts detected (90-day threshold).",
                details={"inactive_count": 0},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="ISM-1648",
            title="Inactive Account Management",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} account(s) inactive for 90+ days. "
                "ISM-1648 requires disabling inactive accounts after 45 days."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── Essential Eight: MFA ──────────────────────────────────────

    def _e8_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="E8-MFA",
                title="Essential Eight — Multi-Factor Authentication",
                severity="info",
                status="pass",
                comments="MFA is enforced, satisfying Essential Eight MFA requirements.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="E8-MFA",
            title="Essential Eight — Multi-Factor Authentication",
            severity="critical",
            status="fail",
            comments=(
                "MFA is not enforced. Essential Eight requires MFA for all users "
                "accessing internet-facing services."
            ),
            details={},
        )]

    # ── Essential Eight: Restrict admin privileges ────────────────

    def _e8_restrict_admin(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)

        issues: list[str] = []
        if admin_analysis.super_admin_count > 3:
            issues.append(
                f"Super admin count ({admin_analysis.super_admin_count}) exceeds 3"
            )
        if admin_analysis.admin_to_user_ratio > 10:
            issues.append(
                f"Admin-to-user ratio ({admin_analysis.admin_to_user_ratio:.1f}%) exceeds 10%"
            )

        if not issues:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="E8-ADMIN",
                title="Essential Eight — Restrict Administrative Privileges",
                severity="info",
                status="pass",
                comments=(
                    "Administrative privileges are appropriately restricted. "
                    f"Super admins: {admin_analysis.super_admin_count}, "
                    f"ratio: {admin_analysis.admin_to_user_ratio:.1f}%."
                ),
                details={
                    "super_admin_count": admin_analysis.super_admin_count,
                    "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="E8-ADMIN",
            title="Essential Eight — Restrict Administrative Privileges",
            severity="high",
            status="fail",
            comments=(
                f"Administrative privilege concerns: {'; '.join(issues)}. "
                "Essential Eight requires restricting admin privileges."
            ),
            details={
                "super_admin_count": admin_analysis.super_admin_count,
                "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                "issues": issues,
            },
        )]

    # ── Essential Eight: Application control (manual) ─────────────

    def _e8_application_control(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="E8-APPCTRL",
            title="Essential Eight — Application Control",
            severity="info",
            status="manual",
            comments=(
                "Application control in Google Workspace is managed through OAuth app "
                "whitelisting, Marketplace app restrictions, and Chrome extension policies. "
                "Verify that only approved applications are permitted."
            ),
            details={},
        )]
