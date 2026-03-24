"""FedRAMP (NIST 800-53) framework analyzer for Google Workspace."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_admins,
    analyze_monitoring,
    analyze_password_policies,
    analyze_session_policies,
    analyze_two_sv,
    analyze_users,
    is_2sv_enforced,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "fedramp"


@register_analyzer
class FedRAMPAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against FedRAMP (NIST 800-53) controls."""

    name = "fedramp"
    display_name = "FedRAMP (NIST 800-53)"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._ac_2_3_inactive_users(data))
        findings.extend(self._ac_6_5_super_admin_count(data))
        findings.extend(self._ac_11_session_duration(data))
        findings.extend(self._ia_2_mfa_enforcement(data))
        findings.extend(self._ia_5_password_policy(data))
        findings.extend(self._au_2_au_3_audit_logging(data))
        findings.extend(self._sc_13_encryption(data))
        findings.extend(self._si_4_monitoring_alerts(data))
        return findings

    # ── AC-2(3): Inactive account management ──────────────────────

    def _ac_2_3_inactive_users(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AC-2(3)",
                title="Inactive Account Management",
                severity="info",
                status="pass",
                comments="No inactive user accounts detected (90-day threshold).",
                details={"inactive_count": 0},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AC-2(3)",
            title="Inactive Account Management",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} user account(s) have not logged in within 90 days. "
                "FedRAMP requires disabling inactive accounts."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── AC-6(5): Super admin least privilege ──────────────────────

    def _ac_6_5_super_admin_count(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)
        count = admin_analysis.super_admin_count

        if count <= 3:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AC-6(5)",
                title="Super Admin Least Privilege",
                severity="info",
                status="pass",
                comments=f"Super admin count ({count}) is within the recommended limit of 3.",
                details={
                    "super_admin_count": count,
                    "super_admins": [
                        u.get("primaryEmail") for u in admin_analysis.super_admin_users
                    ],
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AC-6(5)",
            title="Super Admin Least Privilege",
            severity="high",
            status="fail",
            comments=(
                f"Super admin count ({count}) exceeds the recommended maximum of 3. "
                "FedRAMP requires restricting privileged accounts to the minimum necessary."
            ),
            details={
                "super_admin_count": count,
                "super_admins": [
                    u.get("primaryEmail") for u in admin_analysis.super_admin_users
                ],
            },
        )]

    # ── AC-11: Session lock / duration ────────────────────────────

    def _ac_11_session_duration(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            # FedRAMP typically requires session lock after 15 minutes of inactivity.
            # Google Workspace session duration controls web session length (hours).
            # A duration <= 12 hours is a reasonable proxy for compliance.
            max_hours = 12
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="AC-11",
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
                        "max_hours": max_hours,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="AC-11",
                    title="Session Lock",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding the {max_hours}h limit. "
                        "FedRAMP requires session lock after a period of inactivity."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                        "max_hours": max_hours,
                    },
                ))

        return findings

    # ── IA-2: MFA / 2SV enforcement ──────────────────────────────

    def _ia_2_mfa_enforcement(self, data: GWSData) -> list[ComplianceFinding]:
        two_sv_analyses = analyze_two_sv(data)
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="IA-2",
                title="Multi-Factor Authentication",
                severity="info",
                status="pass",
                comments="2-Step Verification is enforced at the organization level.",
                details={
                    "policies": [
                        {"org_unit": a.org_unit, "enforcement_level": a.enforcement_level}
                        for a in two_sv_analyses
                    ],
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="IA-2",
            title="Multi-Factor Authentication",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "FedRAMP requires MFA for all organizational users (IA-2)."
            ),
            details={
                "policies": [
                    {"org_unit": a.org_unit, "enforcement_level": a.enforcement_level}
                    for a in two_sv_analyses
                ],
            },
        )]

    # ── IA-5: Password policy ────────────────────────────────────

    def _ia_5_password_policy(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 12:
                issues.append(f"Minimum length is {policy.min_length} (require >= 12)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")
            if policy.allow_password_reuse:
                issues.append("Password reuse is allowed")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA-5",
                    title="Password Policy",
                    severity="info",
                    status="pass",
                    comments=f"Password policy for OU '{policy.org_unit}' meets FedRAMP requirements.",
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "allow_password_reuse": policy.allow_password_reuse,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="IA-5",
                    title="Password Policy",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' does not meet "
                        f"FedRAMP requirements: {'; '.join(issues)}."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "allow_password_reuse": policy.allow_password_reuse,
                        "issues": issues,
                    },
                ))

        return findings

    # ── AU-2 / AU-3: Audit logging ───────────────────────────────

    def _au_2_au_3_audit_logging(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="AU-2/AU-3",
                title="Audit Logging",
                severity="info",
                status="pass",
                comments=(
                    "Audit logging is active. "
                    f"Admin events: {monitoring.admin_audit_events}, "
                    f"Login events: {monitoring.login_audit_events}, "
                    f"Drive events: {monitoring.drive_audit_events}."
                ),
                details={
                    "admin_audit_events": monitoring.admin_audit_events,
                    "login_audit_events": monitoring.login_audit_events,
                    "drive_audit_events": monitoring.drive_audit_events,
                    "token_audit_events": monitoring.token_audit_events,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="AU-2/AU-3",
            title="Audit Logging",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "FedRAMP requires comprehensive audit logging of security-relevant events."
            ),
            details={
                "admin_audit_events": monitoring.admin_audit_events,
                "login_audit_events": monitoring.login_audit_events,
            },
        )]

    # ── SC-13: Cryptographic protection ──────────────────────────

    def _sc_13_encryption(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="SC-13",
            title="Cryptographic Protection",
            severity="info",
            status="manual",
            comments=(
                "Google Workspace encrypts data in transit (TLS) and at rest by default. "
                "Verify client-side encryption (CSE) is enabled for sensitive data if required "
                "by your FedRAMP authorization boundary."
            ),
            details={},
        )]

    # ── SI-4: Monitoring and alerts ──────────────────────────────

    def _si_4_monitoring_alerts(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)
        alert_count = len(monitoring.active_alerts)
        has_alerts = bool(monitoring.alert_types)

        if has_alerts:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="SI-4",
                title="Information System Monitoring",
                severity="info",
                status="pass",
                comments=(
                    f"Alert Center is configured with {len(monitoring.alert_types)} alert type(s) "
                    f"and {alert_count} active alert(s)."
                ),
                details={
                    "alert_types": monitoring.alert_types,
                    "active_alert_count": alert_count,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="SI-4",
            title="Information System Monitoring",
            severity="medium",
            status="fail",
            comments=(
                "No alerts detected in the Alert Center. "
                "FedRAMP requires monitoring for security-relevant events and alerting on anomalies."
            ),
            details={"alert_types": {}, "active_alert_count": 0},
        )]
