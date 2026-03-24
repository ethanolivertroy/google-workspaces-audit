"""CIS Google Workspace Benchmark analyzer."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_admins,
    analyze_devices,
    analyze_monitoring,
    analyze_oauth_tokens,
    analyze_password_policies,
    analyze_session_policies,
    analyze_two_sv,
    analyze_users,
    is_2sv_enforced,
    is_less_secure_apps_blocked,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "cis"


@register_analyzer
class CISAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against the CIS Google Workspace Benchmark."""

    name = "cis"
    display_name = "CIS Google Workspace Benchmark"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._s1_1_2sv_enforcement(data))
        findings.extend(self._s1_2_password_policy(data))
        findings.extend(self._s1_3_session_duration(data))
        findings.extend(self._s1_4_less_secure_apps(data))
        findings.extend(self._s1_5_advanced_protection(data))
        findings.extend(self._s1_7_super_admin_count(data))
        findings.extend(self._s1_8_inactive_users(data))
        findings.extend(self._s2_1_audit_logging(data))
        findings.extend(self._s2_2_alerts(data))
        findings.extend(self._s3_1_drive_sharing(data))
        findings.extend(self._s5_x_mobile_management(data))
        findings.extend(self._s7_x_oauth_review(data))
        return findings

    # ── 1.1: 2SV enforcement ─────────────────────────────────────

    def _s1_1_2sv_enforcement(self, data: GWSData) -> list[ComplianceFinding]:
        two_sv_analyses = analyze_two_sv(data)
        enforced = is_2sv_enforced(data)
        user_analysis = analyze_users(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.1",
                title="Enforce 2-Step Verification",
                severity="info",
                status="pass",
                comments=(
                    "2-Step Verification is enforced at the organization level. "
                    f"{len(user_analysis.users_without_2sv)} user(s) are not yet enrolled."
                ),
                details={
                    "policies": [
                        {"org_unit": a.org_unit, "enforcement_level": a.enforcement_level}
                        for a in two_sv_analyses
                    ],
                    "users_without_2sv": len(user_analysis.users_without_2sv),
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="1.1",
            title="Enforce 2-Step Verification",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                f"{len(user_analysis.users_without_2sv)} user(s) are not enrolled. "
                "CIS recommends enforcing 2SV for all organizational units."
            ),
            details={
                "policies": [
                    {"org_unit": a.org_unit, "enforcement_level": a.enforcement_level}
                    for a in two_sv_analyses
                ],
                "users_without_2sv": len(user_analysis.users_without_2sv),
            },
        )]

    # ── 1.2: Password policy ─────────────────────────────────────

    def _s1_2_password_policy(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 12:
                issues.append(f"Minimum length is {policy.min_length} (CIS recommends >= 12)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")
            if policy.allow_password_reuse:
                issues.append("Password reuse is allowed")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="1.2",
                    title="Password Policy",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' meets CIS "
                        "Benchmark recommendations."
                    ),
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
                    control_id="1.2",
                    title="Password Policy",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' does not meet CIS "
                        f"recommendations: {'; '.join(issues)}."
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

    # ── 1.3: Session duration ─────────────────────────────────────

    def _s1_3_session_duration(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            # CIS recommends reducing session duration from the 14-day default
            max_hours = 12
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="1.3",
                    title="Session Duration",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h (CIS recommends <= {max_hours}h)."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="1.3",
                    title="Session Duration",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding the CIS "
                        f"recommendation of {max_hours}h."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))

        return findings

    # ── 1.4: Less secure apps ─────────────────────────────────────

    def _s1_4_less_secure_apps(self, data: GWSData) -> list[ComplianceFinding]:
        blocked = is_less_secure_apps_blocked(data)

        if blocked:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.4",
                title="Disable Less Secure App Access",
                severity="info",
                status="pass",
                comments="Less secure app access is blocked.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="1.4",
            title="Disable Less Secure App Access",
            severity="high",
            status="fail",
            comments=(
                "Less secure app access is not blocked. "
                "CIS recommends disabling access for apps that use less secure sign-in technology."
            ),
            details={},
        )]

    # ── 1.5: Advanced protection ──────────────────────────────────

    def _s1_5_advanced_protection(self, data: GWSData) -> list[ComplianceFinding]:
        has_policies = bool(data.advanced_protection_policies)
        enrolled = any(
            p.get("enabled", False) for p in data.advanced_protection_policies
        )

        if enrolled:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.5",
                title="Advanced Protection Program",
                severity="info",
                status="pass",
                comments=(
                    "Advanced Protection Program is enabled. "
                    "This provides the strongest account protections for high-risk users."
                ),
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="1.5",
            title="Advanced Protection Program",
            severity="low",
            status="fail" if has_policies else "manual",
            comments=(
                "Advanced Protection Program is not enabled. "
                "CIS recommends enrolling high-value target accounts "
                "(admins, executives) in the Advanced Protection Program."
            ),
            details={},
        )]

    # ── 1.7: Super admin count ────────────────────────────────────

    def _s1_7_super_admin_count(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)
        count = admin_analysis.super_admin_count

        if 2 <= count <= 3:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.7",
                title="Limit Super Admin Accounts",
                severity="info",
                status="pass",
                comments=(
                    f"Super admin count ({count}) is within the CIS-recommended "
                    "range of 2-3."
                ),
                details={
                    "super_admin_count": count,
                    "super_admins": [
                        u.get("primaryEmail") for u in admin_analysis.super_admin_users
                    ],
                },
            )]

        if count < 2:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.7",
                title="Limit Super Admin Accounts",
                severity="medium",
                status="fail",
                comments=(
                    f"Only {count} super admin account(s) detected. "
                    "CIS recommends at least 2 super admins for redundancy."
                ),
                details={
                    "super_admin_count": count,
                    "super_admins": [
                        u.get("primaryEmail") for u in admin_analysis.super_admin_users
                    ],
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="1.7",
            title="Limit Super Admin Accounts",
            severity="high",
            status="fail",
            comments=(
                f"Super admin count ({count}) exceeds the CIS-recommended maximum of 3. "
                "Reduce the number of super admin accounts."
            ),
            details={
                "super_admin_count": count,
                "super_admins": [
                    u.get("primaryEmail") for u in admin_analysis.super_admin_users
                ],
            },
        )]

    # ── 1.8: Inactive users ──────────────────────────────────────

    def _s1_8_inactive_users(self, data: GWSData) -> list[ComplianceFinding]:
        user_analysis = analyze_users(data)
        inactive_count = len(user_analysis.inactive_users)

        if inactive_count == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="1.8",
                title="Remove or Suspend Inactive Users",
                severity="info",
                status="pass",
                comments="No inactive user accounts detected (90-day threshold).",
                details={"inactive_count": 0},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="1.8",
            title="Remove or Suspend Inactive Users",
            severity="high",
            status="fail",
            comments=(
                f"{inactive_count} user account(s) have been inactive for 90+ days. "
                "CIS recommends suspending or removing inactive accounts."
            ),
            details={
                "inactive_count": inactive_count,
                "inactive_users": [
                    u.get("primaryEmail") for u in user_analysis.inactive_users
                ],
            },
        )]

    # ── 2.1: Audit logging ────────────────────────────────────────

    def _s2_1_audit_logging(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="2.1",
                title="Enable Audit Logging",
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
            control_id="2.1",
            title="Enable Audit Logging",
            severity="high",
            status="fail",
            comments=(
                "No audit log events detected. "
                "CIS recommends ensuring all audit logging is enabled and retained."
            ),
            details={},
        )]

    # ── 2.2: Alerts ───────────────────────────────────────────────

    def _s2_2_alerts(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)
        has_alerts = bool(monitoring.alert_types)

        if has_alerts:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="2.2",
                title="Configure Email Alerts",
                severity="info",
                status="pass",
                comments=(
                    f"Alert Center has {len(monitoring.alert_types)} alert type(s) configured "
                    f"with {len(monitoring.active_alerts)} active alert(s)."
                ),
                details={
                    "alert_types": monitoring.alert_types,
                    "active_alert_count": len(monitoring.active_alerts),
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="2.2",
            title="Configure Email Alerts",
            severity="medium",
            status="fail",
            comments=(
                "No alerts detected in the Alert Center. "
                "CIS recommends configuring alerts for security-relevant events "
                "(suspicious login, password changes, admin actions)."
            ),
            details={},
        )]

    # ── 3.1: Drive sharing (manual) ───────────────────────────────

    def _s3_1_drive_sharing(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="3.1",
            title="Drive External Sharing Settings",
            severity="info",
            status="manual",
            comments=(
                "Review Google Drive sharing settings to ensure external sharing is "
                "appropriately restricted. CIS recommends limiting sharing to "
                "whitelisted domains or disabling external sharing where possible."
            ),
            details={},
        )]

    # ── 5.x: Mobile device management ─────────────────────────────

    def _s5_x_mobile_management(self, data: GWSData) -> list[ComplianceFinding]:
        device_analysis = analyze_devices(data)

        if device_analysis.total_devices == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="5.x",
                title="Mobile Device Management",
                severity="info",
                status="not_applicable",
                comments="No mobile devices detected in the environment.",
                details={},
            )]

        if device_analysis.unmanaged_devices == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="5.x",
                title="Mobile Device Management",
                severity="info",
                status="pass",
                comments=(
                    f"All {device_analysis.total_devices} device(s) are managed. "
                    "CIS recommends enforcing mobile device management."
                ),
                details={
                    "total_devices": device_analysis.total_devices,
                    "managed_devices": device_analysis.managed_devices,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="5.x",
            title="Mobile Device Management",
            severity="medium",
            status="fail",
            comments=(
                f"{device_analysis.unmanaged_devices} of {device_analysis.total_devices} "
                "device(s) are unmanaged. CIS recommends enabling advanced mobile "
                "management and enforcing device policies."
            ),
            details={
                "total_devices": device_analysis.total_devices,
                "managed_devices": device_analysis.managed_devices,
                "unmanaged_devices": device_analysis.unmanaged_devices,
            },
        )]

    # ── 7.x: OAuth / third-party app review ───────────────────────

    def _s7_x_oauth_review(self, data: GWSData) -> list[ComplianceFinding]:
        risky_apps = analyze_oauth_tokens(data)

        if not risky_apps:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="7.x",
                title="Third-Party App Access Review",
                severity="info",
                status="pass",
                comments=(
                    "No risky third-party OAuth applications detected. "
                    "Continue to review and restrict third-party app access."
                ),
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="7.x",
            title="Third-Party App Access Review",
            severity="high",
            status="fail",
            comments=(
                f"{len(risky_apps)} third-party app(s) with broad OAuth scopes detected. "
                "CIS recommends reviewing and restricting third-party application access, "
                "especially apps with access to Gmail and Drive."
            ),
            details={
                "risky_app_count": len(risky_apps),
                "risky_apps": [
                    {"app_name": a.get("app_name"), "user": a.get("user")}
                    for a in risky_apps
                ],
            },
        )]
