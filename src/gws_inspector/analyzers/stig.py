"""DISA STIG-style analyzer for Google Workspace.

No official DISA STIG exists for Google Workspace.  This analyzer maps
CIS/FedRAMP-equivalent controls into STIG-style control identifiers for
organizations that prefer the STIG reporting format.
"""

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
    analyze_users,
    is_2sv_enforced,
    is_less_secure_apps_blocked,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "stig"


@register_analyzer
class STIGAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against DISA STIG-equivalent controls."""

    name = "stig"
    display_name = "DISA STIG"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._gws_mfa(data))
        findings.extend(self._gws_pwd(data))
        findings.extend(self._gws_sess(data))
        findings.extend(self._gws_adm(data))
        findings.extend(self._gws_log(data))
        findings.extend(self._gws_lsa(data))
        findings.extend(self._gws_mdm(data))
        findings.extend(self._gws_oauth(data))
        return findings

    # ── GWS-MFA: Multi-factor authentication ─────────────────────

    def _gws_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)
        user_analysis = analyze_users(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-MFA",
                title="Multi-Factor Authentication Enforcement",
                severity="info",
                status="pass",
                comments="2-Step Verification is enforced at the organization level.",
                details={
                    "users_without_2sv": len(user_analysis.users_without_2sv),
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="GWS-MFA",
            title="Multi-Factor Authentication Enforcement",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                f"{len(user_analysis.users_without_2sv)} user(s) lack 2SV enrollment."
            ),
            details={
                "users_without_2sv": len(user_analysis.users_without_2sv),
            },
        )]

    # ── GWS-PWD: Password policy ─────────────────────────────────

    def _gws_pwd(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 14:
                issues.append(f"Minimum length is {policy.min_length} (STIG requires >= 14)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")
            if policy.allow_password_reuse:
                issues.append("Password reuse is allowed")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="GWS-PWD",
                    title="Password Policy",
                    severity="info",
                    status="pass",
                    comments=f"Password policy for OU '{policy.org_unit}' meets STIG requirements.",
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="GWS-PWD",
                    title="Password Policy",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' is non-compliant: "
                        f"{'; '.join(issues)}."
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

    # ── GWS-SESS: Session management ─────────────────────────────

    def _gws_sess(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            max_hours = 12
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="GWS-SESS",
                    title="Session Duration",
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
                    control_id="GWS-SESS",
                    title="Session Duration",
                    severity="medium",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h, exceeding {max_hours}h."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                    },
                ))

        return findings

    # ── GWS-ADM: Admin privilege management ───────────────────────

    def _gws_adm(self, data: GWSData) -> list[ComplianceFinding]:
        admin_analysis = analyze_admins(data)
        count = admin_analysis.super_admin_count

        if count <= 3:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-ADM",
                title="Administrative Account Management",
                severity="info",
                status="pass",
                comments=(
                    f"Super admin count ({count}) is within the recommended maximum of 3. "
                    f"Total admin accounts: {admin_analysis.total_admins}."
                ),
                details={
                    "super_admin_count": count,
                    "total_admins": admin_analysis.total_admins,
                    "admin_to_user_ratio": admin_analysis.admin_to_user_ratio,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="GWS-ADM",
            title="Administrative Account Management",
            severity="high",
            status="fail",
            comments=(
                f"Super admin count ({count}) exceeds the recommended maximum of 3. "
                "Reduce the number of super admin accounts."
            ),
            details={
                "super_admin_count": count,
                "total_admins": admin_analysis.total_admins,
                "super_admins": [
                    u.get("primaryEmail") for u in admin_analysis.super_admin_users
                ],
            },
        )]

    # ── GWS-LOG: Audit logging ────────────────────────────────────

    def _gws_log(self, data: GWSData) -> list[ComplianceFinding]:
        monitoring = analyze_monitoring(data)

        if monitoring.has_audit_logging:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-LOG",
                title="Audit Logging",
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
            control_id="GWS-LOG",
            title="Audit Logging",
            severity="high",
            status="fail",
            comments="No audit log events detected. Enable and verify audit logging.",
            details={},
        )]

    # ── GWS-LSA: Less secure apps ────────────────────────────────

    def _gws_lsa(self, data: GWSData) -> list[ComplianceFinding]:
        blocked = is_less_secure_apps_blocked(data)

        if blocked:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-LSA",
                title="Less Secure App Access",
                severity="info",
                status="pass",
                comments="Less secure app access is blocked.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="GWS-LSA",
            title="Less Secure App Access",
            severity="high",
            status="fail",
            comments=(
                "Less secure app access is not blocked. "
                "Disable access for apps that use less secure sign-in technology."
            ),
            details={},
        )]

    # ── GWS-MDM: Mobile device management ────────────────────────

    def _gws_mdm(self, data: GWSData) -> list[ComplianceFinding]:
        device_analysis = analyze_devices(data)

        if device_analysis.total_devices == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-MDM",
                title="Mobile Device Management",
                severity="info",
                status="not_applicable",
                comments="No mobile devices detected in the environment.",
                details={},
            )]

        if device_analysis.unmanaged_devices == 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-MDM",
                title="Mobile Device Management",
                severity="info",
                status="pass",
                comments=(
                    f"All {device_analysis.total_devices} device(s) are managed. "
                    "Mobile device management is properly configured."
                ),
                details={
                    "total_devices": device_analysis.total_devices,
                    "managed_devices": device_analysis.managed_devices,
                },
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="GWS-MDM",
            title="Mobile Device Management",
            severity="medium",
            status="fail",
            comments=(
                f"{device_analysis.unmanaged_devices} of {device_analysis.total_devices} "
                "device(s) are unmanaged. Enforce mobile device management policies."
            ),
            details={
                "total_devices": device_analysis.total_devices,
                "managed_devices": device_analysis.managed_devices,
                "unmanaged_devices": device_analysis.unmanaged_devices,
            },
        )]

    # ── GWS-OAUTH: OAuth / third-party app review ────────────────

    def _gws_oauth(self, data: GWSData) -> list[ComplianceFinding]:
        risky_apps = analyze_oauth_tokens(data)

        if not risky_apps:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="GWS-OAUTH",
                title="Third-Party Application Access",
                severity="info",
                status="pass",
                comments="No risky third-party OAuth applications detected.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="GWS-OAUTH",
            title="Third-Party Application Access",
            severity="high",
            status="fail",
            comments=(
                f"{len(risky_apps)} third-party app(s) with broad OAuth scopes detected. "
                "Review and restrict unauthorized application access."
            ),
            details={
                "risky_app_count": len(risky_apps),
                "risky_apps": [
                    {"app_name": a.get("app_name"), "user": a.get("user")}
                    for a in risky_apps
                ],
            },
        )]
