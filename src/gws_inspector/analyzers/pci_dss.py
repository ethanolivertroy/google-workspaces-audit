"""PCI-DSS 4.0.1 framework analyzer for Google Workspace."""

from __future__ import annotations

from gws_inspector.analyzers import register_analyzer
from gws_inspector.analyzers.base import FrameworkAnalyzer
from gws_inspector.analyzers.common import (
    analyze_password_policies,
    analyze_session_policies,
    is_2sv_enforced,
)
from gws_inspector.models import ComplianceFinding, GWSData

_FRAMEWORK = "pci_dss"


@register_analyzer
class PCIDSSAnalyzer(FrameworkAnalyzer):
    """Analyze Google Workspace configuration against PCI-DSS 4.0.1 requirements."""

    name = "pci_dss"
    display_name = "PCI-DSS 4.0.1"

    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        findings.extend(self._r7_2_1_rbac(data))
        findings.extend(self._r8_2_1_strong_auth(data))
        findings.extend(self._r8_2_6_account_lockout(data))
        findings.extend(self._r8_2_8_session_timeout(data))
        findings.extend(self._r8_3_1_mfa(data))
        findings.extend(self._r8_3_6_password_strength(data))
        findings.extend(self._r8_3_9_password_expiry(data))
        return findings

    # ── 7.2.1: RBAC (groups) ──────────────────────────────────────

    def _r7_2_1_rbac(self, data: GWSData) -> list[ComplianceFinding]:
        group_count = len(data.groups)

        if group_count > 0:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="7.2.1",
                title="Role-Based Access Control",
                severity="info",
                status="pass",
                comments=(
                    f"{group_count} group(s) configured for role-based access control. "
                    "Verify access is restricted based on job classification and function."
                ),
                details={"group_count": group_count},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="7.2.1",
            title="Role-Based Access Control",
            severity="medium",
            status="fail",
            comments=(
                "No groups found. PCI-DSS 7.2.1 requires access control systems that "
                "restrict access based on a user's need to know. "
                "Create Google Groups to implement role-based access."
            ),
            details={"group_count": 0},
        )]

    # ── 8.2.1: Strong authentication (2SV enforcement) ────────────

    def _r8_2_1_strong_auth(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="8.2.1",
                title="Strong Authentication",
                severity="info",
                status="pass",
                comments=(
                    "2-Step Verification is enforced, providing strong authentication "
                    "per PCI-DSS 8.2.1."
                ),
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="8.2.1",
            title="Strong Authentication",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "PCI-DSS 8.2.1 requires strong authentication for all users."
            ),
            details={},
        )]

    # ── 8.2.6: Account lockout (manual) ───────────────────────────

    def _r8_2_6_account_lockout(self, _data: GWSData) -> list[ComplianceFinding]:
        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="8.2.6",
            title="Account Lockout",
            severity="info",
            status="manual",
            comments=(
                "Google Workspace enforces account lockout after repeated failed login "
                "attempts by default (managed by Google, not configurable). "
                "Verify this meets PCI-DSS requirement of lockout after no more than "
                "10 invalid access attempts."
            ),
            details={},
        )]

    # ── 8.2.8: Session timeout (<=15 min) ─────────────────────────

    def _r8_2_8_session_timeout(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        session_policies = analyze_session_policies(data)

        for policy in session_policies:
            # PCI-DSS 8.2.8 requires session timeout after no more than 15 minutes
            # of inactivity.  GWS session duration is the closest configurable proxy.
            # We check against a very strict threshold: session duration in hours
            # that maps closest to 15 min idle is not directly available; we use
            # a practical limit of 1 hour for the web session itself.
            max_hours = 1
            if policy.session_duration_hours <= max_hours:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.2.8",
                    title="Session Idle Timeout",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h. "
                        "PCI-DSS requires idle timeout of 15 minutes or less."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                        "pci_max_idle_minutes": 15,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.2.8",
                    title="Session Idle Timeout",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Session duration for OU '{policy.org_unit}' is "
                        f"{policy.session_duration_hours}h. "
                        "PCI-DSS 8.2.8 requires session idle timeout of no more than "
                        "15 minutes. Google Workspace session duration should be minimized, "
                        "and endpoint-level screen lock should enforce the 15-minute idle limit."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "session_duration_hours": policy.session_duration_hours,
                        "pci_max_idle_minutes": 15,
                    },
                ))

        return findings

    # ── 8.3.1: MFA ────────────────────────────────────────────────

    def _r8_3_1_mfa(self, data: GWSData) -> list[ComplianceFinding]:
        enforced = is_2sv_enforced(data)

        if enforced:
            return [ComplianceFinding(
                framework=_FRAMEWORK,
                control_id="8.3.1",
                title="Multi-Factor Authentication",
                severity="info",
                status="pass",
                comments="MFA is enforced via 2-Step Verification per PCI-DSS 8.3.1.",
                details={},
            )]

        return [ComplianceFinding(
            framework=_FRAMEWORK,
            control_id="8.3.1",
            title="Multi-Factor Authentication",
            severity="critical",
            status="fail",
            comments=(
                "2-Step Verification is not enforced. "
                "PCI-DSS 8.3.1 requires MFA for all access into the CDE."
            ),
            details={},
        )]

    # ── 8.3.6: Password strength (min 12 + strong) ───────────────

    def _r8_3_6_password_strength(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            issues: list[str] = []
            if policy.min_length < 12:
                issues.append(f"Minimum length is {policy.min_length} (PCI-DSS requires >= 12)")
            if not policy.enforce_strong_password:
                issues.append("Strong password enforcement is disabled")

            if not issues:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.3.6",
                    title="Password Strength",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' meets PCI-DSS 8.3.6 "
                        f"requirements (min length: {policy.min_length}, strong passwords enforced)."
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
                    control_id="8.3.6",
                    title="Password Strength",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password policy for OU '{policy.org_unit}' does not meet "
                        f"PCI-DSS 8.3.6 requirements: {'; '.join(issues)}."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "min_length": policy.min_length,
                        "enforce_strong_password": policy.enforce_strong_password,
                        "issues": issues,
                    },
                ))

        return findings

    # ── 8.3.9: Password expiry (<=90 days) ────────────────────────

    def _r8_3_9_password_expiry(self, data: GWSData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        policies = analyze_password_policies(data)

        for policy in policies:
            # expiration_days == 0 means passwords never expire
            if 0 < policy.expiration_days <= 90:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.3.9",
                    title="Password Expiry",
                    severity="info",
                    status="pass",
                    comments=(
                        f"Password expiry for OU '{policy.org_unit}' is set to "
                        f"{policy.expiration_days} days (PCI-DSS max: 90 days)."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "expiration_days": policy.expiration_days,
                    },
                ))
            elif policy.expiration_days == 0:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.3.9",
                    title="Password Expiry",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Passwords never expire for OU '{policy.org_unit}'. "
                        "PCI-DSS 8.3.9 requires password changes at least every 90 days."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "expiration_days": 0,
                        "pci_max_days": 90,
                    },
                ))
            else:
                findings.append(ComplianceFinding(
                    framework=_FRAMEWORK,
                    control_id="8.3.9",
                    title="Password Expiry",
                    severity="high",
                    status="fail",
                    comments=(
                        f"Password expiry for OU '{policy.org_unit}' is "
                        f"{policy.expiration_days} days, exceeding PCI-DSS maximum of 90 days."
                    ),
                    details={
                        "org_unit": policy.org_unit,
                        "expiration_days": policy.expiration_days,
                        "pci_max_days": 90,
                    },
                ))

        return findings
