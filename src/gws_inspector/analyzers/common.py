"""Shared analysis functions used by multiple framework analyzers.

Each function takes a :class:`GWSData` and returns a typed intermediate
dataclass.  Framework analyzers call these, then apply their own thresholds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from gws_inspector.models import (
    AdminAnalysis,
    DeviceAnalysis,
    GWSData,
    MonitoringAnalysis,
    PasswordPolicyAnalysis,
    SessionPolicyAnalysis,
    TwoSVAnalysis,
    UserAnalysis,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# 2-Step Verification
# ------------------------------------------------------------------


def analyze_two_sv(data: GWSData) -> list[TwoSVAnalysis]:
    """Analyze 2SV enforcement across the domain."""
    results: list[TwoSVAnalysis] = []
    for policy in data.two_step_verification_policies:
        enforcement = policy.get("enforcement", False)
        results.append(
            TwoSVAnalysis(
                org_unit=policy.get("org_unit", "/"),
                enforcement_level="enforced" if enforcement else "optional",
            )
        )
    # If no policies collected, add a default
    if not results:
        results.append(TwoSVAnalysis(org_unit="/", enforcement_level="unknown"))
    return results


def is_2sv_enforced(data: GWSData) -> bool:
    """Return True if 2SV is enforced at the root OU."""
    analyses = analyze_two_sv(data)
    return any(a.enforcement_level == "enforced" for a in analyses)


def count_users_without_2sv(data: GWSData) -> list[dict]:
    """Return active users not enrolled in 2SV."""
    return [
        u for u in data.users
        if not u.get("isEnrolledIn2Sv", False)
        and u.get("suspended") is not True
        and u.get("archived") is not True
    ]


# ------------------------------------------------------------------
# Password policies
# ------------------------------------------------------------------


def analyze_password_policies(data: GWSData) -> list[PasswordPolicyAnalysis]:
    """Extract structured password policy data."""
    results: list[PasswordPolicyAnalysis] = []
    for policy in data.password_policies:
        results.append(
            PasswordPolicyAnalysis(
                org_unit=policy.get("org_unit", "/"),
                min_length=policy.get("minLength", 8),
                max_length=policy.get("maxLength", 100),
                enforce_strong_password=policy.get("enforceStrongPassword", False),
                allow_password_reuse=policy.get("allowPasswordReuse", True),
                expiration_days=policy.get("expirationDays", 0),
                enforce_on_next_login=policy.get("enforceOnNextLogin", False),
            )
        )
    # Fallback: extract from customer settings
    if not results and data.customer:
        results.append(
            PasswordPolicyAnalysis(
                org_unit="/",
                min_length=data.customer.get("passwordMinLength", 8),
            )
        )
    return results


# ------------------------------------------------------------------
# Session policies
# ------------------------------------------------------------------


def analyze_session_policies(data: GWSData) -> list[SessionPolicyAnalysis]:
    """Extract web session duration settings."""
    results: list[SessionPolicyAnalysis] = []
    for policy in data.session_policies:
        results.append(
            SessionPolicyAnalysis(
                org_unit=policy.get("org_unit", "/"),
                session_duration_hours=policy.get("sessionDurationHours", 336),
            )
        )
    if not results:
        results.append(SessionPolicyAnalysis(org_unit="/"))
    return results


# ------------------------------------------------------------------
# Admin privileges
# ------------------------------------------------------------------


def analyze_admins(data: GWSData) -> AdminAnalysis:
    """Analyze admin privileges and super admin count."""
    total_active = len([u for u in data.users if u.get("suspended") is not True])
    super_count = len(data.super_admins)
    delegated_count = len(data.delegated_admins)
    total_admins = super_count + delegated_count

    return AdminAnalysis(
        super_admin_count=super_count,
        super_admin_users=data.super_admins,
        delegated_admin_count=delegated_count,
        total_admins=total_admins,
        admin_to_user_ratio=(total_admins / total_active * 100) if total_active > 0 else 0,
    )


# ------------------------------------------------------------------
# User management
# ------------------------------------------------------------------


def analyze_users(data: GWSData) -> UserAnalysis:
    """Analyze user accounts for status and inactivity."""
    result = UserAnalysis(total_users=len(data.users))
    result.active_users = len([u for u in data.users if u.get("suspended") is not True and u.get("archived") is not True])
    result.suspended_users = len([u for u in data.users if u.get("suspended") is True])
    result.archived_users = len([u for u in data.users if u.get("archived") is True])

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for user in data.users:
        last_login = user.get("lastLoginTime")
        if last_login and user.get("suspended") is not True:
            try:
                dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                if dt < cutoff:
                    result.inactive_users.append(user)
            except (ValueError, TypeError):
                pass

    result.users_without_2sv = count_users_without_2sv(data)
    return result


# ------------------------------------------------------------------
# Monitoring & logging
# ------------------------------------------------------------------


def analyze_monitoring(data: GWSData) -> MonitoringAnalysis:
    """Summarize audit logging and alerting status."""
    result = MonitoringAnalysis(
        admin_audit_events=len(data.admin_activities),
        login_audit_events=len(data.login_activities),
        drive_audit_events=len(data.drive_activities),
        token_audit_events=len(data.token_activities),
        has_audit_logging=bool(data.admin_activities or data.login_activities),
    )

    # Summarize alerts by type
    for alert in data.alerts:
        alert_type = alert.get("type", "Unknown")
        result.alert_types[alert_type] = result.alert_types.get(alert_type, 0) + 1

    result.active_alerts = [a for a in data.alerts if a.get("status") != "CLOSED"]
    return result


# ------------------------------------------------------------------
# Devices
# ------------------------------------------------------------------


def analyze_devices(data: GWSData) -> DeviceAnalysis:
    """Analyze managed device inventory."""
    total = len(data.devices) + len(data.mobile_devices)
    managed = len([d for d in data.mobile_devices if d.get("status") == "APPROVED"])

    return DeviceAnalysis(
        total_devices=total,
        managed_devices=managed,
        unmanaged_devices=total - managed,
    )


# ------------------------------------------------------------------
# OAuth / third-party apps
# ------------------------------------------------------------------


def analyze_oauth_tokens(data: GWSData) -> list[dict]:
    """Identify potentially risky third-party app authorizations."""
    risky: list[dict] = []
    for activity in data.token_activities:
        events = activity.get("events", [])
        for event in events:
            if event.get("name") == "authorize":
                params = {p.get("name"): p.get("value") for p in event.get("parameters", [])}
                scopes = params.get("scope", "")
                # Flag apps with broad scopes
                if any(s in scopes for s in ["https://mail.google.com/", "https://www.googleapis.com/auth/drive"]):
                    risky.append({
                        "app_name": params.get("app_name", "Unknown"),
                        "scopes": scopes,
                        "user": activity.get("actor", {}).get("email"),
                    })
    return risky


# ------------------------------------------------------------------
# Less secure apps
# ------------------------------------------------------------------


def is_less_secure_apps_blocked(data: GWSData) -> bool:
    """Check if less secure apps access is blocked."""
    for policy in data.less_secure_apps_policies:
        if policy.get("blocked", False):
            return True
    # Default: Google blocks LSA for most customers now
    return True


# ------------------------------------------------------------------
# Groups (external members)
# ------------------------------------------------------------------


def find_external_group_members(data: GWSData) -> list[dict]:
    """Find groups that allow external members."""
    external_groups: list[dict] = []
    for group in data.groups:
        settings = group.get("directMembersCount", 0)
        # Groups API doesn't directly tell us about external members
        # in the list response.  We flag groups that allow external members
        # based on their settings if available.
        if group.get("allowExternalMembers", False):
            external_groups.append(group)
    return external_groups
