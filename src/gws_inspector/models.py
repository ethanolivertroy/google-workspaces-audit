"""Data models for gws-inspector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ComplianceFinding:
    """A single compliance finding from a framework analyzer."""

    framework: str
    control_id: str
    title: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    status: str  # "pass" | "fail" | "manual" | "not_applicable" | "error"
    comments: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GWSData:
    """Container for all collected Google Workspace API data.

    Populated by GWSDataCollector and passed to every analyzer.
    Analyzers must never read from disk — this object IS the data bus.

    Key difference from OktaData: Google Workspace policies are per-OU,
    so policy fields store lists of per-OU policy dicts.
    """

    domain: str
    admin_email: str = ""

    # ── Directory API ──────────────────────────────────────────────
    users: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    group_members: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    org_units: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    role_assignments: list[dict[str, Any]] = field(default_factory=list)
    domains: list[dict[str, Any]] = field(default_factory=list)
    mobile_devices: list[dict[str, Any]] = field(default_factory=list)
    customer: dict[str, Any] = field(default_factory=dict)

    # ── Reports API ────────────────────────────────────────────────
    admin_activities: list[dict[str, Any]] = field(default_factory=list)
    login_activities: list[dict[str, Any]] = field(default_factory=list)
    drive_activities: list[dict[str, Any]] = field(default_factory=list)
    token_activities: list[dict[str, Any]] = field(default_factory=list)
    usage_reports: list[dict[str, Any]] = field(default_factory=list)

    # ── Policy API (GA Feb 2025) ───────────────────────────────────
    two_step_verification_policies: list[dict[str, Any]] = field(default_factory=list)
    password_policies: list[dict[str, Any]] = field(default_factory=list)
    session_policies: list[dict[str, Any]] = field(default_factory=list)
    advanced_protection_policies: list[dict[str, Any]] = field(default_factory=list)
    less_secure_apps_policies: list[dict[str, Any]] = field(default_factory=list)
    sso_policies: list[dict[str, Any]] = field(default_factory=list)
    login_challenge_policies: list[dict[str, Any]] = field(default_factory=list)

    # ── Alert Center API ───────────────────────────────────────────
    alerts: list[dict[str, Any]] = field(default_factory=list)

    # ── Chrome Policy API ──────────────────────────────────────────
    chrome_policies: list[dict[str, Any]] = field(default_factory=list)

    # ── Cloud Identity Devices API ─────────────────────────────────
    devices: list[dict[str, Any]] = field(default_factory=list)

    # ── Derived (populated during collection) ──────────────────────
    super_admins: list[dict[str, Any]] = field(default_factory=list)
    delegated_admins: list[dict[str, Any]] = field(default_factory=list)


# ---------- Intermediate analysis types ----------


@dataclass
class TwoSVAnalysis:
    """Structured result from 2-Step Verification policy analysis."""

    org_unit: str
    enforcement_level: str  # "off" | "optional" | "enforced"
    allowed_methods: list[str] = field(default_factory=list)
    grace_period_days: int | None = None
    new_user_enrollment_days: int | None = None


@dataclass
class PasswordPolicyAnalysis:
    """Structured result from GWS password policy analysis."""

    org_unit: str
    min_length: int = 8
    max_length: int = 100
    enforce_strong_password: bool = False
    allow_password_reuse: bool = True
    expiration_days: int = 0  # 0 = never
    enforce_on_next_login: bool = False

    @property
    def meets_complexity(self) -> bool:
        return self.enforce_strong_password and self.min_length >= 12


@dataclass
class SessionPolicyAnalysis:
    """Web session duration per OU."""

    org_unit: str
    session_duration_hours: int = 14  # Google default is 14 days (336 hours)


@dataclass
class AdminAnalysis:
    """Admin privilege analysis results."""

    super_admin_count: int = 0
    super_admin_users: list[dict[str, Any]] = field(default_factory=list)
    delegated_admin_count: int = 0
    total_admins: int = 0
    admin_to_user_ratio: float = 0.0


@dataclass
class UserAnalysis:
    """User management analysis."""

    total_users: int = 0
    active_users: int = 0
    suspended_users: int = 0
    archived_users: int = 0
    inactive_users: list[dict[str, Any]] = field(default_factory=list)
    users_without_2sv: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MonitoringAnalysis:
    """Audit logging and alerting analysis."""

    admin_audit_events: int = 0
    login_audit_events: int = 0
    drive_audit_events: int = 0
    token_audit_events: int = 0
    active_alerts: list[dict[str, Any]] = field(default_factory=list)
    alert_types: dict[str, int] = field(default_factory=dict)
    has_audit_logging: bool = False


@dataclass
class DeviceAnalysis:
    """Endpoint management analysis."""

    total_devices: int = 0
    managed_devices: int = 0
    unmanaged_devices: int = 0


@dataclass
class AuditResult:
    """Final result of a complete audit run."""

    findings: list[ComplianceFinding]
    data: GWSData
    api_call_count: int
    timestamp: str
    domain: str
