"""Tests for shared analysis functions."""

from gws_inspector.analyzers.common import (
    analyze_admins,
    analyze_monitoring,
    analyze_users,
    count_users_without_2sv,
    is_2sv_enforced,
    is_less_secure_apps_blocked,
)
from gws_inspector.models import GWSData


def test_is_2sv_enforced(sample_gws_data: GWSData):
    assert is_2sv_enforced(sample_gws_data) is True


def test_count_users_without_2sv(sample_gws_data: GWSData):
    without = count_users_without_2sv(sample_gws_data)
    # carol (u3) is active but not enrolled; dave (u4) is suspended so excluded
    assert len(without) == 1
    assert without[0]["primaryEmail"] == "carol@acme-corp.com"


def test_analyze_admins(sample_gws_data: GWSData):
    result = analyze_admins(sample_gws_data)
    assert result.super_admin_count == 1
    assert result.delegated_admin_count == 0
    assert result.total_admins == 1


def test_analyze_users(sample_gws_data: GWSData):
    result = analyze_users(sample_gws_data)
    assert result.total_users == 4
    assert result.active_users == 3  # alice, bob, carol (dave is suspended)
    assert result.suspended_users == 1
    # bob logged in Oct 2025, >90 days before March 2026
    assert len(result.inactive_users) >= 1
    assert len(result.users_without_2sv) == 1


def test_analyze_monitoring(sample_gws_data: GWSData):
    result = analyze_monitoring(sample_gws_data)
    assert result.admin_audit_events == 1
    assert result.login_audit_events == 2
    assert result.has_audit_logging is True
    assert len(result.active_alerts) == 1


def test_is_less_secure_apps_blocked(sample_gws_data: GWSData):
    assert is_less_secure_apps_blocked(sample_gws_data) is True
