"""Tests for data models."""

from gws_inspector.models import (
    ComplianceFinding,
    GWSData,
    PasswordPolicyAnalysis,
    TwoSVAnalysis,
)


def test_compliance_finding_to_dict():
    f = ComplianceFinding(
        framework="FedRAMP",
        control_id="IA-2",
        title="MFA enforcement",
        severity="high",
        status="pass",
        comments="2SV is enforced",
        details={"enforced": True},
    )
    d = f.to_dict()
    assert d["framework"] == "FedRAMP"
    assert d["details"]["enforced"] is True


def test_gws_data_defaults():
    data = GWSData(domain="test.com")
    assert data.users == []
    assert data.super_admins == []
    assert data.domain == "test.com"


def test_password_policy_meets_complexity():
    pp = PasswordPolicyAnalysis(
        org_unit="/",
        min_length=12,
        enforce_strong_password=True,
    )
    assert pp.meets_complexity is True

    pp2 = PasswordPolicyAnalysis(
        org_unit="/",
        min_length=8,
        enforce_strong_password=False,
    )
    assert pp2.meets_complexity is False


def test_two_sv_analysis():
    a = TwoSVAnalysis(org_unit="/", enforcement_level="enforced")
    assert a.enforcement_level == "enforced"
