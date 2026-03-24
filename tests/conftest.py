"""Shared test fixtures — mock GWSData for analyzer and reporter tests."""

from __future__ import annotations

import pytest

from gws_inspector.models import GWSData


@pytest.fixture
def minimal_gws_data() -> GWSData:
    """Bare-minimum GWSData for smoke tests."""
    return GWSData(domain="test.example.com")


@pytest.fixture
def sample_gws_data() -> GWSData:
    """Realistic GWSData with representative test data."""
    return GWSData(
        domain="acme-corp.com",
        admin_email="admin@acme-corp.com",
        customer={
            "id": "C01234567",
            "customerDomain": "acme-corp.com",
            "kind": "admin#directory#customer",
            "twoStepVerificationEnforced": True,
            "passwordMinLength": 12,
        },
        users=[
            {
                "id": "u1",
                "primaryEmail": "alice@acme-corp.com",
                "suspended": False,
                "archived": False,
                "isAdmin": True,
                "isEnrolledIn2Sv": True,
                "lastLoginTime": "2026-03-20T10:00:00Z",
            },
            {
                "id": "u2",
                "primaryEmail": "bob@acme-corp.com",
                "suspended": False,
                "archived": False,
                "isAdmin": False,
                "isEnrolledIn2Sv": True,
                "lastLoginTime": "2025-10-01T10:00:00Z",  # >90 days ago
            },
            {
                "id": "u3",
                "primaryEmail": "carol@acme-corp.com",
                "suspended": False,
                "archived": False,
                "isAdmin": False,
                "isEnrolledIn2Sv": False,
                "lastLoginTime": "2026-03-22T08:00:00Z",
            },
            {
                "id": "u4",
                "primaryEmail": "dave@acme-corp.com",
                "suspended": True,
                "archived": False,
                "isAdmin": False,
                "isEnrolledIn2Sv": False,
                "lastLoginTime": None,
            },
        ],
        groups=[
            {"id": "g1", "name": "All Staff", "email": "all@acme-corp.com"},
            {"id": "g2", "name": "Engineering", "email": "eng@acme-corp.com"},
            {"id": "g3", "name": "IT Admins", "email": "it-admins@acme-corp.com"},
        ],
        org_units=[
            {"orgUnitPath": "/", "name": "acme-corp.com"},
            {"orgUnitPath": "/Engineering", "name": "Engineering"},
        ],
        roles=[
            {"roleId": "13801188331880449", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True},
        ],
        role_assignments=[
            {"roleId": "13801188331880449", "assignedTo": "u1"},
        ],
        domains=[
            {"domainName": "acme-corp.com", "isPrimary": True, "verified": True},
        ],
        super_admins=[
            {"id": "u1", "primaryEmail": "alice@acme-corp.com", "isAdmin": True},
        ],
        delegated_admins=[],
        two_step_verification_policies=[
            {"org_unit": "/", "enforcement": True},
        ],
        password_policies=[
            {
                "org_unit": "/",
                "minLength": 10,
                "enforceStrongPassword": True,
                "allowPasswordReuse": False,
                "expirationDays": 90,
            },
        ],
        session_policies=[
            {"org_unit": "/", "sessionDurationHours": 12},
        ],
        admin_activities=[
            {"id": {"time": "2026-03-23T10:00:00Z"}, "events": [{"name": "CREATE_USER"}]},
        ],
        login_activities=[
            {"id": {"time": "2026-03-23T08:00:00Z"}, "events": [{"name": "login_success"}]},
            {"id": {"time": "2026-03-23T09:00:00Z"}, "events": [{"name": "login_success"}]},
        ],
        drive_activities=[],
        token_activities=[],
        alerts=[
            {"type": "Phishing", "status": "ACTIVE", "createTime": "2026-03-22T00:00:00Z"},
        ],
        mobile_devices=[
            {"resourceId": "d1", "status": "APPROVED", "type": "ANDROID"},
        ],
        devices=[],
        less_secure_apps_policies=[{"blocked": True}],
    )
