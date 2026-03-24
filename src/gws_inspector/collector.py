"""Google Workspace data collector — queries all APIs into GWSData."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from gws_inspector.client import GWSClient
from gws_inspector.models import GWSData

logger = logging.getLogger(__name__)

# Role ID for the built-in Super Admin role
_SUPER_ADMIN_ROLE_ID = "13801188331880449"


class GWSDataCollector:
    """Queries Google Workspace APIs and populates a :class:`GWSData` object."""

    def __init__(self, client: GWSClient) -> None:
        self._client = client

    def collect(self) -> GWSData:
        """Run all data retrieval and return a populated GWSData."""
        data = GWSData(domain=self._client.domain, admin_email=self._client.admin_email)

        self._collect_customer(data)
        self._collect_directory(data)
        self._collect_admin_privileges(data)
        self._collect_policies(data)
        self._collect_audit_logs(data)
        self._collect_alerts(data)
        self._collect_devices(data)
        self._collect_chrome_policies(data)

        return data

    # ------------------------------------------------------------------
    # Section collectors
    # ------------------------------------------------------------------

    def _collect_customer(self, data: GWSData) -> None:
        logger.info("Retrieving customer information...")
        result = self._client.execute_single(
            self._client.directory.customers().get(customerKey="my_customer")
        )
        if result:
            data.customer = result

    def _collect_directory(self, data: GWSData) -> None:
        logger.info("Retrieving users...")
        svc = self._client.directory
        data.users = self._client.paginate(
            svc.users().list(customer="my_customer", maxResults=500, projection="full"),
            "users",
            list_next_fn=svc.users().list_next,
        )

        logger.info("Retrieving groups...")
        data.groups = self._client.paginate(
            svc.groups().list(customer="my_customer", maxResults=200),
            "groups",
            list_next_fn=svc.groups().list_next,
        )

        logger.info("Retrieving organizational units...")
        result = self._client.execute_single(
            svc.orgunits().list(customerId="my_customer", type="all")
        )
        data.org_units = result.get("organizationUnits", []) if result else []

        logger.info("Retrieving domains...")
        result = self._client.execute_single(
            svc.domains().list(customer="my_customer")
        )
        data.domains = result.get("domains", []) if result else []

        logger.info("Retrieving roles...")
        result = self._client.execute_single(
            svc.roles().list(customer="my_customer")
        )
        data.roles = result.get("items", []) if result else []

        logger.info("Retrieving mobile devices...")
        data.mobile_devices = self._client.paginate(
            svc.mobiledevices().list(customerId="my_customer", maxResults=100),
            "mobiledevices",
            list_next_fn=svc.mobiledevices().list_next,
            max_pages=5,
        )

    def _collect_admin_privileges(self, data: GWSData) -> None:
        logger.info("Retrieving role assignments...")
        svc = self._client.directory
        result = self._client.execute_single(
            svc.roleAssignments().list(customer="my_customer", maxResults=200)
        )
        data.role_assignments = result.get("items", []) if result else []

        # Identify super admins
        super_admin_ids = {
            ra.get("assignedTo")
            for ra in data.role_assignments
            if ra.get("roleId") == _SUPER_ADMIN_ROLE_ID
        }
        data.super_admins = [u for u in data.users if u.get("id") in super_admin_ids]
        data.delegated_admins = [
            u for u in data.users
            if u.get("isAdmin") and u.get("id") not in super_admin_ids
        ]

    def _collect_policies(self, data: GWSData) -> None:
        """Collect security policies via the Policy API.

        The Policy API exposes settings per-OU.  For this initial version we
        collect top-level (root OU) policies.  Per-OU collection can be added
        later by iterating ``data.org_units``.
        """
        logger.info("Retrieving security policies (Policy API)...")
        # NOTE: The Policy API is accessed via different endpoints depending
        # on the exact setting.  For v0.0.1, we collect what's available via
        # the customer resource and fall back gracefully.
        #
        # When the Policy API has stable Python SDK support, this section
        # will be expanded.  For now, we extract what we can from the
        # Directory API's customer and user objects.

        # Extract 2SV enforcement from customer settings
        customer = data.customer
        if customer:
            two_sv = {
                "org_unit": "/",
                "enforcement": customer.get("twoStepVerificationEnforced", False),
            }
            data.two_step_verification_policies = [two_sv]

        # Extract per-user 2SV enrollment status
        for user in data.users:
            if not user.get("isEnrolledIn2Sv", False) and user.get("suspended") is not True:
                pass  # Tracked in analysis, not collection

    def _collect_audit_logs(self, data: GWSData) -> None:
        logger.info("Retrieving audit logs...")
        svc = self._client.reports
        since = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for app_name, attr in [
            ("admin", "admin_activities"),
            ("login", "login_activities"),
            ("drive", "drive_activities"),
            ("token", "token_activities"),
        ]:
            logger.info("  Retrieving %s activities...", app_name)
            try:
                items = self._client.paginate(
                    svc.activities().list(
                        userKey="all",
                        applicationName=app_name,
                        startTime=since,
                        maxResults=200,
                    ),
                    "items",
                    list_next_fn=svc.activities().list_next,
                    max_pages=3,
                )
                setattr(data, attr, items)
            except Exception as e:
                logger.warning("Could not retrieve %s activities: %s", app_name, e)

    def _collect_alerts(self, data: GWSData) -> None:
        logger.info("Retrieving Alert Center alerts...")
        try:
            items = self._client.paginate(
                self._client.alertcenter.alerts().list(pageSize=100),
                "alerts",
                max_pages=3,
            )
            data.alerts = items
        except Exception as e:
            logger.warning("Could not retrieve alerts: %s", e)

    def _collect_devices(self, data: GWSData) -> None:
        logger.info("Retrieving managed devices...")
        try:
            items = self._client.paginate(
                self._client.cloudidentity.devices().list(
                    customer=f"customers/{data.customer.get('id', 'my_customer')}",
                    pageSize=100,
                ),
                "devices",
                max_pages=5,
            )
            data.devices = items
        except Exception as e:
            logger.warning("Could not retrieve devices: %s", e)

    def _collect_chrome_policies(self, data: GWSData) -> None:
        logger.info("Retrieving Chrome browser policies...")
        try:
            # Resolve policies for the root OU
            result = self._client.execute_single(
                self._client.chromepolicy.customers()
                .policies()
                .resolve(
                    customer=f"customers/{data.customer.get('id', 'my_customer')}",
                    body={
                        "policyTargetKey": {"targetResource": "orgunits/"},
                        "pageSize": 100,
                    },
                )
            )
            data.chrome_policies = result.get("resolvedPolicies", []) if result else []
        except Exception as e:
            logger.warning("Could not retrieve Chrome policies: %s", e)
