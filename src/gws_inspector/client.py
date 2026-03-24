"""Google Workspace API client — wraps multiple service objects with pagination and rate limiting."""

from __future__ import annotations

import logging
import time
from typing import Any

from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class GWSClient:
    """Wraps multiple Google API service objects behind a unified interface.

    Each Google API requires a separate ``build()`` call.  This class:
    - Lazily builds and caches service objects on first use
    - Tracks API call count across all services
    - Handles Google API pagination (``pageToken`` pattern)
    - Handles rate-limit backoff (``HttpError`` 429)
    """

    def __init__(self, credentials: Any, domain: str, admin_email: str) -> None:
        self._credentials = credentials
        self.domain = domain
        self.admin_email = admin_email
        self._services: dict[str, Resource] = {}
        self.api_call_count = 0

    # ------------------------------------------------------------------
    # Service accessors (lazy build + cache)
    # ------------------------------------------------------------------

    def _get_service(self, api: str, version: str) -> Resource:
        key = f"{api}:{version}"
        if key not in self._services:
            self._services[key] = build(api, version, credentials=self._credentials)
        return self._services[key]

    @property
    def directory(self) -> Resource:
        return self._get_service("admin", "directory_v1")

    @property
    def reports(self) -> Resource:
        return self._get_service("admin", "reports_v1")

    @property
    def alertcenter(self) -> Resource:
        return self._get_service("alertcenter", "v1beta1")

    @property
    def cloudidentity(self) -> Resource:
        return self._get_service("cloudidentity", "v1")

    @property
    def chromepolicy(self) -> Resource:
        return self._get_service("chromepolicy", "v1")

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def paginate(
        self,
        request: Any,
        items_key: str,
        *,
        max_pages: int = 10,
        list_next_fn: Any = None,
    ) -> list[dict[str, Any]]:
        """Generic Google API paginator.

        Google APIs use the same pattern:
        1. Execute request → get response
        2. Extract items from ``response[items_key]``
        3. Call ``list_next(request, response)`` to get next page
        """
        all_items: list[dict[str, Any]] = []
        page_count = 0

        while request is not None and page_count < max_pages:
            page_count += 1
            self.api_call_count += 1

            try:
                response = request.execute()
            except HttpError as e:
                if e.resp.status == 429:
                    self._handle_rate_limit(e, page_count)
                    continue
                logger.error("API error: %s", e)
                break

            items = response.get(items_key, [])
            if isinstance(items, list):
                all_items.extend(items)
            elif isinstance(items, dict):
                all_items.append(items)

            # Get next page
            if list_next_fn is not None:
                request = list_next_fn(request, response)
            else:
                # Try standard list_next on the parent resource
                request = None

        return all_items

    def execute_single(self, request: Any) -> dict[str, Any] | None:
        """Execute a single (non-paginated) API request."""
        self.api_call_count += 1
        try:
            return request.execute()
        except HttpError as e:
            if e.resp.status == 429:
                self._handle_rate_limit(e, 1)
                try:
                    return request.execute()
                except HttpError:
                    pass
            logger.error("API error: %s", e)
            return None

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    def test_connection(self) -> bool:
        """Quick smoke test — fetch customer info."""
        logger.info("Testing API connection...")
        try:
            result = self.execute_single(
                self.directory.customers().get(customerKey="my_customer")
            )
            if result:
                logger.info("API connection successful! Customer: %s", result.get("customerDomain"))
                return True
            logger.error("API connection failed — no data returned")
            return False
        except Exception as e:
            logger.error("API connection failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_rate_limit(error: HttpError, attempt: int) -> None:
        retry_after = error.resp.get("Retry-After")
        if retry_after:
            wait = int(retry_after)
        else:
            wait = min(2**attempt, 60)
        logger.warning("Rate limit hit. Waiting %d seconds...", wait)
        time.sleep(wait)
