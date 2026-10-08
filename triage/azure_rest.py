"""Minimal Azure Resource Manager client for the Sentinel REST APIs the SDKs don't cover
(incidents, comments, watchlists). Auth: DefaultAzureCredential."""

from __future__ import annotations

import time
from typing import Any

import requests

ARM = "https://management.azure.com"
SENTINEL_API = "2024-03-01"


class ArmError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"ARM request failed ({status}): {body[:500]}")
        self.status = status


class ArmClient:
    def __init__(self, credential=None, session: requests.Session | None = None, api_version: str = SENTINEL_API):
        if credential is None:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self.credential = credential
        self.session = session or requests.Session()
        self.api_version = api_version
        self._token: Any = None

    def _auth(self) -> str:
        if self._token is None or self._token.expires_on - 120 < time.time():
            self._token = self.credential.get_token(f"{ARM}/.default")
        return f"Bearer {self._token.token}"

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, params: dict[str, str] | None = None,
                ok: tuple[int, ...] = (200, 201, 202, 204)) -> dict[str, Any]:
        url = path if path.startswith("http") else ARM + path
        query = {"api-version": self.api_version, **(params or {})} if "api-version=" not in url else params
        for attempt in range(4):
            resp = self.session.request(method, url, json=body, params=query, timeout=30,
                                        headers={"Authorization": self._auth()})
            if resp.status_code == 429 or resp.status_code >= 500:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            break
        if resp.status_code not in ok:
            raise ArmError(resp.status_code, resp.text)
        return resp.json() if resp.content else {}

    def list(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = self.request("GET", path, params=params)
        items.extend(page.get("value", []))
        while page.get("nextLink"):
            page = self.request("GET", page["nextLink"])
            items.extend(page.get("value", []))
        return items
