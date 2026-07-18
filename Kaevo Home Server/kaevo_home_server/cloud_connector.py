from __future__ import annotations

from typing import Any

import httpx

from .cloud_commands import CloudCommand, CloudCommandExecutor
from .connector_identity import ConnectorIdentity


class CloudControlPlaneClient:
    """Outbound-only Cloud client. This client never sends media or local secrets."""

    def __init__(
        self,
        *,
        base_url: str,
        connector_id: str,
        profile_id: str,
        connector_token: str = "",
        connector_identity: ConnectorIdentity | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.connector_id = connector_id
        self.profile_id = profile_id
        self.connector_token = connector_token
        self.connector_identity = connector_identity
        self.transport = transport

    @classmethod
    async def exchange_pairing(
        cls,
        *,
        base_url: str,
        connector_id: str,
        pairing_code: str,
        connector_identity: ConnectorIdentity | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(transport=transport, timeout=15.0, follow_redirects=False) as client:
            path = "/v2/home-connectors/pairing/exchange" if connector_identity else "/v1/home-connectors/pairing/exchange"
            url = f"{base_url.rstrip('/')}{path}"
            response = await client.post(
                url,
                headers={"DPoP": connector_identity.proof("POST", url)} if connector_identity else None,
                json={
                    "connector_id": connector_id,
                    "pairing_code": pairing_code,
                    **({"public_jwk": connector_identity.public_jwk} if connector_identity else {}),
                },
            )
        response.raise_for_status()
        return response.json()

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json"}
        if self.connector_identity:
            headers["DPoP"] = self.connector_identity.proof("POST", url)
        elif self.connector_token:
            headers["Authorization"] = f"Bearer {self.connector_token}"
        async with httpx.AsyncClient(transport=self.transport, timeout=15.0, follow_redirects=False) as client:
            response = await client.post(url, headers=headers, json=body)
        response.raise_for_status()
        return response.json()

    async def register(self, *, app_version: str, capabilities: list[str]) -> dict[str, Any]:
        return await self._post(
            "/v1/home-connectors/register",
            {
                "connector_id": self.connector_id,
                "profile_id": self.profile_id,
                "connector_name": "Kaevo Home Server",
                "host_type": "home_server",
                "app_version": app_version,
                "capabilities": capabilities,
                "provider_status": {},
            },
        )

    async def heartbeat(self, *, provider_status: dict[str, str]) -> dict[str, Any]:
        safe_status = {
            str(name): str(state)
            for name, state in provider_status.items()
            if name in {"jellyfin", "seerr", "optimizer", "playback_tunnel"}
            and state in {"available", "unavailable", "disabled"}
        }
        return await self._post(
            f"/v1/home-connectors/{self.connector_id}/heartbeat",
            {
                "connector_id": self.connector_id,
                "profile_id": self.profile_id,
                "provider_status": safe_status,
            },
        )

    async def relay_ticket(self) -> dict[str, Any]:
        return await self._post(f"/v1/home-connectors/{self.connector_id}/relay-ticket", {})

    async def run_one(self, executor: CloudCommandExecutor) -> str:
        claimed = await self._post("/v1/remote-requests/claim", {"connector_id": self.connector_id})
        if claimed.get("state") == "empty":
            return "empty"
        request = claimed.get("request") or {}
        request_id = str(request.get("request_id") or "")
        if request.get("method") != "COMMAND" or not request_id:
            if request_id:
                await self._fail(request_id, "unsupportedClaimedRequest")
            return "rejected"
        try:
            command = CloudCommand(
                requestId=request_id,
                operation=request.get("operation"),
                parameters=request.get("parameters") or {},
            )
        except Exception:
            await self._fail(request_id, "invalidCommandEnvelope")
            return "rejected"
        result = await executor.execute(command)
        if result.state == "complete":
            await self._post(
                f"/v1/remote-requests/{request_id}/complete",
                {
                    "connector_id": self.connector_id,
                    "http_status": 200,
                    "response": result.model_dump(exclude_none=True),
                },
            )
            return "completed"
        await self._fail(request_id, result.sanitizedErrorCategory or "localCommandFailed")
        return "failed"

    async def _fail(self, request_id: str, category: str) -> None:
        await self._post(
            f"/v1/remote-requests/{request_id}/fail",
            {
                "connector_id": self.connector_id,
                "message": "Home Server command did not complete.",
                "details": {"category": category},
            },
        )
