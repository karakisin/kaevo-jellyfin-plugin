from pathlib import Path

import httpx
import pytest

from kaevo_home_server.cloud_commands import CloudCommandExecutor, CommandReceiptStore, LocalProvider
from kaevo_home_server.cloud_connector import CloudControlPlaneClient


ITEM_ID = "0123456789abcdef0123456789abcdef"


@pytest.mark.asyncio
async def test_outbound_worker_claims_executes_and_completes_without_provider_secret(tmp_path: Path):
    cloud_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "cloud.example":
            cloud_bodies.append(request.content.decode())
            if request.url.path.endswith("/claim"):
                return httpx.Response(
                    200,
                    json={
                        "state": "claimed",
                        "request": {
                            "request_id": "request-0001",
                            "method": "COMMAND",
                            "operation": "jellyfin.favorite",
                            "parameters": {"item_id": ITEM_ID},
                        },
                    },
                )
            return httpx.Response(200, json={"state": "completed"})
        assert request.url.host == "jellyfin"
        assert request.headers["X-Emby-Token"] == "local-provider-secret"
        return httpx.Response(204)

    transport = httpx.MockTransport(handler)
    executor = CloudCommandExecutor(
        receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"),
        jellyfin=LocalProvider("http://jellyfin:8096", "local-provider-secret"),
        jellyfin_user_id="user-42",
        transport=transport,
    )
    cloud = CloudControlPlaneClient(
        base_url="https://cloud.example",
        connector_id="connector-1",
        profile_id="profile-1",
        connector_token="paired-connector-token",
        transport=transport,
    )
    assert await cloud.run_one(executor) == "completed"
    assert all("local-provider-secret" not in body for body in cloud_bodies)


@pytest.mark.asyncio
async def test_worker_rejects_non_command_claim(tmp_path: Path):
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/claim"):
            return httpx.Response(200, json={"state": "claimed", "request": {"request_id": "request-2", "method": "GET"}})
        return httpx.Response(200, json={"state": "failed"})

    transport = httpx.MockTransport(handler)
    cloud = CloudControlPlaneClient(
        base_url="https://cloud.example",
        connector_id="connector-1",
        profile_id="profile-1",
        connector_token="paired-connector-token",
        transport=transport,
    )
    executor = CloudCommandExecutor(receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"))
    assert await cloud.run_one(executor) == "rejected"
    assert paths[-1] == "/v1/remote-requests/request-2/fail"
