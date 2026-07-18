from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from kaevo_home_server.cloud_commands import (
    CloudCommand,
    CloudCommandExecutor,
    CommandReceiptStore,
    LocalProvider,
)


ITEM_ID = "0123456789abcdef0123456789abcdef"


def command(operation: str, parameters: dict, request_id: str = "request-0001") -> CloudCommand:
    return CloudCommand(requestId=request_id, operation=operation, parameters=parameters)


def test_rejects_arbitrary_jellyfin_paths_and_operations():
    with pytest.raises(ValidationError):
        command("jellyfin.delete_media", {"item_id": ITEM_ID})
    with pytest.raises(ValidationError):
        command("jellyfin.favorite", {"item_id": "../../Videos/secret"})


@pytest.mark.asyncio
async def test_jellyfin_write_uses_exact_user_state_route(tmp_path: Path):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["token"] = request.headers.get("X-Emby-Token")
        return httpx.Response(204)

    executor = CloudCommandExecutor(
        receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"),
        jellyfin=LocalProvider("http://jellyfin:8096", "local-secret"),
        jellyfin_user_id="user-42",
        transport=httpx.MockTransport(handler),
    )
    result = await executor.execute(command("jellyfin.mark_played", {"item_id": ITEM_ID}))
    assert result.state == "complete"
    assert captured == {
        "method": "POST",
        "url": f"http://jellyfin:8096/UserPlayedItems/{ITEM_ID}?userId=user-42",
        "token": "local-secret",
    }


@pytest.mark.asyncio
async def test_receipt_prevents_duplicate_provider_mutation(tmp_path: Path):
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(204)

    executor = CloudCommandExecutor(
        receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"),
        jellyfin=LocalProvider("http://jellyfin:8096", "local-secret"),
        jellyfin_user_id="user-42",
        transport=httpx.MockTransport(handler),
    )
    payload = command("jellyfin.favorite", {"item_id": ITEM_ID})
    assert (await executor.execute(payload)).state == "complete"
    assert (await executor.execute(payload)).state == "complete"
    assert calls == 1


@pytest.mark.asyncio
async def test_remux_execution_stays_locally_gated(tmp_path: Path):
    called = False

    async def optimizer(operation: str, parameters: dict):
        nonlocal called
        called = True
        assert operation == "optimizer.execute_remux"
        assert parameters["confirmation"] == "YES_REMUX_ONE_FILE"
        return {"state": "acceptedOneFile"}

    executor = CloudCommandExecutor(
        receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"),
        optimizer=optimizer,
    )
    payload = command(
        "optimizer.execute_remux",
        {
            "plan_id": "f5d88a35-321e-4712-a39c-b4b06bcdaff6",
            "approval_token": "abcdefghijklmnopqrstuvwxyz123456",
            "confirmation": "YES_REMUX_ONE_FILE",
        },
    )
    assert (await executor.execute(payload)).state == "complete"
    assert called


def test_remux_execute_requires_exact_confirmation_and_token():
    with pytest.raises(ValidationError):
        command(
            "optimizer.execute_remux",
            {
                "plan_id": "f5d88a35-321e-4712-a39c-b4b06bcdaff6",
                "approval_token": "short",
                "confirmation": "YES",
            },
        )


@pytest.mark.asyncio
async def test_playback_preparation_returns_only_bound_safe_identifiers(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/Items/{ITEM_ID}/PlaybackInfo"
        assert request.headers["X-Emby-Token"] == "local-secret"
        return httpx.Response(200, json={
            "PlaySessionId": "play-session-1",
            "MediaSources": [{
                "Id": "media-source-1", "SupportsDirectPlay": False,
                "SupportsDirectStream": False, "SupportsTranscoding": True,
                "Path": "/media/Movies/private/movie.mkv",
                "TranscodingUrl": "/Videos/private/master.m3u8?api_key=secret",
            }],
        })

    executor = CloudCommandExecutor(
        receipts=CommandReceiptStore(tmp_path / "receipts.sqlite3"),
        jellyfin=LocalProvider("http://jellyfin:8096", "local-secret"),
        jellyfin_user_id="user-42", transport=httpx.MockTransport(handler),
    )
    result = await executor.execute(command("jellyfin.prepare_playback", {
        "item_id": ITEM_ID, "device_id": "ios-device-1", "max_bitrate": 20_000_000,
    }))
    assert result.state == "complete"
    assert result.result == {
        "item_id": ITEM_ID, "media_source_id": "media-source-1", "playback_session_id": "play-session-1",
        "mode": "transcode", "max_bitrate": 20_000_000,
    }
    assert "/media/" not in str(result.model_dump())
    assert "api_key" not in str(result.model_dump())
