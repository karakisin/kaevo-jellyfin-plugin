from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from .cloud_commands import CloudCommandExecutor, CommandReceiptStore, LocalProvider
from .cloud_connector import CloudControlPlaneClient
from .playback_tunnel import PlaybackGrantVerifier, PlaybackNonceStore
from .relay_worker import RelayConnectorWorker, RelayRequestHandler


class CloudRuntime:
    def __init__(self, *, data_dir: Path, app_version: str, credential_store: Any):
        self.enabled = os.environ.get("KAEVO_CLOUD_CONNECTOR_ENABLED", "false").lower() in {"1", "true", "yes"}
        self.tasks: list[asyncio.Task] = []
        if not self.enabled:
            return
        required = {
            "cloud_base_url": os.environ.get("KAEVO_CLOUD_BASE_URL"),
            "connector_token": os.environ.get("KAEVO_CLOUD_CONNECTOR_TOKEN"),
            "connector_id": os.environ.get("KAEVO_CLOUD_CONNECTOR_ID"),
            "profile_id": os.environ.get("KAEVO_CLOUD_PROFILE_ID"),
            "relay_url": os.environ.get("KAEVO_PLAYBACK_RELAY_WEBSOCKET_URL"),
            "grant_key": os.environ.get("KAEVO_PLAYBACK_CONNECTOR_GRANT_KEY"),
            "jellyfin_user_id": os.environ.get("KAEVO_JELLYFIN_USER_ID"),
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"cloudRuntimeMissingConfiguration:{','.join(missing)}")
        jellyfin = credential_store.get("jellyfin")
        if not jellyfin or not jellyfin.enabled or not jellyfin.api_key:
            raise RuntimeError("cloudRuntimeJellyfinNotConfigured")
        seerr = credential_store.get("seerr")
        self.cloud = CloudControlPlaneClient(
            base_url=required["cloud_base_url"], connector_id=required["connector_id"],
            profile_id=required["profile_id"], connector_token=required["connector_token"],
        )
        self.executor = CloudCommandExecutor(
            receipts=CommandReceiptStore(data_dir / "cloud_command_receipts.sqlite3"),
            jellyfin=LocalProvider(jellyfin.base_url, jellyfin.api_key),
            jellyfin_user_id=required["jellyfin_user_id"],
            seerr=LocalProvider(seerr.base_url, seerr.api_key) if seerr and seerr.enabled and seerr.api_key else None,
        )
        verifier = PlaybackGrantVerifier(required["grant_key"], required["connector_id"])
        handler = RelayRequestHandler(
            verifier=verifier, nonces=PlaybackNonceStore(data_dir / "playback_nonces.sqlite3"),
            jellyfin_base_url=jellyfin.base_url, jellyfin_api_key=jellyfin.api_key,
        )
        self.relay = RelayConnectorWorker(cloud=self.cloud, relay_websocket_url=required["relay_url"], handler=handler)
        self.app_version = app_version

    async def start(self) -> None:
        if not self.enabled:
            return
        await self.cloud.register(
            app_version=self.app_version,
            capabilities=["remote_commands_v1", "playback_tunnel_v1", "direct_play", "hls_remux", "hls_transcode"],
        )
        self.tasks = [
            asyncio.create_task(self._control_loop(), name="kaevo-cloud-control"),
            asyncio.create_task(self.relay.run_forever(), name="kaevo-playback-relay"),
        ]

    async def stop(self) -> None:
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []

    async def _control_loop(self) -> None:
        heartbeat_at = 0.0
        loop = asyncio.get_running_loop()
        while True:
            if loop.time() >= heartbeat_at:
                await self.cloud.heartbeat(provider_status={
                    "jellyfin": "available", "optimizer": "disabled", "playback_tunnel": "available",
                })
                heartbeat_at = loop.time() + 60
            await self.cloud.run_one(self.executor)
            await asyncio.sleep(1)
