"""Discovery records and the RTSP stream returned by connect."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .codec import Capability, VendorExtension
from .constants import TCP_PORT


@dataclass(frozen=True)
class DiscoveredSink:
    """One sink a config flow can show and later pass to `Source.connect`."""

    name: str
    hostname: str
    addresses: tuple[str, ...] = ()
    port: int = TCP_PORT
    container_id: str | None = None
    capability: Capability | None = None
    bssid: bytes | None = None
    connection_preference: tuple[int, ...] | None = None

    @property
    def unique_id(self) -> str:
        return self.container_id or self.hostname

    @classmethod
    def from_vendor_extension(
        cls,
        data: bytes | VendorExtension,
        *,
        name: str | None = None,
        port: int = TCP_PORT,
        container_id: str | None = None,
    ) -> DiscoveredSink:
        extension = data if isinstance(data, VendorExtension) else VendorExtension.decode(data)
        return cls(
            name=name or extension.hostname,
            hostname=extension.hostname,
            addresses=extension.addresses,
            port=port,
            container_id=container_id,
            capability=extension.capability,
            bssid=extension.bssid,
            connection_preference=extension.connection_preference,
        )


@dataclass
class RtspEndpoint:
    """Connected RTSP TCP stream.

    The sink opens this connection to the source. `local_*` is the source
    side and `sink_*` is the sink side. `reader` and `writer` are the byte
    stream. Pass this object to `start_wfd`; it does not open another TCP
    connection.
    """

    local_host: str
    local_port: int
    sink_host: str
    sink_port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
