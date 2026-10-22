"""Miracast sink: listen on the control port and connect back for RTSP."""

from __future__ import annotations

import asyncio
import logging
import secrets
import uuid
from collections.abc import Awaitable, Callable

from .codec import (
    Capability,
    PinResponse,
    SecurityOptions,
    SessionRequest,
    SourceReady,
    StopProjection,
    VendorExtension,
    pin_hash,
)
from .constants import (
    CMD_PIN_CHALLENGE,
    CMD_SECURITY_HANDSHAKE,
    CMD_SESSION_REQUEST,
    CMD_SOURCE_READY,
    CMD_STOP_PROJECTION,
    PIN_ACCEPTED,
    PIN_UNEXPECTED,
    PIN_WRONG,
    SECURITY_HANDSHAKE_TIMEOUT,
    SESSION_TIMEOUT_NO_PIN,
    SESSION_TIMEOUT_PIN,
    TCP_PORT,
    TRANSPORT_INFRASTRUCTURE,
    TRANSPORT_WIFI_DIRECT,
)
from .dtls import DtlsConnection
from .errors import DtlsError, MiceError, ProtocolError
from .mdns import ServiceAdvertiser
from .model import DiscoveredSink
from .stream import close_writer, open_frame, open_tcp, protect, read_frame, security_frame, send_frame

LOGGER = logging.getLogger(__name__)
PinCallback = Callable[[str], None | Awaitable[None]]


class _Stopped(Exception):
    pass


class SinkSession:
    """One accepted control connection."""

    def __init__(self, sink: Sink, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.sink = sink
        self.reader = reader
        self.writer = writer
        self.local_ip = writer.get_extra_info("sockname")[0]
        self.peer_ip = writer.get_extra_info("peername")[0]
        self.source_id: bytes | None = None
        self.friendly_name: str | None = None
        self.security: SecurityOptions | None = None
        self.pin: str | None = None
        self.encryption_key: bytes | None = None
        self.dtls: DtlsConnection | None = None
        self.encrypt = False
        self.rtsp_reader: asyncio.StreamReader | None = None
        self.rtsp_writer: asyncio.StreamWriter | None = None
        self.source_ready_encrypted = False
        self.last_source_ready: SourceReady | None = None
        self.projecting = False
        self._queue: asyncio.Queue[bytes | None | BaseException] = asyncio.Queue()
        self._pump: asyncio.Task[None] | None = None
        now = asyncio.get_running_loop().time()
        seconds = sink.session_timeout
        if seconds is None:
            seconds = SESSION_TIMEOUT_NO_PIN
        self._deadline = now + seconds
        self._extend_pin_timer = sink.session_timeout is None

    def request_stop(self) -> None:
        self._queue.put_nowait(None)

    async def run(self) -> None:
        self._pump = asyncio.create_task(self._read_pump())
        try:
            await self._establish()
            self.projecting = True
            await self._wait_until_stop()
        except _Stopped:
            return
        finally:
            if self._pump is not None:
                self._pump.cancel()
            await close_writer(self.rtsp_writer)
            await close_writer(self.writer)

    async def _read_pump(self) -> None:
        try:
            while True:
                frame = await read_frame(self.reader)
                await self._queue.put(frame)
        except Exception as exc:
            await self._queue.put(exc)

    async def _next(self, *, security: bool = False) -> bytes:
        now = asyncio.get_running_loop().time()
        session_left = self._deadline - now
        if session_left <= 0:
            raise TimeoutError("session")
        wait = session_left
        security_bound = False
        if security and self.sink.security_timeout < session_left:
            wait = self.sink.security_timeout
            security_bound = True
        try:
            item = await asyncio.wait_for(self._queue.get(), wait)
        except TimeoutError as exc:
            raise TimeoutError("security" if security_bound else "session") from exc
        if item is None:
            await self._send_stop()
            raise _Stopped
        if isinstance(item, BaseException):
            raise item
        return item

    def _decode(self, frame: bytes):
        message, encrypted = open_frame(self.dtls, self.encrypt, frame)
        source_id = getattr(message, "source_id", None)
        if source_id is not None:
            if self.source_id is None:
                self.source_id = source_id
            elif source_id != self.source_id:
                raise ProtocolError("source id")
        friendly = getattr(message, "friendly_name", None)
        if friendly and not self.friendly_name:
            self.friendly_name = friendly
        if getattr(message, "command", None) == CMD_SOURCE_READY:
            self.source_ready_encrypted = encrypted
        return message

    async def _establish(self) -> None:
        frame = await self._next()
        message = self._decode(frame)
        command = getattr(message, "command", None)
        if command == CMD_STOP_PROJECTION:
            raise _Stopped
        if command == CMD_SOURCE_READY:
            await self._connect_rtsp(message)
            return
        if command == CMD_SESSION_REQUEST:
            await self._session_request(message)
            if self.security and self.security.use_dtls:
                await self._dtls()
            if self.security and self.security.sink_displays_pin:
                await self._pin()
        elif command == CMD_SECURITY_HANDSHAKE:
            await self._dtls(message)
        else:
            raise ProtocolError("unexpected message")
        ready = self._decode(await self._next())
        if getattr(ready, "command", None) != CMD_SOURCE_READY:
            raise ProtocolError("unexpected message")
        await self._connect_rtsp(ready)

    async def _session_request(self, message: SessionRequest) -> None:
        if message.security is None or message.friendly_name is None or message.source_id is None:
            raise ProtocolError("incomplete session request")
        options = message.security
        if options.use_dtls and not self.sink.stream_encryption:
            raise ProtocolError("encryption not offered")
        if options.sink_displays_pin and not self.sink.pin_supported:
            raise ProtocolError("pin not offered")
        self.security = options
        if options.sink_displays_pin:
            if self._extend_pin_timer:
                self._deadline = asyncio.get_running_loop().time() + SESSION_TIMEOUT_PIN
            self.pin = f"{secrets.randbelow(100_000_000):08d}"
            callback = self.sink.on_pin
            if callback is not None:
                result = callback(self.pin)
                if asyncio.iscoroutine(result):
                    await result

    async def _dtls(self, first=None) -> None:
        self.dtls = DtlsConnection(
            "server",
            self.sink.friendly_name,
            require_cookie=self.sink.require_cookie,
        )
        pending = first
        armed = False
        while not self.dtls.complete:
            if pending is None:
                frame = await self._next(security=armed)
                pending = self._decode(frame)
                armed = False
            if getattr(pending, "command", None) != CMD_SECURITY_HANDSHAKE or not pending.token:
                raise ProtocolError("unexpected message")
            try:
                replies = self.dtls.handle(pending.token)
            except DtlsError as exc:
                raise ProtocolError("dtls failed") from exc
            for flight in replies:
                if self.source_id is None:
                    raise ProtocolError("missing source id")
                await send_frame(self.writer, security_frame(flight, self.source_id))
            pending = None
            if replies and not self.dtls.complete:
                armed = True
        self.encryption_key = self.dtls.export_key()
        if self.security is not None:
            self.encrypt = True

    async def _pin(self) -> None:
        """Stay in the PIN state until the hash matches.

        A wrong PIN is reported and the session stays up. The wait uses the
        session timer, which was extended when PIN entry was selected. The
        one-second security timer applies to DTLS flights, not to user entry.
        """
        assert self.pin is not None and self.dtls is not None
        while True:
            frame = await self._next()
            message = self._decode(frame)
            if getattr(message, "command", None) != CMD_PIN_CHALLENGE:
                response = PinResponse(self.source_id, PIN_UNEXPECTED)
                await send_frame(self.writer, protect(self.dtls, self.encrypt, response))
                raise ProtocolError("unexpected pin challenge")
            expected = pin_hash(self.pin, self.peer_ip)
            if message.challenge == expected and self.source_id is not None:
                digest = pin_hash(self.pin, self.local_ip)
                response = PinResponse(self.source_id, PIN_ACCEPTED, digest)
                await send_frame(self.writer, protect(self.dtls, True, response))
                return
            response = PinResponse(self.source_id or message.source_id, PIN_WRONG)
            await send_frame(self.writer, protect(self.dtls, True, response))

    async def _connect_rtsp(self, message: SourceReady) -> None:
        if message.rtsp_port is None or message.source_id is None:
            raise ProtocolError("incomplete source ready")
        self.last_source_ready = message
        try:
            self.rtsp_reader, self.rtsp_writer = await open_tcp(self.peer_ip, message.rtsp_port)
        except OSError as exc:
            raise ConnectionError("rtsp connection failed") from exc

    async def _wait_until_stop(self) -> None:
        while True:
            frame = await self._next()
            message = self._decode(frame)
            if getattr(message, "command", None) == CMD_STOP_PROJECTION:
                return
            raise ProtocolError("unexpected message")

    async def _send_stop(self) -> None:
        if self.source_id is None or self.friendly_name is None:
            return
        message = StopProjection(self.source_id, self.friendly_name)
        try:
            await send_frame(self.writer, protect(self.dtls, self.encrypt, message))
        except (ConnectionError, OSError, MiceError):
            pass


class Sink:
    """Sink role. Listens on the control port and can publish DNS-SD."""

    def __init__(
        self,
        friendly_name: str,
        hostname: str,
        *,
        container_id: uuid.UUID | str | None = None,
        addresses: tuple[str, ...] = (),
        stream_encryption: bool = True,
        pin_supported: bool = True,
        bssid: bytes | None = None,
        connection_preference: tuple[int, ...] | None = (
            TRANSPORT_INFRASTRUCTURE,
            TRANSPORT_WIFI_DIRECT,
        ),
        on_pin: PinCallback | None = None,
        replace_existing: bool = False,
        session_timeout: float | None = None,
        security_timeout: float = SECURITY_HANDSHAKE_TIMEOUT,
        require_cookie: bool = False,
    ) -> None:
        if not friendly_name or len(friendly_name.encode("utf-8")) > 63:
            raise ValueError("friendly_name")
        if not hostname or "." in hostname or len(hostname.encode("ascii")) > 63:
            raise ValueError("hostname")
        if pin_supported and not stream_encryption:
            raise ValueError("pin requires stream encryption")
        self.friendly_name = friendly_name
        self.hostname = hostname
        self.container_id = uuid.UUID(str(container_id)) if container_id else uuid.uuid4()
        self.addresses = addresses
        self.stream_encryption = stream_encryption
        self.pin_supported = pin_supported
        self.bssid = bssid
        self.connection_preference = connection_preference
        self.on_pin = on_pin
        self.replace_existing = replace_existing
        self.session_timeout = session_timeout
        self.security_timeout = security_timeout
        self.require_cookie = require_cookie
        self.session: SinkSession | None = None
        self.port = 0
        self.listen_host = "0.0.0.0"
        self._server: asyncio.AbstractServer | None = None
        self._advertiser: ServiceAdvertiser | None = None
        self._active: asyncio.Task[None] | None = None

    @property
    def capability(self) -> Capability:
        return Capability(
            infrastructure=True,
            stream_encryption=self.stream_encryption,
            version=1,
            pin=self.pin_supported,
        )

    def vendor_extension(self) -> VendorExtension:
        return VendorExtension(
            capability=self.capability,
            hostname=self.hostname,
            bssid=self.bssid,
            connection_preference=self.connection_preference,
            addresses=self.addresses,
        )

    def info(self, host: str | None = None) -> DiscoveredSink:
        addresses = self.addresses
        if host is not None:
            addresses = (host,)
        elif not addresses and self.listen_host not in ("0.0.0.0", "::", ""):
            addresses = (self.listen_host,)
        return DiscoveredSink(
            name=self.friendly_name,
            hostname=self.hostname,
            addresses=addresses,
            port=self.port,
            container_id=str(self.container_id),
            capability=self.capability,
            bssid=self.bssid,
            connection_preference=self.connection_preference,
        )

    async def start(self, host: str = "0.0.0.0", port: int = TCP_PORT, *, advertise: bool = True) -> None:
        self._server = await asyncio.start_server(self._on_client, host, port)
        sockets = self._server.sockets or []
        self.listen_host = sockets[0].getsockname()[0]
        self.port = sockets[0].getsockname()[1]
        if advertise:
            addresses = self.addresses or (("127.0.0.1",) if host in ("0.0.0.0", "::") else (host,))
            self._advertiser = ServiceAdvertiser(
                self.friendly_name,
                self.hostname,
                addresses,
                self.port,
                str(self.container_id),
            )
            try:
                await self._advertiser.start()
            except OSError:
                LOGGER.warning("display service advertisement failed")
                self._advertiser = None

    async def stop(self) -> None:
        if self.session is not None:
            self.session.request_stop()
        if self._active is not None:
            try:
                await asyncio.wait_for(self._active, 2)
            except (TimeoutError, asyncio.CancelledError):
                self._active.cancel()
        if self._advertiser is not None:
            await self._advertiser.stop()
            self._advertiser = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active is not None and not self._active.done():
            if not self.replace_existing:
                writer.close()
                await close_writer(writer)
                return
            self._active.cancel()
        task = asyncio.current_task()
        assert task is not None
        self._active = task
        session = SinkSession(self, reader, writer)
        self.session = session
        try:
            await session.run()
        except (ProtocolError, DtlsError, ConnectionError, TimeoutError, OSError):
            await close_writer(writer)
        finally:
            if self._active is task:
                self._active = None
