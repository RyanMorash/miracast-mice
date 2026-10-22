"""Miracast source: discover a sink, open the session, yield the RTSP stream."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from .codec import (
    PinChallenge,
    PinResponse,
    SecurityOptions,
    SessionRequest,
    SourceReady,
    StopProjection,
    pin_hash,
)
from .constants import (
    CMD_SECURITY_HANDSHAKE,
    DEFAULT_CONTROL_TIMEOUT,
    DEFAULT_CONTROL_TIMEOUT_PIN,
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_RTSP_PORT,
    PIN_ACCEPTED,
    SECURITY_HANDSHAKE_TIMEOUT,
)
from .dtls import DtlsConnection
from .errors import DtlsError, FallbackRequired, MiceError, ProtocolError
from .mdns import resolve_hostname
from .model import DiscoveredSink, RtspEndpoint
from .stream import (
    close_writer,
    open_frame,
    open_tcp,
    protect,
    read_frame,
    security_frame,
    send_frame,
    tune,
)

PinProvider = Callable[[], str | Awaitable[str]]


class Session:
    """An open infrastructure session.

    `rtsp_endpoint` is the TCP connection the sink opened back to this
    source. `start_wfd` reads and writes that stream.
    """

    def __init__(
        self,
        sink: DiscoveredSink,
        source_id: bytes,
        friendly_name: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        rtsp: RtspEndpoint,
        *,
        encryption_key: bytes | None,
        dtls: DtlsConnection | None,
        encrypt_tlvs: bool,
        pin_used: bool,
        stream_encryption: bool,
        rtsp_server: asyncio.AbstractServer | None = None,
    ) -> None:
        self.sink = sink
        self.source_id = source_id
        self.friendly_name = friendly_name
        self.rtsp_endpoint = rtsp
        self.encryption_key = encryption_key
        self.pin_used = pin_used
        self.stream_encryption = stream_encryption
        self._reader = reader
        self._writer = writer
        self._dtls = dtls
        self._encrypt = encrypt_tlvs
        self._rtsp_server = rtsp_server
        self._closed = False
        self._peer_stopped = False
        self._done: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._reader_task = asyncio.create_task(self._read_loop())

    async def close(self) -> None:
        """Send stop projection and tear the session down."""
        if self._closed:
            await self.wait_closed()
            return
        self._closed = True
        try:
            if not self._peer_stopped:
                message = StopProjection(self.source_id, self.friendly_name)
                await send_frame(self._writer, protect(self._dtls, self._encrypt, message))
        except (ConnectionError, OSError, MiceError):
            pass
        await close_writer(self._writer)
        await close_writer(self.rtsp_endpoint.writer)
        if self._rtsp_server is not None:
            self._rtsp_server.close()
            await self._rtsp_server.wait_closed()
            self._rtsp_server = None
        await self.wait_closed()

    async def wait_closed(self) -> None:
        if not self._done.done():
            await self._done

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                frame = await read_frame(self._reader)
                message, _encrypted = open_frame(self._dtls, self._encrypt, frame)
                command = getattr(message, "command", None)
                if command == StopProjection.command:
                    self._peer_stopped = True
                    self.rtsp_endpoint.writer.close()
                    break
                self._closed = True
                self.rtsp_endpoint.writer.close()
                self._writer.close()
                break
        except (ConnectionError, asyncio.IncompleteReadError, ProtocolError, DtlsError, OSError):
            pass
        finally:
            if not self._done.done():
                self._done.set_result(None)
            self._closed = True


class Source:
    """Source role used by a Home Assistant media player."""

    def __init__(self, friendly_name: str, source_id: bytes | None = None, rtsp_port: int = DEFAULT_RTSP_PORT) -> None:
        if not friendly_name:
            raise ValueError("friendly_name")
        self.friendly_name = friendly_name
        self.source_id = source_id or uuid.uuid4().bytes
        if len(self.source_id) != 16:
            raise ValueError("source_id")
        self.rtsp_port = rtsp_port

    async def connect(
        self,
        sink: DiscoveredSink,
        *,
        pin: str | PinProvider | None = None,
        use_encryption: bool = False,
        use_pin: bool = False,
        control_timeout: float | None = None,
        resolve_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
        security_timeout: float = SECURITY_HANDSHAKE_TIMEOUT,
        resolver: Callable[[str], Awaitable[list[str]]] | None = None,
    ) -> Session:
        """Connect to `sink` and return when its RTSP TCP connection is up.

        Stream encryption and PIN entry are off unless requested. The
        product session does not negotiate content protection.
        """
        if sink.capability is not None and not sink.capability.infrastructure:
            raise FallbackRequired("infrastructure not supported")
        if "." in sink.hostname:
            raise FallbackRequired("hostname is not usable")
        if sink.capability is not None and sink.capability.version < 1:
            raise FallbackRequired("unsupported capability version")
        if use_pin:
            use_encryption = True
        if sink.capability is not None:
            if use_encryption and not sink.capability.stream_encryption:
                raise FallbackRequired("stream encryption is not supported")
            if use_pin and not sink.capability.pin:
                raise FallbackRequired("pin entry is not supported")
        if use_pin and pin is None:
            raise MiceError("pin required")
        addresses = list(sink.addresses)
        if not addresses:
            try:
                if resolver is None:
                    found = await resolve_hostname(sink.hostname, resolve_timeout)
                else:
                    found = await resolver(sink.hostname)
                addresses = list(found)
            except Exception as exc:
                raise FallbackRequired("name resolution failed") from exc
            if not addresses:
                raise FallbackRequired("name resolution failed")
        host = addresses[0]
        if control_timeout is None:
            control_timeout = DEFAULT_CONTROL_TIMEOUT_PIN if use_pin else DEFAULT_CONTROL_TIMEOUT
        deadline = asyncio.get_running_loop().time() + control_timeout
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        server: asyncio.AbstractServer | None = None
        rtsp_writer: asyncio.StreamWriter | None = None
        dtls: DtlsConnection | None = None
        try:
            reader, writer = await open_tcp(host, sink.port)
            local_ip = writer.get_extra_info("sockname")[0]
            peer_ip = writer.get_extra_info("peername")[0]
            encrypt_tlvs = False
            if use_pin:
                request = SessionRequest(
                    self.friendly_name,
                    self.source_id,
                    SecurityOptions(use_dtls=True, sink_displays_pin=True),
                )
                await send_frame(writer, request.encode())
                encrypt_tlvs = True
            key: bytes | None = None
            if use_encryption:
                dtls = DtlsConnection("client", self.friendly_name)
                key = await _client_handshake(
                    dtls, reader, writer, self.source_id, deadline, security_timeout
                )
            pin_value = None
            if use_pin:
                assert dtls is not None
                pin_value = await _call_pin(pin)
                digest = pin_hash(pin_value, local_ip)
                challenge = PinChallenge(self.source_id, digest)
                await send_frame(writer, protect(dtls, True, challenge))
                frame = await _read_limited(
                    reader, deadline, security_timeout, "security handshake timeout"
                )
                message, _encrypted = open_frame(dtls, True, frame)
                if not isinstance(message, PinResponse) or message.reason != PIN_ACCEPTED:
                    raise FallbackRequired("pin rejected")
                expected = pin_hash(pin_value, peer_ip)
                if message.challenge != expected:
                    raise FallbackRequired("pin hash mismatch")
                if message.source_id not in (None, self.source_id):
                    raise FallbackRequired("source id mismatch")
            loop = asyncio.get_running_loop()
            accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
                loop.create_future()
            )

            async def on_rtsp(
                rtsp_reader: asyncio.StreamReader, incoming: asyncio.StreamWriter
            ) -> None:
                if accepted.done():
                    incoming.close()
                    return
                tune(incoming)
                accepted.set_result((rtsp_reader, incoming))

            try:
                server = await asyncio.start_server(on_rtsp, local_ip, self.rtsp_port)
            except OSError as exc:
                raise MiceError("rtsp listen failed") from exc
            bound_port = server.sockets[0].getsockname()[1]
            ready = SourceReady(
                source_id=self.source_id,
                rtsp_port=bound_port,
                friendly_name=None if use_pin else self.friendly_name,
            )
            await send_frame(writer, protect(dtls, encrypt_tlvs, ready))
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise FallbackRequired("control channel timeout")
            try:
                rtsp_reader, rtsp_writer = await asyncio.wait_for(accepted, remaining)
            except TimeoutError as exc:
                raise FallbackRequired("control channel timeout") from exc
            peer = rtsp_writer.get_extra_info("peername")
            sockname = rtsp_writer.get_extra_info("sockname")
            endpoint = RtspEndpoint(
                local_host=sockname[0],
                local_port=sockname[1],
                sink_host=peer[0],
                sink_port=peer[1],
                reader=rtsp_reader,
                writer=rtsp_writer,
            )
            # close() stops the listen socket. wait_closed() also waits
            # until the accepted RTSP connection drops, so that wait
            # belongs to session teardown.
            server.close()
            held_server = server
            server = None
            session = Session(
                sink,
                self.source_id,
                self.friendly_name,
                reader,
                writer,
                endpoint,
                encryption_key=key,
                dtls=dtls,
                encrypt_tlvs=encrypt_tlvs,
                pin_used=use_pin,
                stream_encryption=use_encryption,
                rtsp_server=held_server,
            )
            reader = None
            writer = None
            rtsp_writer = None
            return session
        except FallbackRequired:
            raise
        except (ConnectionError, OSError, asyncio.IncompleteReadError) as exc:
            raise FallbackRequired("connection lost") from exc
        except (ProtocolError, DtlsError) as exc:
            raise FallbackRequired("malformed message") from exc
        except TimeoutError as exc:
            raise FallbackRequired("control channel timeout") from exc
        finally:
            await close_writer(rtsp_writer)
            await close_writer(writer)
            if server is not None:
                server.close()
                await server.wait_closed()


async def _call_pin(pin: str | PinProvider | None) -> str:
    if pin is None:
        raise MiceError("pin required")
    if isinstance(pin, str):
        return pin
    result = pin()
    if asyncio.iscoroutine(result):
        result = await result
    if not isinstance(result, str):
        raise MiceError("pin required")
    return result


async def _read_limited(
    reader: asyncio.StreamReader,
    deadline: float,
    limit: float,
    reason: str,
) -> bytes:
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise FallbackRequired("control channel timeout")
    security_bound = limit < remaining
    try:
        return await asyncio.wait_for(read_frame(reader), min(limit, remaining))
    except TimeoutError as exc:
        if security_bound:
            raise FallbackRequired(reason) from exc
        raise FallbackRequired("control channel timeout") from exc


async def _client_handshake(
    dtls: DtlsConnection,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    source_id: bytes,
    deadline: float,
    security_timeout: float,
) -> bytes:
    try:
        for flight in dtls.start():
            await send_frame(writer, security_frame(flight, source_id))
        while not dtls.complete:
            frame = await _read_limited(
                reader, deadline, security_timeout, "security handshake timeout"
            )
            message, _encrypted = open_frame(None, False, frame)
            if getattr(message, "command", None) != CMD_SECURITY_HANDSHAKE or not getattr(
                message, "token", None
            ):
                raise FallbackRequired("unexpected message")
            for flight in dtls.handle(message.token):
                await send_frame(writer, security_frame(flight, source_id))
    except DtlsError as exc:
        raise FallbackRequired("dtls failed") from exc
    return dtls.export_key()
