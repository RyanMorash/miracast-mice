"""Source and sink session behavior on loopback."""

import asyncio

from miracast_mice import (
    DiscoveredSink,
    FallbackRequired,
    MiceError,
    PinChallenge,
    PinResponse,
    SessionRequest,
    Sink,
    Source,
    SourceReady,
    pin_hash,
)
from miracast_mice.codec import Capability, SecurityOptions
from miracast_mice.constants import PIN_ACCEPTED, PIN_UNEXPECTED, PIN_WRONG
from miracast_mice.dtls import DtlsConnection
from miracast_mice.stream import open_frame, protect, read_frame, security_frame, send_frame


def test_cleartext_rtsp_stream_and_stop() -> None:
    asyncio.run(_cleartext_rtsp_stream_and_stop())


def test_dtls_without_pin_exports_matching_keys() -> None:
    asyncio.run(_dtls_without_pin_exports_matching_keys())


def test_pin_session_encrypts_source_ready() -> None:
    asyncio.run(_pin_session_encrypts_source_ready())


def test_wrong_pin_keeps_the_listener_up() -> None:
    asyncio.run(_wrong_pin_keeps_the_listener_up())


def test_wrong_pin_can_be_retried() -> None:
    asyncio.run(_wrong_pin_can_be_retried())


def test_unexpected_message_while_waiting_for_pin() -> None:
    asyncio.run(_unexpected_message_while_waiting_for_pin())


def test_second_connection_is_rejected() -> None:
    asyncio.run(_second_connection_is_rejected())


def test_replace_existing_connection() -> None:
    asyncio.run(_replace_existing_connection())


def test_sink_stop_closes_the_source() -> None:
    asyncio.run(_sink_stop_closes_the_source())


def test_unexpected_message_tears_the_session_down() -> None:
    asyncio.run(_unexpected_message_tears_the_session_down())


def test_connect_refusals() -> None:
    asyncio.run(_connect_refusals())


def test_timeouts() -> None:
    asyncio.run(_timeouts())


def test_vendor_extension_is_enough_to_connect() -> None:
    asyncio.run(_vendor_extension_is_enough_to_connect())


async def _listening_sink(**kwargs) -> Sink:
    sink = Sink("Living Room", "livingroom", **kwargs)
    await sink.start("127.0.0.1", 0, advertise=False)
    return sink


async def _wait_projecting(sink: Sink, timeout: float = 3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        session = sink.session
        if (
            session is not None
            and session.projecting
            and session.rtsp_reader is not None
            and session.rtsp_writer is not None
        ):
            return session
        await asyncio.sleep(0.02)
    raise AssertionError("sink did not project")


async def _wait_idle(sink: Sink, timeout: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        active = sink._active
        if active is None or active.done():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("sink session still active")


async def _cleartext_rtsp_stream_and_stop() -> None:
    sink = await _listening_sink()
    source = Source("Laptop", rtsp_port=0)
    session = None
    try:
        info = sink.info("127.0.0.1")
        assert info.capability is not None and info.capability.stream_encryption
        session = await source.connect(info, control_timeout=3)
        assert session.encryption_key is None
        assert session.pin_used is False
        assert session.stream_encryption is False
        peer = await _wait_projecting(sink)
        assert peer.source_ready_encrypted is False
        assert peer.last_source_ready is not None
        assert peer.last_source_ready.friendly_name == "Laptop"
        assert session.rtsp_endpoint.local_port != 0
        session.rtsp_endpoint.writer.write(b"OPTIONS * RTSP/1.0\r\n\r\n")
        await session.rtsp_endpoint.writer.drain()
        incoming = await asyncio.wait_for(peer.rtsp_reader.read(64), 2)
        assert incoming.startswith(b"OPTIONS ")
        assert peer.rtsp_writer is not None
        peer.rtsp_writer.write(b"RTSP/1.0 200 OK\r\n\r\n")
        await peer.rtsp_writer.drain()
        reply = await asyncio.wait_for(session.rtsp_endpoint.reader.read(64), 2)
        assert reply.startswith(b"RTSP/1.0 200")
    finally:
        if session is not None:
            await session.close()
        await sink.stop()


async def _dtls_without_pin_exports_matching_keys() -> None:
    sink = await _listening_sink(require_cookie=True, pin_supported=False)
    source = Source("Laptop", rtsp_port=0)
    session = None
    try:
        session = await source.connect(
            sink.info("127.0.0.1"),
            use_encryption=True,
            control_timeout=5,
            security_timeout=2,
        )
        peer = await _wait_projecting(sink)
        assert session.encryption_key is not None
        assert session.encryption_key == peer.encryption_key
        assert len(session.encryption_key) == 32
        assert session.pin_used is False
        assert session.stream_encryption is True
        assert peer.source_ready_encrypted is False
        assert peer.last_source_ready is not None
        assert peer.last_source_ready.friendly_name == "Laptop"
    finally:
        if session is not None:
            await session.close()
        await sink.stop()


async def _pin_session_encrypts_source_ready() -> None:
    shown: list[str] = []

    def on_pin(pin: str) -> None:
        shown.append(pin)

    sink = await _listening_sink(on_pin=on_pin)
    source = Source("Laptop", rtsp_port=0)
    session = None
    try:
        session = await source.connect(
            sink.info("127.0.0.1"),
            use_pin=True,
            pin=lambda: shown[0],
            control_timeout=8,
            security_timeout=2,
        )
        peer = await _wait_projecting(sink)
        assert shown and len(shown[0]) == 8 and shown[0].isdigit()
        assert session.pin_used is True
        assert session.stream_encryption is True
        assert session.encryption_key == peer.encryption_key
        assert peer.source_ready_encrypted is True
        assert peer.last_source_ready is not None
        assert peer.last_source_ready.friendly_name is None
        assert peer.friendly_name == "Laptop"
    finally:
        if session is not None:
            await session.close()
        await sink.stop()


async def _wrong_pin_keeps_the_listener_up() -> None:
    sink = await _listening_sink()
    source = Source("Laptop", rtsp_port=0)
    try:
        try:
            await source.connect(
                sink.info("127.0.0.1"),
                use_pin=True,
                pin="00000000",
                control_timeout=8,
                security_timeout=2,
            )
        except FallbackRequired as exc:
            assert exc.reason == "pin rejected"
        else:
            raise AssertionError("wrong pin was accepted")
        await _wait_idle(sink)
        retry = Source("Laptop", rtsp_port=0)
        session = await retry.connect(sink.info("127.0.0.1"), control_timeout=3)
        try:
            await _wait_projecting(sink)
        finally:
            await session.close()
    finally:
        await sink.stop()


async def _handshake(reader, writer, source_id: bytes) -> DtlsConnection:
    dtls = DtlsConnection("client", "Laptop")
    for flight in dtls.start():
        await send_frame(writer, security_frame(flight, source_id))
    while not dtls.complete:
        frame = await asyncio.wait_for(read_frame(reader), 3)
        message, _encrypted = open_frame(None, False, frame)
        token = getattr(message, "token", None)
        if not token:
            raise AssertionError("expected a security handshake")
        for flight in dtls.handle(token):
            await send_frame(writer, security_frame(flight, source_id))
    return dtls


async def _wrong_pin_can_be_retried() -> None:
    shown: list[str] = []
    sink = await _listening_sink(on_pin=shown.append)
    source_id = Source("Laptop").source_id
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", sink.port)
        try:
            request = SessionRequest("Laptop", source_id, SecurityOptions(True, True))
            await send_frame(writer, request.encode())
            dtls = await _handshake(reader, writer, source_id)
            local_ip = writer.get_extra_info("sockname")[0]
            wrong = PinChallenge(source_id, pin_hash("00000000", "192.0.2.9"))
            await send_frame(writer, protect(dtls, True, wrong))
            first, _encrypted = open_frame(dtls, True, await asyncio.wait_for(read_frame(reader), 2))
            assert isinstance(first, PinResponse)
            assert first.reason == PIN_WRONG
            assert first.challenge is None
            right = PinChallenge(source_id, pin_hash(shown[0], local_ip))
            await send_frame(writer, protect(dtls, True, right))
            second, encrypted = open_frame(dtls, True, await asyncio.wait_for(read_frame(reader), 2))
            assert encrypted
            assert isinstance(second, PinResponse)
            assert second.reason == PIN_ACCEPTED
            assert second.challenge == pin_hash(shown[0], writer.get_extra_info("peername")[0])
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await sink.stop()


async def _unexpected_message_while_waiting_for_pin() -> None:
    sink = await _listening_sink()
    source_id = Source("Laptop").source_id
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", sink.port)
        try:
            request = SessionRequest("Laptop", source_id, SecurityOptions(True, True))
            await send_frame(writer, request.encode())
            dtls = await _handshake(reader, writer, source_id)
            ready = SourceReady(source_id, 7236, None)
            await send_frame(writer, protect(dtls, True, ready))
            message, _encrypted = open_frame(dtls, True, await asyncio.wait_for(read_frame(reader), 2))
            assert isinstance(message, PinResponse)
            assert message.reason == PIN_UNEXPECTED
            leftover = await asyncio.wait_for(reader.read(16), 2)
            assert leftover == b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        await _wait_idle(sink)
    finally:
        await sink.stop()


async def _second_connection_is_rejected() -> None:
    sink = await _listening_sink()
    session = None
    try:
        session = await Source("Laptop", rtsp_port=0).connect(sink.info("127.0.0.1"), control_timeout=3)
        await _wait_projecting(sink)
        try:
            await Source("Other", rtsp_port=0).connect(
                sink.info("127.0.0.1"),
                control_timeout=0.4,
            )
        except FallbackRequired as exc:
            assert exc.reason == "control channel timeout"
        else:
            raise AssertionError("second connection was accepted")
        peer = sink.session
        assert peer is not None and peer.projecting
        session.rtsp_endpoint.writer.write(b"still-open")
        await session.rtsp_endpoint.writer.drain()
        data = await asyncio.wait_for(peer.rtsp_reader.read(16), 2)
        assert data == b"still-open"
    finally:
        if session is not None:
            await session.close()
        await sink.stop()


async def _replace_existing_connection() -> None:
    sink = await _listening_sink(replace_existing=True)
    first = None
    second = None
    try:
        first = await Source("Laptop", rtsp_port=0).connect(sink.info("127.0.0.1"), control_timeout=3)
        await _wait_projecting(sink)
        second = await Source("Other", rtsp_port=0).connect(sink.info("127.0.0.1"), control_timeout=3)
        await asyncio.wait_for(first.wait_closed(), 2)
        peer = await _wait_projecting(sink)
        assert peer.friendly_name == "Other"
    finally:
        if second is not None:
            await second.close()
        if first is not None:
            await first.close()
        await sink.stop()


async def _sink_stop_closes_the_source() -> None:
    sink = await _listening_sink()
    session = None
    try:
        session = await Source("Laptop", rtsp_port=0).connect(sink.info("127.0.0.1"), control_timeout=3)
        await _wait_projecting(sink)
        assert sink.session is not None
        sink.session.request_stop()
        await asyncio.wait_for(session.wait_closed(), 2)
        await session.close()
    finally:
        if session is not None and not session._closed:
            await session.close()
        await sink.stop()


async def _unexpected_message_tears_the_session_down() -> None:
    sink = await _listening_sink()
    session = None
    try:
        session = await Source("Laptop", rtsp_port=0).connect(sink.info("127.0.0.1"), control_timeout=3)
        await _wait_projecting(sink)
        extra = SourceReady(session.source_id, 7236, "Laptop")
        await send_frame(session._writer, extra.encode())
        await _wait_idle(sink)
        await asyncio.wait_for(session.wait_closed(), 2)
    finally:
        if session is not None:
            await session.close()
        await sink.stop()


async def _connect_refusals() -> None:
    dotted = DiscoveredSink("TV", "tv.local", ("127.0.0.1",), port=9)
    try:
        await Source("Laptop", rtsp_port=0).connect(dotted)
    except FallbackRequired as exc:
        assert exc.reason == "hostname is not usable"
    else:
        raise AssertionError("dotted hostname")

    direct = DiscoveredSink(
        "TV",
        "tv",
        ("127.0.0.1",),
        port=9,
        capability=Capability(False, False, version=1),
    )
    try:
        await Source("Laptop", rtsp_port=0).connect(direct)
    except FallbackRequired as exc:
        assert exc.reason == "infrastructure not supported"
    else:
        raise AssertionError("missing infrastructure")

    old = DiscoveredSink(
        "TV",
        "tv",
        ("127.0.0.1",),
        port=9,
        capability=Capability(True, False, version=0),
    )
    try:
        await Source("Laptop", rtsp_port=0).connect(old)
    except FallbackRequired as exc:
        assert exc.reason == "unsupported capability version"
    else:
        raise AssertionError("old version")

    plain = await _listening_sink(stream_encryption=False, pin_supported=False)
    try:
        info = plain.info("127.0.0.1")
        try:
            await Source("Laptop", rtsp_port=0).connect(info, use_encryption=True)
        except FallbackRequired as exc:
            assert exc.reason == "stream encryption is not supported"
        else:
            raise AssertionError("encryption")
        try:
            await Source("Laptop", rtsp_port=0).connect(info, use_pin=True, pin="1234")
        except FallbackRequired as exc:
            assert exc.reason == "stream encryption is not supported"
        else:
            raise AssertionError("pin forced encryption")
    finally:
        await plain.stop()

    no_pin = await _listening_sink(pin_supported=False)
    try:
        try:
            await Source("Laptop", rtsp_port=0).connect(
                no_pin.info("127.0.0.1"),
                use_pin=True,
                pin="1234",
            )
        except FallbackRequired as exc:
            assert exc.reason == "pin entry is not supported"
        else:
            raise AssertionError("pin")
    finally:
        await no_pin.stop()

    pin_cap = DiscoveredSink(
        "TV",
        "tv",
        ("127.0.0.1",),
        port=9,
        capability=Capability(True, True, version=1, pin=True),
    )
    try:
        await Source("Laptop", rtsp_port=0).connect(pin_cap, use_pin=True)
    except FallbackRequired as exc:
        raise AssertionError(exc.reason) from exc
    except MiceError:
        pass
    else:
        raise AssertionError("missing pin")

    async def fail(_hostname: str) -> list[str]:
        raise OSError("resolver")

    missing = DiscoveredSink("TV", "tv", (), port=9)
    try:
        await Source("Laptop", rtsp_port=0).connect(missing, resolver=fail)
    except FallbackRequired as exc:
        assert exc.reason == "name resolution failed"
    else:
        raise AssertionError("resolver")

    async def empty(_hostname: str) -> list[str]:
        return []

    try:
        await Source("Laptop", rtsp_port=0).connect(missing, resolver=empty)
    except FallbackRequired as exc:
        assert exc.reason == "name resolution failed"
    else:
        raise AssertionError("empty resolver")


async def _timeouts() -> None:
    sink = await _listening_sink(session_timeout=0.2)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", sink.port)
        await asyncio.sleep(0.5)
        writer.close()
        await _wait_idle(sink)
    finally:
        await sink.stop()

    async def hold(reader, writer) -> None:
        try:
            await reader.readexactly(2)
            await asyncio.sleep(2)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        writer.close()

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        target = DiscoveredSink("TV", "tv", ("127.0.0.1",), port=port)
        try:
            await Source("Laptop", rtsp_port=0).connect(target, control_timeout=0.3)
        except FallbackRequired as exc:
            assert exc.reason == "control channel timeout"
        else:
            raise AssertionError("control timeout")
    finally:
        server.close()
        await server.wait_closed()

    async def swallow(reader, writer) -> None:
        try:
            header = await reader.readexactly(2)
            size = int.from_bytes(header, "big")
            await reader.readexactly(size - 2)
            await asyncio.sleep(2)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        writer.close()

    stalled = await asyncio.start_server(swallow, "127.0.0.1", 0)
    stalled_port = stalled.sockets[0].getsockname()[1]
    try:
        target = DiscoveredSink("TV", "tv", ("127.0.0.1",), port=stalled_port)
        try:
            await Source("Laptop", rtsp_port=0).connect(
                target,
                use_encryption=True,
                control_timeout=3,
                security_timeout=0.3,
            )
        except FallbackRequired as exc:
            assert exc.reason == "security handshake timeout"
        else:
            raise AssertionError("security timeout")
    finally:
        stalled.close()
        await stalled.wait_closed()


async def _vendor_extension_is_enough_to_connect() -> None:
    sink = await _listening_sink(addresses=("127.0.0.1",), bssid=bytes(6))
    session = None
    try:
        discovered = DiscoveredSink.from_vendor_extension(
            sink.vendor_extension().encode(),
            name=sink.friendly_name,
            port=sink.port,
            container_id=str(sink.container_id),
        )
        assert discovered.addresses == ("127.0.0.1",)
        assert discovered.unique_id == str(sink.container_id)
        assert discovered.capability is not None and discovered.capability.infrastructure
        session = await Source("Laptop", rtsp_port=0).connect(discovered, control_timeout=3)
        await _wait_projecting(sink)
        await session.close()
        session = None
        await _wait_idle(sink)

        async def resolver(hostname: str) -> list[str]:
            assert hostname == "livingroom"
            return ["127.0.0.1"]

        unnamed = DiscoveredSink("Living Room", "livingroom", (), port=sink.port)
        session = await Source("Laptop", rtsp_port=0).connect(unnamed, resolver=resolver, control_timeout=3)
        await _wait_projecting(sink)
    finally:
        if session is not None:
            await session.close()
        await sink.stop()
