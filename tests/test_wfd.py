"""Wi-Fi Display source RTSP against a fake sink on one TCP stream."""

import asyncio
import contextlib

import pytest

from miracast_mice import ProtocolError, RtspEndpoint, start_wfd


def test_source_sequence_returns_plain_rtp() -> None:
    asyncio.run(_source_sequence_returns_plain_rtp())


def test_format_selection() -> None:
    asyncio.run(_format_selection())


def test_sink_rejects_parameters() -> None:
    asyncio.run(_sink_rejects_parameters())


def test_missing_constrained_baseline() -> None:
    asyncio.run(_missing_constrained_baseline())


def test_oversized_mode_is_rejected() -> None:
    asyncio.run(_oversized_mode_is_rejected())


def test_session_controls_and_keepalive() -> None:
    asyncio.run(_session_controls_and_keepalive())


def test_keepalive_minimum() -> None:
    asyncio.run(_keepalive_minimum())


class Msg:
    def __init__(self, start: str, headers: dict[str, str], body: bytes) -> None:
        self.start = start
        self.headers = headers
        self.body = body
        parts = start.split(" ")
        if start.upper().startswith("RTSP/"):
            self.status = int(parts[1])
            self.reason = " ".join(parts[2:])
            self.method = ""
            self.uri = ""
        else:
            self.status = 0
            self.reason = ""
            self.method = parts[0]
            self.uri = parts[1]


class FakeSink:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        video: str,
        audio: str = "AAC 00000001 00, LPCM 00000003 00",
        ports: str = "1028 0",
        protection: str | None = "HDCP2.1 port=4000",
        client_port: str = "1028",
        server_port: int = 5000,
        timeout: int = 30,
        url_host: str = "127.0.0.1",
        reject: bool = False,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.video = video
        self.audio = audio
        self.ports = ports
        self.protection = protection
        self.client_port = client_port
        self.server_port = server_port
        self.timeout = timeout
        self.url_host = url_host
        self.reject = reject
        self.buf = b""
        self.cseq = 0
        self.m4 = b""
        self.session_id = ""
        self.uri = f"rtsp://{url_host}/wfd1.0/streamid=0"

    async def read(self, timeout: float = 2) -> Msg:
        return await asyncio.wait_for(self._read(), timeout)

    async def _read(self) -> Msg:
        while b"\r\n\r\n" not in self.buf:
            chunk = await self.reader.read(4096)
            if not chunk:
                raise ConnectionError("connection lost")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, value = line.split(":", 1)
            assert value.startswith(" ")
            headers[name.strip().lower()] = value[1:]
        length = int(headers.get("content-length", "0"))
        while len(self.buf) < length:
            chunk = await self.reader.read(4096)
            if not chunk:
                raise ConnectionError("connection lost")
            self.buf += chunk
        body, self.buf = self.buf[:length], self.buf[length:]
        if "content-length" in headers:
            assert length == len(body)
        return Msg(lines[0], headers, body)

    async def respond(self, message: Msg, status: int = 200, reason: str = "OK", headers: dict[str, str] | None = None, body: bytes = b"") -> None:
        lines = [f"RTSP/1.0 {status} {reason}", f"CSeq: {message.headers['cseq']}"]
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        if body:
            lines.append("Content-Type: text/parameters")
            lines.append(f"Content-Length: {len(body)}")
        self.writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        await self.writer.drain()

    async def request(self, method: str, uri: str, headers: dict[str, str] | None = None, body: bytes = b"", cseq_name: str = "CSeq") -> None:
        self.cseq += 1
        lines = [f"{method} {uri} RTSP/1.0", f"{cseq_name}: {self.cseq}"]
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        if body:
            lines.append("Content-Type: text/parameters")
            lines.append(f"Content-Length: {len(body)}")
        self.writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        await self.writer.drain()

    async def negotiate(self) -> None:
        options = await self.read()
        assert options.method == "OPTIONS"
        assert options.uri == "*"
        assert options.headers["require"] == "org.wfa.wfd1.0"
        await self.respond(options, headers={"Public": "org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER"})
        await self.request("OPTIONS", "*", cseq_name="Cseq")
        answer = await self.read()
        assert answer.status == 200
        assert answer.headers["public"] == "org.wfa.wfd1.0, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER"

        query = await self.read()
        assert query.method == "GET_PARAMETER"
        assert query.uri == "rtsp://localhost/wfd1.0"
        assert b":" not in query.body
        for name in (b"wfd_video_formats", b"wfd_audio_codecs", b"wfd_client_rtp_ports", b"wfd_content_protection"):
            assert name + b"\r\n" in query.body
        lines = [
            f"wfd_video_formats: {self.video}",
            f"wfd_audio_codecs: {self.audio}",
            "wfd_3d_video_formats: none",
            f"wfd_client_rtp_ports: RTP/AVP/UDP;unicast {self.ports} mode=play",
        ]
        if self.protection is not None:
            lines.append(f"wfd_content_protection: {self.protection}")
        lines.extend(["wfd_display_edid: none", "wfd_coupled_sink: none"])
        await self.respond(query, body=("".join(f"{line}\r\n" for line in lines)).encode())

        chosen = await self.read()
        assert chosen.method == "SET_PARAMETER"
        assert chosen.headers["content-type"] == "text/parameters"
        self.m4 = chosen.body
        if self.reject:
            await self.respond(chosen, 303, "See Other", body=b"wfd_content_protection: 457\r\n")
            return
        await self.respond(chosen)

        trigger = await self.read()
        assert trigger.body == b"wfd_trigger_method: SETUP\r\n"
        assert trigger.headers["content-length"] == "27"
        await self.respond(trigger)
        await self.request(
            "SETUP",
            self.uri,
            {"Transport": f"RTP/AVP/UDP;unicast;client_port={self.client_port}"},
        )
        setup = await self.read()
        assert setup.status == 200
        session, _, timeout = setup.headers["session"].partition(";")
        assert len(session) == 8
        assert timeout == f"timeout={self.timeout}"
        rtp_port = self.client_port.split("-", 1)[0]
        assert setup.headers["transport"] == (
            f"RTP/AVP/UDP;unicast;client_port={rtp_port};server_port={self.server_port}"
        )
        assert "-" not in setup.headers["transport"]
        self.session_id = session
        await self.request("PLAY", self.uri, {"Session": self.session_id})
        play = await self.read()
        assert play.status == 200
        assert play.headers["session"] == self.session_id

    async def take_trigger(self, method: str) -> None:
        message = await self.read()
        assert message.method == "SET_PARAMETER"
        assert message.body == f"wfd_trigger_method: {method}\r\n".encode()
        assert message.headers["session"] == self.session_id
        await self.respond(message)
        await self.request(method, self.uri, {"Session": self.session_id})
        response = await self.read()
        assert response.status == 200

    async def idr(self) -> Msg:
        await self.request("SET_PARAMETER", self.uri, {"Session": self.session_id}, b"wfd_idr_request\r\n")
        response = await self.read()
        assert response.status == 200
        return response


def _video(profile: str = "01", level: str = "10", cea: str = "000000a0", vesa: str = "00000000", hh: str = "00000000") -> str:
    return f"00 00 {profile} {level} {cea} {vesa} {hh} 00 0000 0000 00 none none"


async def _pair(local_host: str = "127.0.0.1", sink_host: str = "192.0.2.50"):
    accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = asyncio.get_running_loop().create_future()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not accepted.done():
            accepted.set_result((reader, writer))

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets is not None
    port = sockets[0].getsockname()[1]
    sink_reader, sink_writer = await asyncio.open_connection("127.0.0.1", port)
    src_reader, src_writer = await accepted
    endpoint = RtspEndpoint(
        local_host,
        port,
        sink_host,
        sink_writer.get_extra_info("sockname")[1],
        src_reader,
        src_writer,
    )
    return endpoint, sink_reader, sink_writer, server


async def _close(endpoint: RtspEndpoint, sink_writer: asyncio.StreamWriter, server: asyncio.Server) -> None:
    sink_writer.close()
    endpoint.writer.close()
    server.close()
    await server.wait_closed()


async def _run(sink: FakeSink, endpoint: RtspEndpoint, **kwargs):
    loop = asyncio.get_running_loop()
    create_connection = loop.create_connection
    create_datagram = loop.create_datagram_endpoint

    async def refused(*_args, **_kwargs):
        raise AssertionError("the RTSP module opened a socket")

    loop.create_connection = refused  # type: ignore[method-assign]
    loop.create_datagram_endpoint = refused  # type: ignore[method-assign]
    source = asyncio.create_task(start_wfd(endpoint, **kwargs))
    peer = asyncio.create_task(sink.negotiate())
    try:
        session = await source
        await peer
        return session
    finally:
        loop.create_connection = create_connection  # type: ignore[method-assign]
        loop.create_datagram_endpoint = create_datagram  # type: ignore[method-assign]
        if not peer.done():
            peer.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await peer


async def _source_sequence_returns_plain_rtp() -> None:
    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), client_port="1028-1029", server_port=5000)
    try:
        session = await _run(sink, endpoint, server_port=5000)
        text = sink.m4.decode()
        assert "wfd_video_formats: 00 00 01 04 00000080 00000000 00000000 00 0000 0000 00 none none" in text
        assert "wfd_audio_codecs: AAC 00000001 00" in text
        assert "wfd_presentation_URL: rtsp://127.0.0.1/wfd1.0/streamid=0 none" in text
        assert "wfd_client_rtp_ports: RTP/AVP/UDP;unicast 1028 0 mode=play" in text
        assert "wfd_content_protection: none" in text
        assert "HDCP" not in text
        rtp = session.rtp
        assert rtp.host == "192.0.2.50"
        assert rtp.port == 1028
        assert rtp.server_port == 5000
        assert rtp.content_protection == "none"
        assert rtp.video.profile == "CBP"
        assert rtp.video.level == "4"
        assert (rtp.video.width, rtp.video.height, rtp.video.refresh_rate) == (1920, 1080, 30)
        assert rtp.video.interlaced is False
        assert (rtp.video.table, rtp.video.index) == ("CEA", 7)
        assert (rtp.audio.codec, rtp.audio.rate, rtp.audio.channels, rtp.audio.bits) == ("AAC", 48000, 2, 16)
        assert session.state == "playing"
        assert session.paused is False
        await asyncio.gather(session.teardown(), sink.take_trigger("TEARDOWN"))
        assert session.closed
        assert endpoint.writer.is_closing() is False
    finally:
        await _close(endpoint, writer, server)


async def _format_selection() -> None:
    cases = [
        {
            "video": _video(level="01"),
            "line": "00 00 01 01 00000020 00000000 00000000 00 0000 0000 00 none none",
            "level": "3.1",
            "size": (1280, 720, 30),
        },
        {
            "video": (
                "00 00 02 10 00000080 00000000 00000000 00 0000 0000 00 none none, "
                "01 04 00000020 00000000 00000000 00 0000 0000 00 none none"
            ),
            "line": "00 00 01 01 00000020 00000000 00000000 00 0000 0000 00 none none",
            "level": "3.1",
            "size": (1280, 720, 30),
        },
        {
            "video": _video(profile="03"),
            "line": "00 00 01 04 00000080 00000000 00000000 00 0000 0000 00 none none",
            "level": "4",
            "size": (1920, 1080, 30),
        },
    ]
    for case in cases:
        endpoint, reader, writer, server = await _pair()
        sink = FakeSink(reader, writer, video=case["video"])
        try:
            session = await _run(sink, endpoint)
            assert case["line"] in sink.m4.decode()
            assert session.rtp.video.level == case["level"]
            assert (session.rtp.video.width, session.rtp.video.height, session.rtp.video.refresh_rate) == case["size"]
            await session._stop_tasks()
        finally:
            await _close(endpoint, writer, server)

    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), audio="AAC 00000002 00, LPCM 00000003 00")
    try:
        session = await _run(sink, endpoint)
        assert "wfd_audio_codecs: LPCM 00000002 00" in sink.m4.decode()
        assert session.rtp.audio.codec == "LPCM"
        assert session.rtp.audio.rate == 48000
        await session._stop_tasks()
    finally:
        await _close(endpoint, writer, server)

    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), audio="LPCM 00000001 00")
    try:
        session = await _run(sink, endpoint)
        assert "wfd_audio_codecs: LPCM 00000001 00" in sink.m4.decode()
        assert session.rtp.audio.rate == 44100
        await session._stop_tasks()
    finally:
        await _close(endpoint, writer, server)

    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), audio="AC3 00000001 00")
    try:
        session = await _run(sink, endpoint)
        assert session.rtp.audio.codec == "AC3"
        await session._stop_tasks()
    finally:
        await _close(endpoint, writer, server)

    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), protection=None)
    try:
        session = await _run(sink, endpoint)
        assert b"wfd_content_protection" not in sink.m4
        await session._stop_tasks()
    finally:
        await _close(endpoint, writer, server)

    endpoint, reader, writer, server = await _pair(local_host="2001:db8::1")
    sink = FakeSink(reader, writer, video=_video(), url_host="[2001:db8::1]")
    try:
        session = await _run(sink, endpoint)
        assert "wfd_presentation_URL: rtsp://[2001:db8::1]/wfd1.0/streamid=0 none" in sink.m4.decode()
        await session._stop_tasks()
    finally:
        await _close(endpoint, writer, server)


async def _fail(sink: FakeSink, endpoint: RtspEndpoint, server: asyncio.Server, writer: asyncio.StreamWriter, match: str) -> None:
    source = asyncio.create_task(start_wfd(endpoint, request_timeout=2))
    peer = asyncio.create_task(sink.negotiate())
    try:
        with pytest.raises(ProtocolError, match=match):
            await source
    finally:
        peer.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await peer
        await _close(endpoint, writer, server)


async def _sink_rejects_parameters() -> None:
    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), reject=True)
    await _fail(sink, endpoint, server, writer, "rtsp status 303")


async def _missing_constrained_baseline() -> None:
    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(profile="02"))
    await _fail(sink, endpoint, server, writer, "constrained baseline is not advertised")


async def _oversized_mode_is_rejected() -> None:
    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(cea="00000000", vesa="10000000"))
    await _fail(sink, endpoint, server, writer, "no supported video format")


async def _session_controls_and_keepalive() -> None:
    endpoint, reader, writer, server = await _pair()
    sink = FakeSink(reader, writer, video=_video(), timeout=10)
    try:
        session = await _run(sink, endpoint, keepalive_timeout=10)
        await asyncio.gather(session.pause(), sink.take_trigger("PAUSE"))
        assert session.paused
        with pytest.raises(ProtocolError, match="not playing"):
            await session.pause()
        await asyncio.gather(session.resume(), sink.take_trigger("PLAY"))
        assert session.state == "playing"
        await sink.request("PLAY", sink.uri, {"Session": sink.session_id})
        rejected = await sink.read()
        assert rejected.status == 406
        assert rejected.reason == "in-play-state"
        waiter = asyncio.create_task(session.wait_idr())
        await sink.idr()
        await waiter
        assert session.idr_requests == 1
        await sink.request("PAUSE", sink.uri, {"Session": sink.session_id})
        paused = await sink.read()
        assert paused.status == 200
        assert session.paused
        await asyncio.gather(session.resume(), sink.take_trigger("PLAY"))
        keepalive = await sink.read(6)
        assert keepalive.method == "GET_PARAMETER"
        assert keepalive.body == b""
        assert keepalive.headers["session"] == sink.session_id
        await sink.respond(keepalive, 200)
        assert session.closed is False
        await sink.request("TEARDOWN", sink.uri, {"Session": sink.session_id})
        torn = await sink.read()
        assert torn.status == 200
        assert session.closed
        assert endpoint.writer.is_closing() is False
        await session.teardown()
    finally:
        await _close(endpoint, writer, server)


async def _keepalive_minimum() -> None:
    endpoint, _reader, writer, server = await _pair()
    try:
        with pytest.raises(ValueError, match="10"):
            await start_wfd(endpoint, keepalive_timeout=9)
    finally:
        await _close(endpoint, writer, server)
