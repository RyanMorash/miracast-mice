"""Wi-Fi Display RTSP source session.

Speaks the source side of the RTSP control session on a TCP stream the sink
already opened. The result is a clear RTP target. MS-MICE requires RTP to be
encrypted with the DTLS key after a security handshake, but it never defines
the packet layout, nonce, or cipher, so this module does not apply that key.
"""

from __future__ import annotations

import asyncio
import math
import re
import secrets
from dataclasses import dataclass

from .errors import ProtocolError
from .model import RtspEndpoint

_PARAMETER_URI = "rtsp://localhost/wfd1.0"
_REQUEST_TIMEOUT = 5.0
_GAP_TIMEOUT = 6.0
_MIN_KEEPALIVE = 10
_DEFAULT_KEEPALIVE = 30
_DEFAULT_SERVER_PORT = 5000
_PUBLIC = "org.wfa.wfd1.0, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER"
_M3_NAMES = (
    "wfd_video_formats",
    "wfd_audio_codecs",
    "wfd_3d_video_formats",
    "wfd_content_protection",
    "wfd_display_edid",
    "wfd_coupled_sink",
    "wfd_client_rtp_ports",
)

# H.264 Table A-1 limits for the levels named by Wi-Fi Display Table 39.
# The display spec names the levels and does not restate MaxFS or MaxMBPS.
_LEVELS = (
    ("3.1", 0x01, 3600, 108_000),
    ("3.2", 0x02, 5120, 216_000),
    ("4", 0x04, 8192, 245_760),
    ("4.1", 0x08, 8192, 245_760),
    ("4.2", 0x10, 8704, 522_240),
)

# width, height, refresh rate, interlaced. Tables 34, 35, and 36.
_CEA = {
    0: (640, 480, 60, False),
    1: (720, 480, 60, False),
    2: (720, 480, 60, True),
    3: (720, 576, 50, False),
    4: (720, 576, 50, True),
    5: (1280, 720, 30, False),
    6: (1280, 720, 60, False),
    7: (1920, 1080, 30, False),
    8: (1920, 1080, 60, False),
    9: (1920, 1080, 60, True),
    10: (1280, 720, 25, False),
    11: (1280, 720, 50, False),
    12: (1920, 1080, 25, False),
    13: (1920, 1080, 50, False),
    14: (1920, 1080, 50, True),
    15: (1280, 720, 24, False),
    16: (1920, 1080, 24, False),
}
_VESA = {
    0: (800, 600, 30, False),
    1: (800, 600, 60, False),
    2: (1024, 768, 30, False),
    3: (1024, 768, 60, False),
    4: (1152, 864, 30, False),
    5: (1152, 864, 60, False),
    6: (1280, 768, 30, False),
    7: (1280, 768, 60, False),
    8: (1280, 800, 30, False),
    9: (1280, 800, 60, False),
    10: (1360, 768, 30, False),
    11: (1360, 768, 60, False),
    12: (1366, 768, 30, False),
    13: (1366, 768, 60, False),
    14: (1280, 1024, 30, False),
    15: (1280, 1024, 60, False),
    16: (1400, 1050, 30, False),
    17: (1400, 1050, 60, False),
    18: (1440, 900, 30, False),
    19: (1440, 900, 60, False),
    20: (1600, 900, 30, False),
    21: (1600, 900, 60, False),
    22: (1600, 1200, 30, False),
    23: (1600, 1200, 60, False),
    24: (1680, 1024, 30, False),
    25: (1680, 1024, 60, False),
    26: (1680, 1050, 30, False),
    27: (1680, 1050, 60, False),
    28: (1920, 1200, 30, False),
}
_HH = {
    0: (800, 480, 30, False),
    1: (800, 480, 60, False),
    2: (854, 480, 30, False),
    3: (854, 480, 60, False),
    4: (864, 480, 30, False),
    5: (864, 480, 60, False),
    6: (640, 360, 30, False),
    7: (640, 360, 60, False),
    8: (960, 540, 30, False),
    9: (960, 540, 60, False),
    10: (848, 480, 30, False),
    11: (848, 480, 60, False),
}
_TABLES = {"CEA": _CEA, "VESA": _VESA, "HH": _HH}
_PREFERRED = (
    ("CEA", 7),
    ("CEA", 5),
    ("CEA", 16),
    ("CEA", 12),
    ("CEA", 15),
    ("CEA", 10),
    ("CEA", 1),
    ("CEA", 3),
    ("CEA", 6),
    ("CEA", 11),
    ("CEA", 8),
    ("CEA", 13),
    ("CEA", 0),
)
_AUDIO = (
    ("AAC", 0, 48_000, 2),
    ("LPCM", 1, 48_000, 2),
    ("LPCM", 0, 44_100, 2),
    ("AC3", 0, 48_000, 2),
)
_CLIENT_PORT = re.compile(r"client_port=(\d+)")


@dataclass(frozen=True)
class H264Format:
    """Constrained-baseline mode selected for the sink."""

    profile: str
    level: str
    width: int
    height: int
    refresh_rate: int
    interlaced: bool
    table: str
    index: int


@dataclass(frozen=True)
class AudioFormat:
    """Audio mode selected for the sink."""

    codec: str
    rate: int
    channels: int
    bits: int


@dataclass(frozen=True)
class RtpTarget:
    """Plain UDP destination for MPEG-TS over RTP."""

    host: str
    port: int
    video: H264Format
    audio: AudioFormat
    content_protection: str = "none"
    server_port: int = _DEFAULT_SERVER_PORT


@dataclass
class _Codec:
    profile: int
    level: int
    cea: int
    vesa: int
    hh: int


@dataclass
class _Message:
    kind: str
    method: str
    uri: str
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    @property
    def cseq(self) -> int:
        try:
            return int(self.headers["cseq"])
        except (KeyError, ValueError) as exc:
            raise ProtocolError("malformed message") from exc


def _presentation_host(host: str) -> str:
    if ":" in host:
        return f"[{host}]"
    return host


def _macroblocks(width: int, height: int) -> int:
    return math.ceil(width / 16) * math.ceil(height / 16)


def _highest_level(mask: int) -> int | None:
    found = None
    for index, (_name, bit, _fs, _mbps) in enumerate(_LEVELS):
        if mask & bit:
            found = index
    return found


def _level_for(width: int, height: int, rate: int, interlaced: bool, mask: int) -> tuple[str, int] | None:
    """Lowest Table 39 level that can encode this picture and is within the sink maximum."""
    maximum = _highest_level(mask)
    if maximum is None:
        return None
    blocks = _macroblocks(width, height)
    # i60 and i50 are 30 and 25 frames per second.
    frames = rate // 2 if interlaced else rate
    per_second = blocks * frames
    for index, (name, bit, max_fs, max_mbps) in enumerate(_LEVELS):
        if index > maximum:
            return None
        if blocks <= max_fs and per_second <= max_mbps:
            return name, bit
    return None


def _parse_video(value: str) -> list[_Codec]:
    if value.strip().lower() == "none":
        raise ProtocolError("no supported video format")
    tokens = value.replace(",", " ").split()
    if len(tokens) < 13:
        raise ProtocolError("malformed message")
    rest = tokens[2:]
    codecs: list[_Codec] = []
    while rest:
        if len(rest) < 11:
            raise ProtocolError("malformed message")
        profile, level, cea, vesa, hh = rest[:5]
        rest = rest[11:]
        try:
            codecs.append(
                _Codec(
                    profile=int(profile, 16),
                    level=int(level, 16),
                    cea=int(cea, 16),
                    vesa=int(vesa, 16),
                    hh=int(hh, 16),
                )
            )
        except ValueError as exc:
            raise ProtocolError("malformed message") from exc
    return codecs


def _select_video(value: str) -> tuple[H264Format, int]:
    codecs = [codec for codec in _parse_video(value) if codec.profile & 0x01]
    if not codecs:
        raise ProtocolError("constrained baseline is not advertised")

    def fit(table: str, index: int) -> tuple[H264Format, int] | None:
        width, height, rate, interlaced = _TABLES[table][index]
        for codec in codecs:
            mask = {"CEA": codec.cea, "VESA": codec.vesa, "HH": codec.hh}[table]
            if not mask & (1 << index):
                continue
            level = _level_for(width, height, rate, interlaced, codec.level)
            if level is None:
                continue
            name, bit = level
            return (
                H264Format("CBP", name, width, height, rate, interlaced, table, index),
                bit,
            )
        return None

    seen: set[tuple[str, int]] = set()
    order: list[tuple[str, int]] = []
    for table, index in _PREFERRED:
        seen.add((table, index))
        order.append((table, index))
    for table, modes in _TABLES.items():
        for index in sorted(modes):
            if (table, index) in seen or modes[index][3]:
                continue
            order.append((table, index))
    for table, modes in _TABLES.items():
        for index in sorted(modes):
            if modes[index][3] and (table, index) not in seen:
                order.append((table, index))
    for table, index in order:
        chosen = fit(table, index)
        if chosen is not None:
            return chosen
    raise ProtocolError("no supported video format")


def _video_line(fmt: H264Format, level_bit: int) -> str:
    masks = {"CEA": 0, "VESA": 0, "HH": 0}
    masks[fmt.table] = 1 << fmt.index
    return (
        "00 00 01 "
        f"{level_bit:02x} "
        f"{masks['CEA']:08x} {masks['VESA']:08x} {masks['HH']:08x} "
        "00 0000 0000 00 none none"
    )


def _parse_audio(value: str) -> list[tuple[str, int]]:
    if value.strip().lower() == "none":
        return []
    codecs = []
    for item in value.split(","):
        parts = item.split()
        if len(parts) < 2:
            raise ProtocolError("malformed message")
        try:
            codecs.append((parts[0].upper(), int(parts[1], 16)))
        except ValueError as exc:
            raise ProtocolError("malformed message") from exc
    return codecs


def _select_audio(value: str) -> tuple[AudioFormat, str]:
    advertised = _parse_audio(value)
    for codec, bit, rate, channels in _AUDIO:
        for name, mask in advertised:
            if name == codec and mask & (1 << bit):
                fmt = AudioFormat(codec, rate, channels, 16)
                return fmt, f"{codec} {1 << bit:08x} 00"
    raise ProtocolError("no supported audio codec")


def _parse_ports(value: str) -> tuple[int, int]:
    parts = value.split()
    if len(parts) < 4 or parts[0].upper() != "RTP/AVP/UDP;UNICAST" or parts[3].lower() != "mode=play":
        raise ProtocolError("malformed message")
    try:
        port0 = int(parts[1])
        port1 = int(parts[2])
    except ValueError as exc:
        raise ProtocolError("malformed message") from exc
    if not 0 <= port0 <= 65535 or not 0 <= port1 <= 65535:
        raise ProtocolError("malformed message")
    if port0 == 0 or port1 != 0:
        raise ProtocolError("primary rtp port is missing")
    return port0, port1


def _parameters(body: bytes) -> dict[str, str]:
    found: dict[str, str] = {}
    text = body.decode("utf-8", "replace")
    for line in text.split("\r\n"):
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        found[name.strip().lower()] = value.strip()
    return found


def _encode_request(method: str, uri: str, cseq: int, headers: list[tuple[str, str]], body: bytes | None) -> bytes:
    lines = [f"{method} {uri} RTSP/1.0", f"CSeq: {cseq}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    if body is not None:
        lines.append("Content-Type: text/parameters")
        lines.append(f"Content-Length: {len(body)}")
    text = "\r\n".join(lines) + "\r\n\r\n"
    return text.encode() + (body or b"")


def _encode_response(status: int, reason: str, cseq: int, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"RTSP/1.0 {status} {reason}", f"CSeq: {cseq}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class WfdSession:
    """Running Wi-Fi Display source session on one RTSP TCP stream."""

    def __init__(
        self,
        endpoint: RtspEndpoint,
        *,
        server_port: int,
        keepalive_timeout: int,
        request_timeout: float,
    ) -> None:
        self._endpoint = endpoint
        self._reader = endpoint.reader
        self._writer = endpoint.writer
        self._server_port = server_port
        self._keepalive_timeout = keepalive_timeout
        self._request_timeout = request_timeout
        self._buffer = b""
        self._cseq = 0
        self._pending: dict[int, asyncio.Future[_Message]] = {}
        self._write_lock = asyncio.Lock()
        self._m2 = asyncio.Event()
        self._setup_done = asyncio.Event()
        self._play_done = asyncio.Event()
        self._trigger_done = asyncio.Event()
        self._waiting_for: str | None = None
        self._session_id = ""
        self._port0 = 0
        self._port1 = 0
        self._video: tuple[H264Format, int] | None = None
        self._audio: AudioFormat | None = None
        self._audio_line = ""
        self._include_protection = False
        self._setup_error: ProtocolError | None = None
        self._idr_waiters: list[asyncio.Future[None]] = []
        self._idr_unconsumed = 0
        self._reader_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._aborted = False
        self._torn = False
        self.idr_requests = 0
        self.closed = False
        self.state = "setup"
        self.rtp: RtpTarget

    @property
    def paused(self) -> bool:
        return self.state == "paused"

    async def pause(self) -> None:
        """Ask the sink to pause, then answer its PAUSE."""
        if self.state != "playing":
            raise ProtocolError("not playing")
        await self._trigger_and_wait("PAUSE")

    async def resume(self) -> None:
        """Ask the sink to play again, then answer its PLAY."""
        if self.state != "paused":
            raise ProtocolError("not paused")
        await self._trigger_and_wait("PLAY")

    async def teardown(self) -> None:
        """Ask the sink to tear the RTSP session down. The TCP stream stays open."""
        if self._torn:
            return
        self._torn = True
        await self._cancel_keepalive()
        try:
            if self.state in ("playing", "paused"):
                await self._trigger_and_wait("TEARDOWN")
        finally:
            await self._stop_tasks()

    async def wait_idr(self) -> None:
        """Wait until the sink has asked for an IDR picture."""
        if self._idr_unconsumed:
            self._idr_unconsumed -= 1
            return
        if self.closed:
            raise ConnectionError("connection lost")
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._idr_waiters.append(future)
        try:
            await future
        finally:
            if future in self._idr_waiters:
                self._idr_waiters.remove(future)

    async def _negotiate(self) -> None:
        await self._request("OPTIONS", "*", [("Require", "org.wfa.wfd1.0")])
        await self._wait(self._m2, "OPTIONS")
        query = "".join(f"{name}\r\n" for name in _M3_NAMES).encode()
        response = await self._request("GET_PARAMETER", _PARAMETER_URI, body=query)
        params = _parameters(response.body)
        try:
            video_value = params["wfd_video_formats"]
            audio_value = params["wfd_audio_codecs"]
            ports_value = params["wfd_client_rtp_ports"]
        except KeyError as exc:
            raise ProtocolError("malformed message") from exc
        self._video = _select_video(video_value)
        self._audio, self._audio_line = _select_audio(audio_value)
        self._port0, self._port1 = _parse_ports(ports_value)
        self._include_protection = "wfd_content_protection" in params
        await self._request("SET_PARAMETER", _PARAMETER_URI, body=self._m4_body())
        await self._request("SET_PARAMETER", _PARAMETER_URI, body=b"wfd_trigger_method: SETUP\r\n")
        await self._wait(self._setup_done, "SETUP")
        if self._setup_error is not None:
            raise self._setup_error
        await self._wait(self._play_done, "PLAY")

    def _m4_body(self) -> bytes:
        assert self._video is not None
        video, level_bit = self._video
        host = _presentation_host(self._endpoint.local_host)
        lines = [
            f"wfd_video_formats: {_video_line(video, level_bit)}",
            f"wfd_audio_codecs: {self._audio_line}",
            f"wfd_presentation_URL: rtsp://{host}/wfd1.0/streamid=0 none",
            f"wfd_client_rtp_ports: RTP/AVP/UDP;unicast {self._port0} {self._port1} mode=play",
        ]
        if self._include_protection:
            lines.append("wfd_content_protection: none")
        return ("".join(f"{line}\r\n" for line in lines)).encode()

    async def _trigger_and_wait(self, method: str) -> None:
        self._trigger_done.clear()
        self._waiting_for = method
        try:
            await self._request(
                "SET_PARAMETER",
                _PARAMETER_URI,
                body=f"wfd_trigger_method: {method}\r\n".encode(),
                session=True,
            )
            await self._wait(self._trigger_done, method)
        finally:
            self._waiting_for = None

    async def _wait(self, event: asyncio.Event, what: str) -> None:
        try:
            await asyncio.wait_for(event.wait(), _GAP_TIMEOUT)
        except TimeoutError:
            error = ProtocolError(f"timed out waiting for {what}")
            self._abort(error)
            raise error from None

    async def _request(
        self,
        method: str,
        uri: str,
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
        *,
        session: bool = False,
        timeout: float | None = None,
        accept_any: bool = False,
    ) -> _Message:
        if self.closed:
            raise ConnectionError("connection lost")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[_Message] = loop.create_future()
        extra = list(headers or [])
        if session and self._session_id:
            extra.insert(0, ("Session", self._session_id))
        async with self._write_lock:
            self._cseq += 1
            cseq = self._cseq
            self._pending[cseq] = future
            self._writer.write(_encode_request(method, uri, cseq, extra, body))
        try:
            await self._writer.drain()
        except (ConnectionError, OSError) as exc:
            self._pending.pop(cseq, None)
            raise ConnectionError("connection lost") from exc
        try:
            try:
                message = await asyncio.wait_for(future, self._request_timeout if timeout is None else timeout)
            except TimeoutError:
                raise ProtocolError("timed out waiting for a response") from None
        finally:
            self._pending.pop(cseq, None)
        if not accept_any and message.status != 200:
            raise ProtocolError(f"rtsp status {message.status}")
        return message

    async def _respond(self, message: _Message, status: int, reason: str, headers: list[tuple[str, str]] | None = None) -> None:
        data = _encode_response(status, reason, message.cseq, headers or [])
        async with self._write_lock:
            self._writer.write(data)
        try:
            await self._writer.drain()
        except (ConnectionError, OSError) as exc:
            raise ConnectionError("connection lost") from exc

    async def _read_loop(self) -> None:
        try:
            while not self.closed:
                message = await self._read_message()
                await self._dispatch(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._abort(exc)

    async def _read_message(self) -> _Message:
        while b"\r\n\r\n" not in self._buffer:
            chunk = await self._reader.read(4096)
            if not chunk:
                raise ConnectionError("connection lost")
            self._buffer += chunk
            if len(self._buffer) > 1_048_576:
                raise ProtocolError("malformed message")
        head, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
        lines = head.decode("utf-8", "replace").split("\r\n")
        if not lines or not lines[0]:
            raise ProtocolError("malformed message")
        start = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise ProtocolError("malformed message")
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        length = 0
        if "content-length" in headers:
            try:
                length = int(headers["content-length"])
            except ValueError as exc:
                raise ProtocolError("malformed message") from exc
        if length < 0:
            raise ProtocolError("malformed message")
        while len(self._buffer) < length:
            chunk = await self._reader.read(4096)
            if not chunk:
                raise ConnectionError("connection lost")
            self._buffer += chunk
        body, self._buffer = self._buffer[:length], self._buffer[length:]
        upper = start.upper()
        if upper.startswith("RTSP/1.0 "):
            parts = start.split(" ", 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError) as exc:
                raise ProtocolError("malformed message") from exc
            reason = parts[2] if len(parts) > 2 else ""
            return _Message("response", "", "", status, reason, headers, body)
        if not upper.endswith(" RTSP/1.0"):
            raise ProtocolError("malformed message")
        try:
            method, uri = start[: -len(" RTSP/1.0")].split(" ", 1)
        except ValueError as exc:
            raise ProtocolError("malformed message") from exc
        return _Message("request", method, uri, 0, "", headers, body)

    async def _dispatch(self, message: _Message) -> None:
        if message.kind == "response":
            future = self._pending.get(message.cseq)
            if future is not None and not future.done():
                future.set_result(message)
            return
        if "cseq" not in message.headers:
            raise ProtocolError("malformed message")
        handlers = {
            "OPTIONS": self._on_options,
            "SETUP": self._on_setup,
            "PLAY": self._on_play,
            "PAUSE": self._on_pause,
            "TEARDOWN": self._on_teardown,
            "SET_PARAMETER": self._on_set_parameter,
            "GET_PARAMETER": self._on_get_parameter,
        }
        handler = handlers.get(message.method)
        if handler is None:
            await self._respond(message, 405, "Method Not Allowed")
            return
        await handler(message)

    async def _on_options(self, message: _Message) -> None:
        await self._respond(message, 200, "OK", [("Public", _PUBLIC)])
        self._m2.set()

    async def _on_setup(self, message: _Message) -> None:
        if self._setup_done.is_set():
            await self._respond(message, 455, "Method Not Valid in This State")
            return
        match = _CLIENT_PORT.search(message.headers.get("transport", ""))
        port = int(match.group(1)) if match else None
        if self._video is None or self._audio is None or self._port0 == 0:
            self._setup_error = ProtocolError("unsupported transport")
            await self._respond(message, 455, "Method Not Valid in This State")
            self._setup_done.set()
            return
        if "streamid=0" not in message.uri or port != self._port0:
            self._setup_error = ProtocolError("unsupported transport")
            await self._respond(message, 461, "Unsupported Transport")
            self._setup_done.set()
            return
        self._session_id = secrets.token_hex(4).upper()
        video, _level_bit = self._video
        transport = f"RTP/AVP/UDP;unicast;client_port={port};server_port={self._server_port}"
        await self._respond(
            message,
            200,
            "OK",
            [
                ("Session", f"{self._session_id};timeout={self._keepalive_timeout}"),
                ("Transport", transport),
            ],
        )
        self.rtp = RtpTarget(
            host=self._endpoint.sink_host,
            port=port,
            video=video,
            audio=self._audio,
            content_protection="none",
            server_port=self._server_port,
        )
        self._setup_done.set()

    async def _on_play(self, message: _Message) -> None:
        if not await self._accept_session(message):
            return
        if not self._setup_done.is_set():
            await self._respond(message, 455, "Method Not Valid in This State")
            return
        if self.state == "playing":
            await self._respond(message, 406, "in-play-state", self._session_header())
            return
        if self.state not in ("setup", "paused"):
            await self._respond(message, 455, "Method Not Valid in This State")
            return
        await self._respond(message, 200, "OK", self._session_header())
        self.state = "playing"
        self._play_done.set()
        if self._waiting_for == "PLAY":
            self._trigger_done.set()

    async def _on_pause(self, message: _Message) -> None:
        if not await self._accept_session(message):
            return
        if self.state == "paused":
            await self._respond(message, 406, "in-pause-state", self._session_header())
            return
        if self.state != "playing":
            await self._respond(message, 455, "Method Not Valid in This State")
            return
        await self._respond(message, 200, "OK", self._session_header())
        self.state = "paused"
        if self._waiting_for == "PAUSE":
            self._trigger_done.set()

    async def _on_teardown(self, message: _Message) -> None:
        if not await self._accept_session(message):
            return
        await self._respond(message, 200, "OK", self._session_header())
        self.state = "closed"
        self.closed = True
        self._trigger_done.set()
        await self._cancel_keepalive()

    async def _on_set_parameter(self, message: _Message) -> None:
        await self._respond(message, 200, "OK", self._session_header())
        text = message.body.decode("utf-8", "replace")
        for line in text.split("\r\n"):
            name = line.split(":", 1)[0].strip().lower()
            if name == "wfd_idr_request":
                self._note_idr()
                break

    async def _on_get_parameter(self, message: _Message) -> None:
        if not await self._accept_session(message):
            return
        await self._respond(message, 200, "OK", self._session_header())

    def _note_idr(self) -> None:
        self.idr_requests += 1
        waiters = [future for future in self._idr_waiters if not future.done()]
        self._idr_waiters.clear()
        if waiters:
            for future in waiters:
                future.set_result(None)
        else:
            self._idr_unconsumed += 1

    def _session_header(self) -> list[tuple[str, str]]:
        if not self._session_id:
            return []
        return [("Session", self._session_id)]

    async def _accept_session(self, message: _Message) -> bool:
        raw = message.headers.get("session")
        if raw is None or not self._session_id:
            return True
        if raw.split(";", 1)[0].strip().lower() == self._session_id.lower():
            return True
        await self._respond(message, 454, "Session Not Found")
        return False

    async def _keepalive(self) -> None:
        interval = self._keepalive_timeout - 6
        try:
            while not self.closed:
                await asyncio.sleep(interval)
                if self.closed:
                    return
                await self._request(
                    "GET_PARAMETER",
                    _PARAMETER_URI,
                    session=True,
                    timeout=float(self._keepalive_timeout),
                    accept_any=True,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._abort(exc)

    def _abort(self, exc: BaseException) -> None:
        if self._aborted:
            return
        self._aborted = True
        self.closed = True
        self.state = "closed"
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(exc)
        for future in self._idr_waiters:
            if not future.done():
                future.set_exception(exc)
        self._idr_waiters.clear()
        current = asyncio.current_task()
        for task in (self._reader_task, self._keepalive_task):
            if task is not None and task is not current and not task.done():
                task.cancel()

    async def _cancel_keepalive(self) -> None:
        task = self._keepalive_task
        if task is None or task.done():
            return
        if task is asyncio.current_task():
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    async def _stop_tasks(self) -> None:
        self.closed = True
        self.state = "closed"
        await self._cancel_keepalive()
        task = self._reader_task
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


async def start_wfd(
    endpoint: RtspEndpoint,
    *,
    server_port: int = _DEFAULT_SERVER_PORT,
    keepalive_timeout: int = _DEFAULT_KEEPALIVE,
    request_timeout: float = _REQUEST_TIMEOUT,
) -> WfdSession:
    """Run M1 through M7 on the sink's existing RTSP connection.

    `endpoint` is `session.rtsp_endpoint`. This function does not open a
    second TCP connection and does not bind the RTP port.
    """
    if keepalive_timeout < _MIN_KEEPALIVE:
        raise ValueError("keepalive timeout must be at least 10 seconds")
    if not 1 <= server_port <= 65535:
        raise ValueError("server port is out of range")
    if request_timeout <= 0:
        raise ValueError("request timeout must be positive")
    session = WfdSession(
        endpoint,
        server_port=server_port,
        keepalive_timeout=keepalive_timeout,
        request_timeout=request_timeout,
    )
    session._reader_task = asyncio.create_task(session._read_loop())
    try:
        await session._negotiate()
    except BaseException:
        await session._stop_tasks()
        raise
    session._keepalive_task = asyncio.create_task(session._keepalive())
    return session
