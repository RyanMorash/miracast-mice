"""Async framing helpers for the TCP control connection."""

from __future__ import annotations

import asyncio
import socket

from .codec import SecurityHandshake, decode_payload, encode_frame
from .constants import CMD_SECURITY_HANDSHAKE
from .dtls import DtlsConnection
from .errors import ProtocolError

Message = object


def tune(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


async def open_tcp(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(host, port)
    tune(writer)
    return reader, writer


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        header = await reader.readexactly(2)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("control connection closed") from exc
    size = int.from_bytes(header, "big")
    if size < 4 or size > 0xFFFF:
        raise ProtocolError("frame size")
    try:
        rest = await reader.readexactly(size - 2)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("control connection closed") from exc
    return header + rest


async def send_frame(writer: asyncio.StreamWriter, frame: bytes) -> None:
    writer.write(frame)
    await writer.drain()


def protect(dtls: DtlsConnection | None, encrypt: bool, message) -> bytes:
    if encrypt:
        if dtls is None:
            raise ProtocolError("missing dtls session")
        return encode_frame(message.command, dtls.send_application(message.payload()))
    return message.encode()


def open_frame(dtls: DtlsConnection | None, encrypt: bool, frame: bytes):
    from .codec import split_frame

    command, payload = split_frame(frame)
    if encrypt and command != CMD_SECURITY_HANDSHAKE:
        if dtls is None:
            raise ProtocolError("missing dtls session")
        payload = dtls.decrypt_application(payload)
    return decode_payload(command, payload), command != CMD_SECURITY_HANDSHAKE and encrypt


def security_frame(token: bytes, source_id: bytes) -> bytes:
    return SecurityHandshake(token, source_id).encode()


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, RuntimeError):
        pass
