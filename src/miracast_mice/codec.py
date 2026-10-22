"""Message, TLV, vendor-extension, and PIN hash encoding."""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field
from typing import ClassVar

from .constants import (
    ATTR_BSSID,
    ATTR_CAPABILITY,
    ATTR_CONNECTION_PREFERENCE,
    ATTR_HOST_NAME,
    ATTR_IP_ADDRESS,
    CAP_INFRASTRUCTURE,
    CAP_PIN,
    CAP_STREAM_ENCRYPTION,
    CAP_VERSION_SHIFT,
    CMD_PIN_CHALLENGE,
    CMD_PIN_RESPONSE,
    CMD_SECURITY_HANDSHAKE,
    CMD_SESSION_REQUEST,
    CMD_SOURCE_READY,
    CMD_STOP_PROJECTION,
    FRIENDLY_NAME_MAX_BYTES,
    OPT_SINK_DISPLAYS_PIN,
    OPT_USE_DTLS,
    PIN_HASH_LENGTH,
    PROTOCOL_VERSION,
    SOURCE_ID_LENGTH,
    TLV_FRIENDLY_NAME,
    TLV_PIN_CHALLENGE,
    TLV_PIN_RESPONSE_REASON,
    TLV_RTSP_PORT,
    TLV_SECURITY_OPTIONS,
    TLV_SECURITY_TOKEN,
    TLV_SOURCE_ID,
    WPS_OUI,
    WSC_VENDOR_EXTENSION,
)
from .errors import ProtocolError


def encode_frame(command: int, payload: bytes) -> bytes:
    """Build one length-prefixed message. The size covers the whole frame."""
    total = 4 + len(payload)
    if total > 0xFFFF:
        raise ProtocolError("message too large")
    return total.to_bytes(2, "big") + bytes((PROTOCOL_VERSION, command)) + payload


def split_frame(data: bytes) -> tuple[int, bytes]:
    """Return command and payload. `data` is one complete frame."""
    if len(data) < 4:
        raise ProtocolError("short frame")
    size = int.from_bytes(data[:2], "big")
    if size != len(data) or size < 4:
        raise ProtocolError("frame size does not match")
    if data[2] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported version")
    return data[3], data[4:]


def encode_tlv(tlv_type: int, value: bytes) -> bytes:
    if not 1 <= len(value) <= 0xFFFF:
        raise ProtocolError("invalid tlv length")
    return bytes((tlv_type,)) + len(value).to_bytes(2, "big") + value


def parse_tlvs(payload: bytes) -> list[tuple[int, bytes]]:
    if not payload:
        raise ProtocolError("tlv array is empty")
    items: list[tuple[int, bytes]] = []
    seen: set[int] = set()
    offset = 0
    while offset < len(payload):
        if offset + 3 > len(payload):
            raise ProtocolError("truncated tlv")
        tlv_type = payload[offset]
        length = int.from_bytes(payload[offset + 1 : offset + 3], "big")
        offset += 3
        if length < 1 or offset + length > len(payload):
            raise ProtocolError("invalid tlv length")
        if tlv_type in seen:
            raise ProtocolError("duplicate tlv")
        seen.add(tlv_type)
        items.append((tlv_type, payload[offset : offset + length]))
        offset += length
    return items


def encode_friendly_name(name: str) -> bytes:
    raw = name.encode("utf-16-le")
    if not raw or len(raw) > FRIENDLY_NAME_MAX_BYTES:
        raise ProtocolError("friendly name length")
    return encode_tlv(TLV_FRIENDLY_NAME, raw)


def decode_friendly_name(value: bytes) -> str:
    if not value or len(value) > FRIENDLY_NAME_MAX_BYTES or len(value) % 2:
        raise ProtocolError("friendly name length")
    return value.decode("utf-16-le")


def connection_address_bytes(ip: str | bytes) -> bytes:
    """Packed address used as the PIN salt. IPv4-mapped values use 4 bytes."""
    if isinstance(ip, bytes):
        if len(ip) == 4 or len(ip) == 16:
            return ip
        raise ProtocolError("address length")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ProtocolError("address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.packed


def pin_hash(pin: str, ip: str | bytes) -> bytes:
    """SHA-256 of the ASCII PIN immediately followed by the sender address."""
    try:
        pin_bytes = pin.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError("pin") from exc
    if not pin_bytes or b"\x00" in pin_bytes:
        raise ProtocolError("pin")
    return hashlib.sha256(pin_bytes + connection_address_bytes(ip)).digest()


def _source_id(value: bytes) -> bytes:
    if len(value) != SOURCE_ID_LENGTH:
        raise ProtocolError("source id length")
    return value


def _rtsp_port(value: bytes) -> int:
    if len(value) != 2:
        raise ProtocolError("rtsp port length")
    port = int.from_bytes(value, "big")
    if not 1 <= port <= 65535:
        raise ProtocolError("rtsp port")
    return port


@dataclass
class SecurityOptions:
    use_dtls: bool
    sink_displays_pin: bool
    extra: bytes = b""

    def encode(self) -> bytes:
        if self.sink_displays_pin and not self.use_dtls:
            raise ProtocolError("pin requires stream encryption")
        flags = (OPT_USE_DTLS if self.use_dtls else 0) | (
            OPT_SINK_DISPLAYS_PIN if self.sink_displays_pin else 0
        )
        return encode_tlv(TLV_SECURITY_OPTIONS, bytes((flags,)) + self.extra)

    @classmethod
    def decode(cls, value: bytes) -> SecurityOptions:
        if not value:
            raise ProtocolError("security options")
        flags = value[0]
        use_dtls = bool(flags & OPT_USE_DTLS)
        pin = bool(flags & OPT_SINK_DISPLAYS_PIN)
        if pin and not use_dtls:
            raise ProtocolError("pin requires stream encryption")
        return cls(use_dtls, pin, value[1:])


@dataclass
class SourceReady:
    source_id: bytes | None
    rtsp_port: int | None
    friendly_name: str | None = None
    command: ClassVar[int] = CMD_SOURCE_READY

    def payload(self) -> bytes:
        if self.source_id is None or self.rtsp_port is None:
            raise ProtocolError("incomplete source ready")
        parts: list[bytes] = []
        if self.friendly_name is not None:
            parts.append(encode_friendly_name(self.friendly_name))
        parts.append(encode_tlv(TLV_RTSP_PORT, self.rtsp_port.to_bytes(2, "big")))
        parts.append(encode_tlv(TLV_SOURCE_ID, _source_id(self.source_id)))
        return b"".join(parts)

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class StopProjection:
    source_id: bytes | None
    friendly_name: str | None
    command: ClassVar[int] = CMD_STOP_PROJECTION

    def payload(self) -> bytes:
        if self.source_id is None or self.friendly_name is None:
            raise ProtocolError("incomplete stop projection")
        return encode_friendly_name(self.friendly_name) + encode_tlv(
            TLV_SOURCE_ID, _source_id(self.source_id)
        )

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class SecurityHandshake:
    token: bytes | None
    source_id: bytes | None = None
    command: ClassVar[int] = CMD_SECURITY_HANDSHAKE

    def payload(self) -> bytes:
        if not self.token:
            raise ProtocolError("missing security token")
        parts = [encode_tlv(TLV_SECURITY_TOKEN, self.token)]
        if self.source_id is not None:
            parts.append(encode_tlv(TLV_SOURCE_ID, _source_id(self.source_id)))
        return b"".join(parts)

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class SessionRequest:
    friendly_name: str | None
    source_id: bytes | None
    security: SecurityOptions | None
    command: ClassVar[int] = CMD_SESSION_REQUEST

    def payload(self) -> bytes:
        if self.friendly_name is None or self.source_id is None or self.security is None:
            raise ProtocolError("incomplete session request")
        return b"".join(
            (
                self.security.encode(),
                encode_friendly_name(self.friendly_name),
                encode_tlv(TLV_SOURCE_ID, _source_id(self.source_id)),
            )
        )

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class PinChallenge:
    source_id: bytes | None
    challenge: bytes | None
    command: ClassVar[int] = CMD_PIN_CHALLENGE

    def payload(self) -> bytes:
        if self.source_id is None or self.challenge is None:
            raise ProtocolError("incomplete pin challenge")
        if len(self.challenge) != PIN_HASH_LENGTH:
            raise ProtocolError("pin challenge length")
        return encode_tlv(TLV_PIN_CHALLENGE, self.challenge) + encode_tlv(
            TLV_SOURCE_ID, _source_id(self.source_id)
        )

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class PinResponse:
    source_id: bytes | None
    reason: int | None
    challenge: bytes | None = None
    command: ClassVar[int] = CMD_PIN_RESPONSE

    def payload(self) -> bytes:
        if self.source_id is None or self.reason is None:
            raise ProtocolError("incomplete pin response")
        if not 0 <= self.reason <= 2:
            raise ProtocolError("pin reason")
        parts: list[bytes] = []
        if self.challenge is not None:
            if len(self.challenge) != PIN_HASH_LENGTH:
                raise ProtocolError("pin challenge length")
            parts.append(encode_tlv(TLV_PIN_CHALLENGE, self.challenge))
        parts.append(encode_tlv(TLV_PIN_RESPONSE_REASON, bytes((self.reason,))))
        parts.append(encode_tlv(TLV_SOURCE_ID, _source_id(self.source_id)))
        return b"".join(parts)

    def encode(self) -> bytes:
        return encode_frame(self.command, self.payload())


@dataclass
class UnknownMessage:
    command: int
    payload: bytes


Message = (
    SourceReady
    | StopProjection
    | SecurityHandshake
    | SessionRequest
    | PinChallenge
    | PinResponse
    | UnknownMessage
)


def decode_payload(command: int, payload: bytes) -> Message:
    if command == CMD_SECURITY_HANDSHAKE and payload and payload[0] != TLV_SECURITY_TOKEN:
        # Encrypted bodies are not TLV until the session decrypts them.
        pass
    try:
        items = parse_tlvs(payload)
    except ProtocolError:
        if command not in {
            CMD_SOURCE_READY,
            CMD_STOP_PROJECTION,
            CMD_SECURITY_HANDSHAKE,
            CMD_SESSION_REQUEST,
            CMD_PIN_CHALLENGE,
            CMD_PIN_RESPONSE,
        }:
            return UnknownMessage(command, payload)
        raise
    fields = dict(items)
    if command == CMD_SOURCE_READY:
        return SourceReady(
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
            rtsp_port=_rtsp_port(fields[TLV_RTSP_PORT]) if TLV_RTSP_PORT in fields else None,
            friendly_name=decode_friendly_name(fields[TLV_FRIENDLY_NAME])
            if TLV_FRIENDLY_NAME in fields
            else None,
        )
    if command == CMD_STOP_PROJECTION:
        return StopProjection(
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
            friendly_name=decode_friendly_name(fields[TLV_FRIENDLY_NAME])
            if TLV_FRIENDLY_NAME in fields
            else None,
        )
    if command == CMD_SECURITY_HANDSHAKE:
        return SecurityHandshake(
            token=fields.get(TLV_SECURITY_TOKEN),
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
        )
    if command == CMD_SESSION_REQUEST:
        return SessionRequest(
            friendly_name=decode_friendly_name(fields[TLV_FRIENDLY_NAME])
            if TLV_FRIENDLY_NAME in fields
            else None,
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
            security=SecurityOptions.decode(fields[TLV_SECURITY_OPTIONS])
            if TLV_SECURITY_OPTIONS in fields
            else None,
        )
    if command == CMD_PIN_CHALLENGE:
        return PinChallenge(
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
            challenge=fields.get(TLV_PIN_CHALLENGE),
        )
    if command == CMD_PIN_RESPONSE:
        reason = None
        if TLV_PIN_RESPONSE_REASON in fields:
            raw = fields[TLV_PIN_RESPONSE_REASON]
            if len(raw) != 1:
                raise ProtocolError("pin reason length")
            reason = raw[0]
        return PinResponse(
            source_id=fields.get(TLV_SOURCE_ID) and _source_id(fields[TLV_SOURCE_ID]),
            reason=reason,
            challenge=fields.get(TLV_PIN_CHALLENGE),
        )
    return UnknownMessage(command, payload)


def decode_message(data: bytes) -> Message:
    command, payload = split_frame(data)
    return decode_payload(command, payload)


@dataclass
class Capability:
    infrastructure: bool
    stream_encryption: bool
    version: int = 1
    pin: bool = False

    def to_byte(self) -> int:
        pin = self.pin and self.stream_encryption
        return (
            (CAP_INFRASTRUCTURE if self.infrastructure else 0)
            | (CAP_STREAM_ENCRYPTION if self.stream_encryption else 0)
            | ((self.version & 0x07) << CAP_VERSION_SHIFT)
            | (CAP_PIN if pin else 0)
        )

    @classmethod
    def from_byte(cls, value: int) -> Capability:
        encryption = bool(value & CAP_STREAM_ENCRYPTION)
        pin = bool(value & CAP_PIN) and encryption
        return cls(
            infrastructure=bool(value & CAP_INFRASTRUCTURE),
            stream_encryption=encryption,
            version=(value >> CAP_VERSION_SHIFT) & 0x07,
            pin=pin,
        )


def encode_connection_preference(transports: tuple[int, ...]) -> bytes:
    values = list(transports[:8])
    values.extend([0] * (8 - len(values)))
    out = bytearray(4)
    for index, ident in enumerate(values):
        if not 0 <= ident <= 0x0F:
            raise ProtocolError("transport id")
        if index % 2 == 0:
            out[index // 2] = ident << 4
        else:
            out[index // 2] |= ident
    return bytes(out)


def decode_connection_preference(value: bytes) -> tuple[int, ...]:
    if len(value) != 4:
        raise ProtocolError("connection preference length")
    idents: list[int] = []
    for byte in value:
        idents.append(byte >> 4)
        idents.append(byte & 0x0F)
    while idents and idents[-1] == 0:
        idents.pop()
    return tuple(idents)


@dataclass
class VendorExtension:
    capability: Capability
    hostname: str
    bssid: bytes | None = None
    connection_preference: tuple[int, ...] | None = None
    addresses: tuple[str, ...] = ()
    unknown: tuple[tuple[int, bytes], ...] = field(default_factory=tuple)

    def encode(self) -> bytes:
        body = bytearray(WPS_OUI)
        info = bytes((self.capability.to_byte(),))
        body += struct.pack(">HH", ATTR_CAPABILITY, len(info)) + info
        host = self.hostname.encode("ascii")
        if not host or b"." in host:
            raise ProtocolError("hostname")
        body += struct.pack(">HH", ATTR_HOST_NAME, len(host)) + host
        if self.bssid is not None:
            if len(self.bssid) != 6:
                raise ProtocolError("bssid")
            body += struct.pack(">HH", ATTR_BSSID, 6) + self.bssid
        if self.connection_preference is not None:
            pref = encode_connection_preference(self.connection_preference)
            body += struct.pack(">HH", ATTR_CONNECTION_PREFERENCE, len(pref)) + pref
        for address in self.addresses:
            raw = address.encode("ascii")
            connection_address_bytes(address)
            body += struct.pack(">HH", ATTR_IP_ADDRESS, len(raw)) + raw
        for attr_id, raw in self.unknown:
            body += struct.pack(">HH", attr_id, len(raw)) + raw
        return struct.pack(">HH", WSC_VENDOR_EXTENSION, len(body)) + bytes(body)

    @classmethod
    def decode(cls, data: bytes) -> VendorExtension:
        extension, consumed = cls._decode_at(data, 0)
        if consumed != len(data):
            raise ProtocolError("trailing vendor data")
        return extension

    @classmethod
    def _decode_at(cls, data: bytes, offset: int) -> tuple[VendorExtension, int]:
        if offset + 4 > len(data):
            raise ProtocolError("short vendor extension")
        attr_id, length = struct.unpack_from(">HH", data, offset)
        offset += 4
        if attr_id != WSC_VENDOR_EXTENSION or offset + length > len(data):
            raise ProtocolError("vendor extension header")
        body = data[offset : offset + length]
        offset += length
        if len(body) < 3 or body[:3] != WPS_OUI:
            raise ProtocolError("wps oui")
        cursor = 3
        capability: Capability | None = None
        hostname: str | None = None
        bssid: bytes | None = None
        preference: tuple[int, ...] | None = None
        addresses: list[str] = []
        unknown: list[tuple[int, bytes]] = []
        while cursor < len(body):
            if cursor + 4 > len(body):
                raise ProtocolError("truncated attribute")
            aid, alen = struct.unpack_from(">HH", body, cursor)
            cursor += 4
            if cursor + alen > len(body):
                raise ProtocolError("truncated attribute")
            value = body[cursor : cursor + alen]
            cursor += alen
            if aid == ATTR_CAPABILITY:
                if capability is not None or alen != 1:
                    raise ProtocolError("capability")
                capability = Capability.from_byte(value[0])
            elif aid == ATTR_HOST_NAME:
                if hostname is not None:
                    raise ProtocolError("hostname")
                try:
                    hostname = value.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ProtocolError("hostname") from exc
            elif aid == ATTR_BSSID:
                if bssid is not None or alen != 6:
                    raise ProtocolError("bssid")
                bssid = value
            elif aid == ATTR_CONNECTION_PREFERENCE:
                if preference is not None:
                    raise ProtocolError("connection preference")
                preference = decode_connection_preference(value)
            elif aid == ATTR_IP_ADDRESS:
                try:
                    text = value.decode("ascii")
                    connection_address_bytes(text)
                except (UnicodeDecodeError, ProtocolError) as exc:
                    raise ProtocolError("ip address") from exc
                addresses.append(text)
            else:
                unknown.append((aid, value))
        if capability is None or hostname is None:
            raise ProtocolError("missing required attribute")
        return (
            cls(capability, hostname, bssid, preference, tuple(addresses), tuple(unknown)),
            offset,
        )
