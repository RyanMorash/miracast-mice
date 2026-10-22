"""DNS-SD browse and announcement for the display service."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
from dataclasses import dataclass

from .constants import (
    CONTAINER_ID_KEY,
    MDNS_GROUP,
    MDNS_PORT,
    MDNS_SERVICE,
    TCP_PORT,
)
from .errors import ProtocolError
from .model import DiscoveredSink

_PTR = 12
_TXT = 16
_A = 1
_AAAA = 28
_SRV = 33
_ANY = 255
_IN = 1


def encode_name(name: str) -> bytes:
    labels = name.strip(".").split(".") if name.strip(".") else []
    out = bytearray()
    for label in labels:
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ProtocolError("dns label")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    seen: set[int] = set()
    guard = 0
    while True:
        guard += 1
        if guard > 64 or offset >= len(packet):
            raise ProtocolError("dns name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ProtocolError("dns pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen or pointer >= len(packet):
                raise ProtocolError("dns pointer")
            seen.add(pointer)
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length > 63 or offset + 1 + length > len(packet):
            raise ProtocolError("dns label")
        labels.append(packet[offset + 1 : offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


@dataclass
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: bytes
    data_offset: int


def parse_message(
    packet: bytes,
) -> tuple[int, int, list[DnsQuestion], list[DnsRecord]]:
    if len(packet) < 12:
        raise ProtocolError("dns header")
    qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet)
    offset = 12
    questions: list[DnsQuestion] = []
    for _ in range(qd):
        name, offset = read_name(packet, offset)
        qtype, qclass = struct.unpack_from("!HH", packet, offset)
        offset += 4
        questions.append(DnsQuestion(name, qtype, qclass))
    records: list[DnsRecord] = []
    for _ in range(an + ns + ar):
        name, offset = read_name(packet, offset)
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        data = packet[offset : offset + rdlen]
        records.append(DnsRecord(name, rtype, rclass, ttl, data, offset))
        offset += rdlen
    return qid, flags, questions, records


def build_query(name: str, qtype: int, qid: int | None = None) -> bytes:
    ident = os.urandom(2) if qid is None else qid.to_bytes(2, "big")
    header = ident + struct.pack("!HHHHH", 0, 1, 0, 0, 0)
    # QU bit asks for a unicast response.
    return header + encode_name(name) + struct.pack("!HH", qtype, _IN | 0x8000)


def build_response(qid: int, answers: list[tuple[str, int, int, bytes]]) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8400, 0, len(answers), 0, 0)
    body = bytearray()
    for name, rtype, ttl, rdata in answers:
        body += encode_name(name)
        body += struct.pack("!HHIH", rtype, _IN | 0x8000, ttl, len(rdata))
        body += rdata
    return header + bytes(body)


def _txt(values: dict[str, str]) -> bytes:
    out = bytearray()
    for key, value in values.items():
        item = f"{key}={value}".encode("utf-8")
        if len(item) > 255:
            raise ProtocolError("txt")
        out.append(len(item))
        out += item
    return bytes(out)


def parse_txt(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        item = data[offset : offset + length].decode("utf-8", "replace")
        offset += length
        if "=" in item:
            key, value = item.split("=", 1)
            result[key] = value
    return result


def _instance_label(fqdn: str) -> str | None:
    trimmed = fqdn.strip(".")
    suffix = "." + MDNS_SERVICE
    if not trimmed.lower().endswith(suffix):
        return None
    return trimmed[: -len(suffix)]


def _host_label(target: str) -> str:
    trimmed = target.strip(".")
    if trimmed.lower().endswith(".local"):
        return trimmed[: -len(".local")]
    return trimmed


class _Accumulator:
    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}
        self._addresses: dict[str, list[str]] = {}

    def add(self, packet: bytes, record: DnsRecord) -> None:
        key = record.name.strip(".").lower()
        if record.rtype == _PTR:
            try:
                target, _ = read_name(packet, record.data_offset)
            except ProtocolError:
                return
            self._rows.setdefault(target.strip(".").lower(), {"fqdn": target})
        elif record.rtype == _SRV and len(record.data) >= 6:
            port = int.from_bytes(record.data[4:6], "big")
            try:
                target, _ = read_name(packet, record.data_offset + 6)
            except ProtocolError:
                return
            row = self._rows.setdefault(key, {"fqdn": record.name})
            row["port"] = port
            row["target"] = target
        elif record.rtype == _TXT:
            row = self._rows.setdefault(key, {"fqdn": record.name})
            text = {k.lower(): v for k, v in parse_txt(record.data).items()}
            if CONTAINER_ID_KEY in text:
                row["container_id"] = text[CONTAINER_ID_KEY]
        elif record.rtype == _A and len(record.data) == 4:
            ip = socket.inet_ntoa(record.data)
            self._addresses.setdefault(key, [])
            if ip not in self._addresses[key]:
                self._addresses[key].append(ip)
        elif record.rtype == _AAAA and len(record.data) == 16:
            ip = socket.inet_ntop(socket.AF_INET6, record.data)
            self._addresses.setdefault(key, [])
            if ip not in self._addresses[key]:
                self._addresses[key].append(ip)

    def sinks(self) -> list[DiscoveredSink]:
        found: list[DiscoveredSink] = []
        for key, row in self._rows.items():
            label = _instance_label(row.get("fqdn", key))
            if label is None or "target" not in row:
                continue
            hostname = _host_label(row["target"])
            addresses = tuple(self._addresses.get(row["target"].strip(".").lower(), ()))
            found.append(
                DiscoveredSink(
                    name=label,
                    hostname=hostname,
                    addresses=addresses,
                    port=int(row.get("port", TCP_PORT)),
                    container_id=row.get("container_id"),
                )
            )
        return found


def _service_answers(
    *,
    name: str,
    hostname: str,
    port: int,
    addresses: tuple[str, ...],
    container_id: str,
    ttl: int = 120,
) -> list[tuple[str, int, int, bytes]]:
    instance = f"{name}.{MDNS_SERVICE}"
    target = f"{hostname}.local"
    answers: list[tuple[str, int, int, bytes]] = [
        (MDNS_SERVICE, _PTR, ttl, encode_name(instance)),
        (instance, _SRV, ttl, struct.pack("!HHH", 0, 0, port) + encode_name(target)),
        (instance, _TXT, ttl, _txt({CONTAINER_ID_KEY: container_id})),
    ]
    for address in addresses:
        try:
            parsed = socket.inet_pton(socket.AF_INET, address)
            answers.append((target, _A, ttl, parsed))
        except OSError:
            try:
                parsed6 = socket.inet_pton(socket.AF_INET6, address)
            except OSError:
                continue
            answers.append((target, _AAAA, ttl, parsed6))
    return answers


class _Advertiser(asyncio.DatagramProtocol):
    def __init__(self, answers: list[tuple[str, int, int, bytes]]) -> None:
        self.answers = answers
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if self.transport is None:
            return
        try:
            qid, flags, questions, _ = parse_message(data)
        except ProtocolError:
            return
        if flags & 0x8000:
            return
        selected: list[tuple[str, int, int, bytes]] = []
        service_query = any(
            question.name.strip(".").lower() == MDNS_SERVICE and question.qtype in (_PTR, _ANY)
            for question in questions
        )
        if service_query:
            selected = list(self.answers)
        else:
            for question in questions:
                qname = question.name.strip(".").lower()
                for name, rtype, ttl, rdata in self.answers:
                    if name.strip(".").lower() != qname:
                        continue
                    if question.qtype in (rtype, _ANY):
                        selected.append((name, rtype, ttl, rdata))
        # Unique by (name, type)
        unique: list[tuple[str, int, int, bytes]] = []
        seen: set[tuple[str, int]] = set()
        for item in selected:
            key = (item[0].lower(), item[1])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        if unique:
            self.transport.sendto(build_response(qid, unique), addr)


class ServiceAdvertiser:
    """Publish `<name>._display._tcp.local` with the container id."""

    def __init__(
        self,
        name: str,
        hostname: str,
        addresses: tuple[str, ...],
        port: int,
        container_id: str,
    ) -> None:
        self._answers = _service_answers(
            name=name,
            hostname=hostname,
            port=port,
            addresses=addresses,
            container_id=container_id,
        )
        self._transport: asyncio.BaseTransport | None = None

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> None:
        loop = asyncio.get_running_loop()
        protocol = _Advertiser(self._answers)
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(host, port),
        )
        sock = self._transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            except OSError:
                pass

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    @property
    def port(self) -> int:
        if self._transport is None:
            return 0
        sockname = self._transport.get_extra_info("sockname")
        return int(sockname[1]) if sockname else 0


def _join_mdns(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        group = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group)
    except OSError:
        pass


async def discover_sinks(
    timeout: float = 3.0,
    *,
    servers: list[tuple[str, int]] | None = None,
) -> list[DiscoveredSink]:
    """Browse `_display._tcp.local` and return sinks for a config flow.

    `servers` replaces the multicast group for tests and for a unicast DNS-SD
    responder. The default also queries 224.0.0.251 port 5353.
    """
    loop = asyncio.get_running_loop()
    inbox: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue()

    class _Browser(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            inbox.put_nowait((data, addr))

    transport, _ = await loop.create_datagram_endpoint(
        _Browser,
        local_addr=("0.0.0.0", 0),
    )
    sock = transport.get_extra_info("socket")
    if sock is not None:
        _join_mdns(sock)
    targets = list(servers or [])
    if not servers:
        targets.append((MDNS_GROUP, MDNS_PORT))
    query = build_query(MDNS_SERVICE, _PTR)
    for dest in targets:
        try:
            transport.sendto(query, dest)
        except OSError:
            continue
    found = _Accumulator()
    deadline = loop.time() + timeout
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                data, addr = await asyncio.wait_for(inbox.get(), remaining)
            except TimeoutError:
                break
            try:
                _, flags, _, records = parse_message(data)
            except ProtocolError:
                continue
            if not flags & 0x8000:
                continue
            for record in records:
                found.add(data, record)
    finally:
        transport.close()
    return found.sinks()


def _dns_lookup(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    result: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in result:
            result.append(address)
    return result


async def query_addresses(
    fqdn: str,
    timeout: float,
    *,
    servers: list[tuple[str, int]] | None = None,
) -> list[str]:
    """Resolve A and AAAA records. Used for an unqualified sink host name."""
    loop = asyncio.get_running_loop()
    inbox: asyncio.Queue[bytes] = asyncio.Queue()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            inbox.put_nowait(data)

    transport, _ = await loop.create_datagram_endpoint(_Proto, local_addr=("0.0.0.0", 0))
    sock = transport.get_extra_info("socket")
    if sock is not None:
        _join_mdns(sock)
    targets = list(servers or [(MDNS_GROUP, MDNS_PORT)])
    for qtype in (_A, _AAAA):
        query = build_query(fqdn, qtype)
        for dest in targets:
            try:
                transport.sendto(query, dest)
            except OSError:
                continue
    addresses: list[str] = []
    deadline = loop.time() + timeout
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(inbox.get(), remaining)
            except TimeoutError:
                break
            try:
                _, flags, _, records = parse_message(data)
            except ProtocolError:
                continue
            if not flags & 0x8000:
                continue
            for record in records:
                if record.rtype == _A and len(record.data) == 4:
                    ip = socket.inet_ntoa(record.data)
                elif record.rtype == _AAAA and len(record.data) == 16:
                    ip = socket.inet_ntop(socket.AF_INET6, record.data)
                else:
                    continue
                if ip not in addresses:
                    addresses.append(ip)
    finally:
        transport.close()
    return addresses


async def resolve_hostname(
    hostname: str,
    timeout: float = 1.5,
    *,
    servers: list[tuple[str, int]] | None = None,
) -> list[str]:
    """Resolve an unqualified host name with DNS and multicast DNS together."""
    if not hostname or "." in hostname:
        return []
    loop = asyncio.get_running_loop()

    async def from_dns() -> list[str]:
        return await loop.run_in_executor(None, _dns_lookup, hostname)

    async def from_mdns() -> list[str]:
        return await query_addresses(f"{hostname}.local", timeout, servers=servers)

    tasks = [asyncio.create_task(from_dns()), asyncio.create_task(from_mdns())]
    try:
        done, _pending = await asyncio.wait(tasks, timeout=timeout)
    finally:
        for task in tasks:
            task.cancel()
    ordered: list[str] = []
    for task in done:
        if task.cancelled():
            continue
        try:
            values = task.result()
        except Exception:
            continue
        for value in values:
            if value not in ordered:
                ordered.append(value)
    return ordered
