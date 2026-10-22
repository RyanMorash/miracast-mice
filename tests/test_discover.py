"""DNS-SD browse for the display service."""

import asyncio
import socket
import struct

from miracast_mice import DiscoveredSink, Sink, discover_sinks
from miracast_mice.mdns import (
    build_query,
    build_response,
    encode_name,
    parse_message,
    parse_txt,
    query_addresses,
    read_name,
    resolve_hostname,
)


def test_dns_codec_roundtrip() -> None:
    query = build_query("_display._tcp.local", 12, qid=0x1234)
    qid, flags, questions, records = parse_message(query)
    assert qid == 0x1234
    assert flags & 0x8000 == 0
    assert questions[0].name == "_display._tcp.local"
    assert questions[0].qclass & 0x8000
    item = b"container_id=abc"
    text = parse_txt(bytes((len(item),)) + item)
    assert text["container_id"] == "abc"
    packet = build_response(
        9,
        [
            ("_display._tcp.local", 12, 120, encode_name("Room._display._tcp.local")),
            ("host.local", 1, 120, socket.inet_aton("127.0.0.1")),
        ],
    )
    qid, flags, _questions, answers = parse_message(packet)
    assert qid == 9 and flags & 0x8000
    target, consumed = read_name(packet, answers[0].data_offset)
    assert target == "Room._display._tcp.local"
    assert consumed == answers[0].data_offset + len(answers[0].data)
    assert socket.inet_ntoa(answers[1].data) == "127.0.0.1"
    compressed = encode_name("host.local") + bytes((0xC0, 0))
    again, end = read_name(compressed, 0)
    assert again == "host.local"
    assert end == len(encode_name("host.local"))
    pointer = struct.pack("!H", 0xC000) 
    jumped, end = read_name(encode_name("only.local") + pointer, len(encode_name("only.local")))
    assert jumped == "only.local"
    assert end == len(encode_name("only.local")) + 2


def test_dotted_hostname_is_not_resolved() -> None:
    assert asyncio.run(resolve_hostname("tv.local")) == []


def test_discover_advertised_sink() -> None:
    asyncio.run(_discover_advertised_sink())


async def _discover_advertised_sink() -> None:
    sink = Sink(
        "Living Room",
        "livingroom",
        addresses=("127.0.0.1",),
        container_id="00112233-4455-6677-8899-aabbccddeeff",
    )
    await sink.start("127.0.0.1", 0, advertise=True)
    try:
        assert sink._advertiser is not None
        server = ("127.0.0.1", sink._advertiser.port)
        found = await discover_sinks(0.4, servers=[server])
        match = [item for item in found if item.container_id == str(sink.container_id)]
        assert len(match) == 1
        item = match[0]
        assert item.name == "Living Room"
        assert item.hostname == "livingroom"
        assert item.port == sink.port
        assert "127.0.0.1" in item.addresses
        assert item.unique_id == str(sink.container_id)
        addresses = await query_addresses("livingroom.local", 0.4, servers=[server])
        assert "127.0.0.1" in addresses
        info = DiscoveredSink(
            item.name,
            item.hostname,
            item.addresses,
            port=item.port,
            container_id=item.container_id,
        )
        assert info.hostname == "livingroom"
    finally:
        await sink.stop()
