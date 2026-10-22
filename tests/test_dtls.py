"""DTLS handshake between a local client and server."""

from miracast_mice.dtls import DtlsConnection, prf
from miracast_mice.errors import DtlsError


def _finish(require_cookie: bool = False) -> tuple[DtlsConnection, DtlsConnection]:
    client = DtlsConnection("client", "Laptop")
    server = DtlsConnection("server", "Living Room", require_cookie=require_cookie)
    to_server = client.start()
    assert len(to_server) == 1
    for _ in range(6):
        to_client = []
        for datagram in to_server:
            to_client.extend(server.handle(datagram))
        if client.complete and server.complete:
            break
        to_server = []
        for datagram in to_client:
            to_server.extend(client.handle(datagram))
        if client.complete and server.complete:
            break
    assert client.complete and server.complete
    return client, server


def test_handshake_and_application_data() -> None:
    client, server = _finish()
    assert client.export_key() == server.export_key()
    blob = client.send_application(b"tlv-array")
    assert server.decrypt_application(blob) == b"tlv-array"
    reply = server.send_application(b"response-tlv")
    assert client.decrypt_application(reply) == b"response-tlv"
    second = client.send_application(b"next")
    assert server.decrypt_application(second) == b"next"


def test_cookie_exchange() -> None:
    client, server = _finish(require_cookie=True)
    assert client.export_key() == server.export_key()


def test_finished_tamper_fails() -> None:
    client = DtlsConnection("client", "Laptop")
    server = DtlsConnection("server", "Living Room")
    (hello,) = client.start()
    (flight,) = server.handle(hello)
    (client_flight,) = client.handle(flight)
    damaged = bytearray(client_flight)
    damaged[-1] ^= 0xFF
    try:
        server.handle(bytes(damaged))
    except DtlsError:
        return
    raise AssertionError("tampered finished was accepted")


def test_prf_is_stable() -> None:
    first = prf(b"secret", b"label", b"seed", 16)
    second = prf(b"secret", b"label", b"seed", 16)
    assert first == second
    assert len(first) == 16
    assert prf(b"secret", b"label", b"seed", 8) == first[:8]
