# SPDX-License-Identifier: Apache-2.0
"""DTLS 1.2 records and handshake for the security-handshake messages.

Record framing, the AES-GCM nonce and additional data, and the TLS 1.2
PRF follow the pure-Python style of hue-entertainment
(https://github.com/music-assistant/hue-entertainment, Apache-2.0),
file hue_entertainment/dtls.py. Copyright music-assistant contributors.

The cipher suite, certificates, and when the handshake runs are for
this protocol: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, a self-signed
P-256 certificate, and datagrams carried in security-token TLVs. The
Hue entertainment stream is not implemented.

`cryptography` supplies AES-GCM, HMAC-SHA256, ECDH, and ECDSA.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.x509.oid import NameOID

from .constants import DTLS_CIPHER_SUITE, DTLS_EXPORTER_LABEL, DTLS_EXPORTER_LENGTH
from .errors import DtlsError

_DTLS_1_2 = 0xFEFD
_CT_CHANGE_CIPHER_SPEC = 0x14
_CT_ALERT = 0x15
_CT_HANDSHAKE = 0x16
_CT_APPLICATION_DATA = 0x17

_HT_CLIENT_HELLO = 0x01
_HT_SERVER_HELLO = 0x02
_HT_HELLO_VERIFY_REQUEST = 0x03
_HT_CERTIFICATE = 0x0B
_HT_SERVER_KEY_EXCHANGE = 0x0C
_HT_SERVER_HELLO_DONE = 0x0E
_HT_CLIENT_KEY_EXCHANGE = 0x10
_HT_FINISHED = 0x14

_NAMED_CURVE = 0x0017  # secp256r1
_CURVE_TYPE_NAMED = 3
_SHA256 = 4
_ECDSA = 3


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 P_SHA256."""
    result = b""
    block = _hmac_sha256(secret, label + seed)
    while len(result) < length:
        result += _hmac_sha256(secret, block + label + seed)
        block = _hmac_sha256(secret, block)
    return result[:length]


def _tls_random() -> bytes:
    return struct.pack("!I", int(time.time())) + os.urandom(28)


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _handshake(msg_type: int, seq: int, body: bytes) -> bytes:
    return (
        bytes((msg_type,))
        + _u24(len(body))
        + struct.pack("!H", seq)
        + _u24(0)
        + _u24(len(body))
        + body
    )


def _record(content_type: int, epoch: int, seq: int, fragment: bytes) -> bytes:
    return (
        struct.pack("!BHH", content_type, _DTLS_1_2, epoch)
        + seq.to_bytes(6, "big")
        + struct.pack("!H", len(fragment))
        + fragment
    )


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _client_extensions() -> bytes:
    signature_algorithms = _extension(0x000D, struct.pack("!H", 2) + bytes((_SHA256, _ECDSA)))
    groups = _extension(0x000A, struct.pack("!H", 2) + struct.pack("!H", _NAMED_CURVE))
    point_formats = _extension(0x000B, b"\x01\x00")
    blob = signature_algorithms + groups + point_formats
    return struct.pack("!H", len(blob)) + blob


def _server_extensions() -> bytes:
    blob = _extension(0x000B, b"\x01\x00")
    return struct.pack("!H", len(blob)) + blob


def _self_signed(identity: str) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity[:64] or "miracast")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.DER)


def _public_point(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _iter_records(data: bytes):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 13:
            raise DtlsError("short record header")
        content_type = data[offset]
        version = int.from_bytes(data[offset + 1 : offset + 3], "big")
        epoch = int.from_bytes(data[offset + 3 : offset + 5], "big")
        seq = int.from_bytes(data[offset + 5 : offset + 11], "big")
        length = int.from_bytes(data[offset + 11 : offset + 13], "big")
        offset += 13
        if version not in (0xFEFD, 0xFEFF):
            raise DtlsError("record version")
        if length > 18432 or offset + length > len(data):
            raise DtlsError("truncated record")
        fragment = data[offset : offset + length]
        offset += length
        yield content_type, epoch, seq, fragment


def _iter_handshake(fragment: bytes):
    offset = 0
    while offset < len(fragment):
        if len(fragment) - offset < 12:
            raise DtlsError("short handshake header")
        msg_type = fragment[offset]
        msg_len = int.from_bytes(fragment[offset + 1 : offset + 4], "big")
        frag_off = int.from_bytes(fragment[offset + 6 : offset + 9], "big")
        frag_len = int.from_bytes(fragment[offset + 9 : offset + 12], "big")
        if frag_off != 0 or frag_len != msg_len:
            raise DtlsError("fragmented handshake")
        end = offset + 12 + frag_len
        if end > len(fragment):
            raise DtlsError("truncated handshake")
        raw = fragment[offset:end]
        yield msg_type, raw[12:], raw
        offset = end


class DtlsConnection:
    """One DTLS 1.2 endpoint. Datagrams in, datagrams out. No sockets."""

    def __init__(self, role: str, identity: str, *, require_cookie: bool = False) -> None:
        if role not in ("client", "server"):
            raise ValueError("role")
        self.role = role
        self.require_cookie = require_cookie and role == "server"
        self._identity = identity or "miracast"
        self._transcript = bytearray()
        self._write_epoch = 0
        self._write_seq = 0
        self._read_epoch = 0
        self._read_seq = 0
        self._hs_seq = 0
        self._client_random = b""
        self._server_random = b""
        self._master = b""
        self._write_iv = b""
        self._read_iv = b""
        self._write_aead: AESGCM | None = None
        self._read_aead: AESGCM | None = None
        self._ephemeral = ec.generate_private_key(ec.SECP256R1())
        self._sign_key: ec.EllipticCurvePrivateKey | None = None
        self._cert_der = b""
        self._peer_cert_key: ec.EllipticCurvePublicKey | None = None
        self._peer_point = b""
        self._cookie = b""
        self._cookie_sent = False
        self._stage = "start" if role == "client" else "wait-hello"
        self._flight: list[bytes] = []
        self.complete = False
        if role == "server":
            self._sign_key, self._cert_der = _self_signed(self._identity)

    def start(self) -> list[bytes]:
        if self.role != "client":
            raise DtlsError("server waits for the first handshake message")
        self._client_random = _tls_random()
        hello = self._client_hello(b"")
        self._queue_records([self._plain_handshake(_HT_CLIENT_HELLO, hello)])
        self._stage = "wait-server"
        return self._take_flight()

    def handle(self, datagram: bytes) -> list[bytes]:
        if self.complete:
            raise DtlsError("handshake already complete")
        self._flight.clear()
        for content_type, epoch, seq, fragment in _iter_records(datagram):
            self._check_read_seq(epoch, seq)
            if content_type == _CT_ALERT:
                raise DtlsError("alert")
            if content_type == _CT_CHANGE_CIPHER_SPEC:
                if fragment != b"\x01":
                    raise DtlsError("change cipher spec")
                self._read_epoch = 1
                self._read_seq = 0
                continue
            if epoch != self._read_epoch:
                raise DtlsError("epoch")
            if content_type == _CT_HANDSHAKE and epoch == 0:
                payload = fragment
            elif content_type == _CT_HANDSHAKE and epoch == 1:
                payload = self._open(_CT_HANDSHAKE, epoch, seq, fragment)
            else:
                raise DtlsError("unexpected record")
            for msg_type, body, raw in _iter_handshake(payload):
                self._on_handshake(msg_type, body, raw)
            self._read_seq = seq + 1
        return self._take_flight()

    def send_application(self, plaintext: bytes) -> bytes:
        if not self.complete:
            raise DtlsError("handshake incomplete")
        return self._seal(_CT_APPLICATION_DATA, plaintext)

    def decrypt_application(self, datagram: bytes) -> bytes:
        if not self.complete:
            raise DtlsError("handshake incomplete")
        plain = b""
        for content_type, epoch, seq, fragment in _iter_records(datagram):
            self._check_read_seq(epoch, seq)
            if content_type != _CT_APPLICATION_DATA or epoch != 1:
                raise DtlsError("expected application data")
            plain += self._open(content_type, epoch, seq, fragment)
            self._read_seq = seq + 1
        return plain

    def export_key(
        self,
        length: int = DTLS_EXPORTER_LENGTH,
        label: bytes = DTLS_EXPORTER_LABEL,
    ) -> bytes:
        if not self.complete:
            raise DtlsError("handshake incomplete")
        return prf(self._master, label, self._client_random + self._server_random, length)

    def _take_flight(self) -> list[bytes]:
        flight = self._flight
        self._flight = []
        if not flight:
            return []
        return [b"".join(flight)]

    def _queue_records(self, records: list[bytes]) -> None:
        self._flight.extend(records)

    def _check_read_seq(self, epoch: int, seq: int) -> None:
        if epoch != self._read_epoch or seq != self._read_seq:
            raise DtlsError("record sequence")

    def _plain_handshake(self, msg_type: int, body: bytes, *, transcript: bool = True) -> bytes:
        raw = _handshake(msg_type, self._hs_seq, body)
        self._hs_seq += 1
        if transcript:
            self._transcript.extend(raw)
        record = _record(_CT_HANDSHAKE, self._write_epoch, self._write_seq, raw)
        self._write_seq += 1
        return record

    def _seal(self, content_type: int, plaintext: bytes) -> bytes:
        if self._write_aead is None:
            raise DtlsError("no write key")
        explicit = struct.pack("!H", self._write_epoch) + self._write_seq.to_bytes(6, "big")
        nonce = self._write_iv + explicit
        aad = explicit + struct.pack("!BHH", content_type, _DTLS_1_2, len(plaintext))
        sealed = self._write_aead.encrypt(nonce, plaintext, aad)
        fragment = explicit + sealed
        record = _record(content_type, self._write_epoch, self._write_seq, fragment)
        self._write_seq += 1
        return record

    def _open(self, content_type: int, epoch: int, seq: int, fragment: bytes) -> bytes:
        if self._read_aead is None or len(fragment) < 24:
            raise DtlsError("no read key")
        explicit = fragment[:8]
        expected = struct.pack("!H", epoch) + seq.to_bytes(6, "big")
        if explicit != expected:
            raise DtlsError("explicit nonce")
        plain_len = len(fragment) - 8 - 16
        aad = explicit + struct.pack("!BHH", content_type, _DTLS_1_2, plain_len)
        try:
            return self._read_aead.decrypt(self._read_iv + explicit, fragment[8:], aad)
        except InvalidTag as exc:
            raise DtlsError("authentication tag") from exc

    def _client_hello(self, cookie: bytes) -> bytes:
        body = bytearray()
        body += struct.pack("!H", _DTLS_1_2)
        body += self._client_random
        body.append(0)
        body.append(len(cookie))
        body += cookie
        body += struct.pack("!H", len(DTLS_CIPHER_SUITE))
        body += DTLS_CIPHER_SUITE
        body += b"\x01\x00"
        body += _client_extensions()
        return bytes(body)

    def _on_handshake(self, msg_type: int, body: bytes, raw: bytes) -> None:
        if self.role == "client":
            self._client_message(msg_type, body, raw)
        else:
            self._server_message(msg_type, body, raw)

    def _client_message(self, msg_type: int, body: bytes, raw: bytes) -> None:
        if msg_type == _HT_HELLO_VERIFY_REQUEST:
            if self._stage != "wait-server":
                raise DtlsError("unexpected hello verify")
            cookie = body[3 : 3 + body[2]]
            self._transcript.clear()
            hello = self._client_hello(cookie)
            self._queue_records([self._plain_handshake(_HT_CLIENT_HELLO, hello)])
            return
        if self._stage == "wait-server":
            self._transcript.extend(raw)
            if msg_type == _HT_SERVER_HELLO:
                self._parse_server_hello(body)
            elif msg_type == _HT_CERTIFICATE:
                self._parse_certificate(body)
            elif msg_type == _HT_SERVER_KEY_EXCHANGE:
                self._parse_server_key_exchange(body)
            elif msg_type == _HT_SERVER_HELLO_DONE:
                self._send_client_flight()
                self._stage = "wait-finished"
            else:
                raise DtlsError("unexpected server handshake")
            return
        if self._stage == "wait-finished" and msg_type == _HT_FINISHED:
            self._check_finished(body, b"server finished")
            self._transcript.extend(raw)
            self.complete = True
            self._stage = "done"
            return
        raise DtlsError("unexpected handshake message")

    def _server_message(self, msg_type: int, body: bytes, raw: bytes) -> None:
        if self._stage == "wait-hello" and msg_type == _HT_CLIENT_HELLO:
            random_bytes, cookie = _parse_client_hello(body)
            if self.require_cookie and cookie != self._cookie:
                if self._cookie_sent:
                    raise DtlsError("cookie")
                self._cookie = os.urandom(16)
                self._cookie_sent = True
                verify = struct.pack("!H", _DTLS_1_2) + bytes((len(self._cookie),)) + self._cookie
                # The cookie flight is not part of the finished transcript.
                saved = self._transcript
                self._transcript = bytearray()
                record = self._plain_handshake(
                    _HT_HELLO_VERIFY_REQUEST, verify, transcript=False
                )
                self._transcript = saved
                self._queue_records([record])
                return
            self._client_random = random_bytes
            self._transcript.extend(raw)
            self._send_server_flight()
            self._stage = "wait-client"
            return
        if self._stage == "wait-client" and msg_type == _HT_CLIENT_KEY_EXCHANGE:
            self._transcript.extend(raw)
            self._peer_point = body[1 : 1 + body[0]]
            self._derive(self._shared_secret(self._peer_point))
            return
        if self._stage == "wait-client" and msg_type == _HT_FINISHED:
            self._check_finished(body, b"client finished")
            self._transcript.extend(raw)
            self._send_server_finished()
            self.complete = True
            self._stage = "done"
            return
        raise DtlsError("unexpected handshake message")

    def _send_server_flight(self) -> None:
        assert self._sign_key is not None
        self._server_random = _tls_random()
        hello = bytearray()
        hello += struct.pack("!H", _DTLS_1_2)
        hello += self._server_random
        hello.append(0)
        hello += DTLS_CIPHER_SUITE
        hello.append(0)
        hello += _server_extensions()
        point = _public_point(self._ephemeral)
        params = (
            bytes((_CURVE_TYPE_NAMED,))
            + struct.pack("!H", _NAMED_CURVE)
            + bytes((len(point),))
            + point
        )
        signed = self._client_random + self._server_random + params
        signature = self._sign_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        key_exchange = params + bytes((_SHA256, _ECDSA)) + struct.pack("!H", len(signature)) + signature
        certs = _u24(len(self._cert_der)) + self._cert_der
        certificate = _u24(len(certs)) + certs
        records = [
            self._plain_handshake(_HT_SERVER_HELLO, bytes(hello)),
            self._plain_handshake(_HT_CERTIFICATE, certificate),
            self._plain_handshake(_HT_SERVER_KEY_EXCHANGE, key_exchange),
            self._plain_handshake(_HT_SERVER_HELLO_DONE, b""),
        ]
        self._queue_records(records)

    def _send_client_flight(self) -> None:
        if self._peer_cert_key is None or not self._peer_point:
            raise DtlsError("incomplete server flight")
        self._derive(self._shared_secret(self._peer_point))
        point = _public_point(self._ephemeral)
        key_exchange = bytes((len(point),)) + point
        records = [self._plain_handshake(_HT_CLIENT_KEY_EXCHANGE, key_exchange)]
        records.append(_record(_CT_CHANGE_CIPHER_SPEC, self._write_epoch, self._write_seq, b"\x01"))
        self._write_seq += 1
        self._write_epoch = 1
        self._write_seq = 0
        verify = prf(self._master, b"client finished", hashlib.sha256(self._transcript).digest(), 12)
        finished = _handshake(_HT_FINISHED, self._hs_seq, verify)
        self._hs_seq += 1
        records.append(self._seal(_CT_HANDSHAKE, finished))
        self._transcript.extend(finished)
        self._queue_records(records)

    def _send_server_finished(self) -> None:
        ccs = _record(_CT_CHANGE_CIPHER_SPEC, self._write_epoch, self._write_seq, b"\x01")
        self._write_seq += 1
        self._write_epoch = 1
        self._write_seq = 0
        verify = prf(self._master, b"server finished", hashlib.sha256(self._transcript).digest(), 12)
        finished = _handshake(_HT_FINISHED, self._hs_seq, verify)
        self._hs_seq += 1
        self._transcript.extend(finished)
        self._queue_records([ccs, self._seal(_CT_HANDSHAKE, finished)])

    def _parse_server_hello(self, body: bytes) -> None:
        if len(body) < 35:
            raise DtlsError("server hello")
        self._server_random = body[2:34]
        index = 34 + 1 + body[34]
        suite = body[index : index + 2]
        if suite != DTLS_CIPHER_SUITE:
            raise DtlsError("cipher suite")

    def _parse_certificate(self, body: bytes) -> None:
        if len(body) < 6:
            raise DtlsError("certificate")
        cert_len = int.from_bytes(body[3:6], "big")
        der = body[6 : 6 + cert_len]
        cert = x509.load_der_x509_certificate(der)
        public = cert.public_key()
        if not isinstance(public, ec.EllipticCurvePublicKey):
            raise DtlsError("certificate key")
        self._peer_cert_key = public

    def _parse_server_key_exchange(self, body: bytes) -> None:
        if self._peer_cert_key is None or body[0] != _CURVE_TYPE_NAMED:
            raise DtlsError("server key exchange")
        curve = int.from_bytes(body[1:3], "big")
        if curve != _NAMED_CURVE:
            raise DtlsError("curve")
        point_len = body[3]
        point = body[4 : 4 + point_len]
        rest = body[4 + point_len :]
        if rest[0] != _SHA256 or rest[1] != _ECDSA:
            raise DtlsError("signature algorithm")
        sig_len = int.from_bytes(rest[2:4], "big")
        signature = rest[4 : 4 + sig_len]
        params = body[: 4 + point_len]
        signed = self._client_random + self._server_random + params
        try:
            self._peer_cert_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise DtlsError("server key exchange signature") from exc
        self._peer_point = point

    def _shared_secret(self, point: bytes) -> bytes:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        return self._ephemeral.exchange(ec.ECDH(), peer)

    def _derive(self, shared: bytes) -> None:
        self._master = prf(
            shared,
            b"master secret",
            self._client_random + self._server_random,
            48,
        )
        block = prf(
            self._master,
            b"key expansion",
            self._server_random + self._client_random,
            40,
        )
        client_key, server_key = block[0:16], block[16:32]
        client_iv, server_iv = block[32:36], block[36:40]
        if self.role == "client":
            write_key, write_iv = client_key, client_iv
            read_key, read_iv = server_key, server_iv
        else:
            write_key, write_iv = server_key, server_iv
            read_key, read_iv = client_key, client_iv
        self._write_iv = write_iv
        self._read_iv = read_iv
        self._write_aead = AESGCM(write_key)
        self._read_aead = AESGCM(read_key)

    def _check_finished(self, body: bytes, label: bytes) -> None:
        expected = prf(self._master, label, hashlib.sha256(self._transcript).digest(), 12)
        if len(body) != 12 or not hmac_compare(body, expected):
            raise DtlsError("finished")


def hmac_compare(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    diff = 0
    for one, two in zip(left, right, strict=True):
        diff |= one ^ two
    return diff == 0


def _parse_client_hello(body: bytes) -> tuple[bytes, bytes]:
    if len(body) < 35:
        raise DtlsError("client hello")
    random_bytes = body[2:34]
    index = 34
    sid_len = body[index]
    index += 1 + sid_len
    cookie_len = body[index]
    index += 1
    cookie = body[index : index + cookie_len]
    index += cookie_len
    suite_len = int.from_bytes(body[index : index + 2], "big")
    index += 2
    suites = body[index : index + suite_len]
    if DTLS_CIPHER_SUITE not in _chunks(suites, 2):
        raise DtlsError("cipher suite")
    return random_bytes, cookie


def _chunks(data: bytes, size: int) -> list[bytes]:
    return [data[index : index + size] for index in range(0, len(data), size)]
