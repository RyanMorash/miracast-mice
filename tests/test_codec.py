"""Encoding checks against the published message samples and PIN hashes."""

import hashlib

from miracast_mice import (
    PinChallenge,
    SecurityOptions,
    SessionRequest,
    SourceReady,
    StopProjection,
    VendorExtension,
    decode_message,
    pin_hash,
)
from miracast_mice.codec import Capability, decode_connection_preference, encode_connection_preference
from miracast_mice.constants import PIN_ACCEPTED
from miracast_mice.errors import ProtocolError

SOURCE_ID = bytes.fromhex("91f4abe9eff5464aaee269722aed11b5")
FRIENDLY = "Dummy1-Kabylake"

SOURCE_READY = bytes.fromhex(
    "003d0101"
    "00001e440075006d006d00790031002d004b00"
    "6100620079006c0061006b006500"
    "0200021c44"
    "03001091f4abe9eff5464aaee269722aed11b5"
)
STOP = bytes.fromhex(
    "00380102"
    "00001e440075006d006d00790031002d004b00"
    "6100620079006c0061006b006500"
    "03001091f4abe9eff5464aaee269722aed11b5"
)
VENDOR = bytes.fromhex(
    "1049001b000137"
    "2001000105"
    "2002000f44756d6d79312d4b6162796c616b65"
)
PIN_CHALLENGE = bytes.fromhex(
    "003a0105"
    "060020"
    "605409f832308ad0b893a7f91be42b26"
    "4c7372b36e9077506e1b4cc183de79da"
    "03001091f4abe9eff5464aaee269722aed11b5"
)
# The illustrated session-request size field is two short of the bytes shown.
SESSION_REQUEST = bytes.fromhex(
    "003a0104"
    "05000103"
    "00001e440075006d006d00790031002d004b00"
    "6100620079006c0061006b006500"
    "03001091f4abe9eff5464aaee269722aed11b5"
)
PIN_RESPONSE = bytes.fromhex(
    "002b0106"
    "060020"
    "18d8d8afdbd0d02b0c0d5d27ed058f8d"
    "f3afd860a45ef137ed257915a8bb2df7"
    "07000100"
)


def test_source_ready_sample_roundtrip() -> None:
    assert len(SOURCE_READY) == 0x3D
    message = decode_message(SOURCE_READY)
    assert isinstance(message, SourceReady)
    assert message.friendly_name == FRIENDLY
    assert message.rtsp_port == 7236
    assert message.source_id == SOURCE_ID
    assert message.encode() == SOURCE_READY


def test_stop_projection_sample_roundtrip() -> None:
    message = decode_message(STOP)
    assert isinstance(message, StopProjection)
    assert message.friendly_name == FRIENDLY
    assert message.source_id == SOURCE_ID
    assert message.encode() == STOP


def test_vendor_extension_sample_roundtrip() -> None:
    extension = VendorExtension.decode(VENDOR)
    assert extension.capability.infrastructure
    assert extension.capability.version == 1
    assert not extension.capability.stream_encryption
    assert not extension.capability.pin
    assert extension.hostname == FRIENDLY
    assert extension.encode() == VENDOR


def test_pin_challenge_sample_and_hash() -> None:
    digest = pin_hash("12345678", "192.0.2.100")
    assert digest == hashlib.sha256(b"12345678" + bytes((192, 0, 2, 100))).digest()
    assert digest.hex() == "605409f832308ad0b893a7f91be42b264c7372b36e9077506e1b4cc183de79da"
    message = decode_message(PIN_CHALLENGE)
    assert isinstance(message, PinChallenge)
    assert message.challenge == digest
    assert message.encode() == PIN_CHALLENGE
    ipv6 = pin_hash("98765432", "2001:db8:1f::4242")
    assert ipv6.hex() == "b3452b2c46c83d28d8d464b6697a81d1af3f356107e1d0731ea9bb183803f9c7"


def test_session_request_body_matches_sample() -> None:
    message = SessionRequest(FRIENDLY, SOURCE_ID, SecurityOptions(True, True))
    encoded = message.encode()
    assert encoded[:2] == b"\x00\x3c"
    assert encoded[2:] == SESSION_REQUEST[2:]
    assert len(SESSION_REQUEST) == 60
    decoded = decode_message(encoded)
    assert isinstance(decoded, SessionRequest)
    assert decoded.security is not None
    assert decoded.security.use_dtls and decoded.security.sink_displays_pin


def test_pin_response_sample_shape() -> None:
    message = decode_message(PIN_RESPONSE)
    from miracast_mice import PinResponse

    assert isinstance(message, PinResponse)
    assert message.reason == PIN_ACCEPTED
    assert message.challenge is not None and len(message.challenge) == 32
    assert message.source_id is None
    # The illustrated digest does not match the hash construction; the
    # construction is tested with the worked examples above.
    assert message.challenge != pin_hash("12345678", "192.0.2.200")


def test_security_options_and_capability_bits() -> None:
    options = SecurityOptions.decode(b"\x03\xff")
    assert options.use_dtls and options.sink_displays_pin and options.extra == b"\xff"
    try:
        SecurityOptions(False, True).encode()
    except ProtocolError:
        pass
    else:
        raise AssertionError("pin without encryption was encoded")
    capability = Capability.from_byte(0x05)
    assert capability.infrastructure and capability.version == 1
    masked = Capability.from_byte(0x21)
    assert masked.infrastructure and not masked.stream_encryption and not masked.pin
    assert Capability(True, True, pin=True).to_byte() == 0x27


def test_connection_preference_packing() -> None:
    encoded = encode_connection_preference((1, 2))
    assert encoded == bytes.fromhex("12000000")
    assert decode_connection_preference(encoded) == (1, 2)


def test_rejects_truncated_and_empty_tlv() -> None:
    for blob in (b"\x00\x03\x01\x01", b"\x00\x04\x01\x01\x00", bytes.fromhex("000601010000")):
        try:
            decode_message(blob)
        except ProtocolError:
            continue
        raise AssertionError(blob.hex())
