"""Miracast over Infrastructure and the Wi-Fi Display RTSP source.

The public surface is the source a Home Assistant media player needs:
discover sinks, connect, run the RTSP setup on the sink's TCP stream,
and close the session. This package does not encode video.
"""

from .codec import (
    Capability,
    PinChallenge,
    PinResponse,
    SecurityHandshake,
    SecurityOptions,
    SessionRequest,
    SourceReady,
    StopProjection,
    VendorExtension,
    decode_message,
    pin_hash,
)
from .constants import DEFAULT_RTSP_PORT, TCP_PORT
from .errors import DtlsError, FallbackRequired, MiceError, ProtocolError
from .mdns import discover_sinks
from .model import DiscoveredSink, RtspEndpoint
from .sink import Sink
from .source import Session, Source
from .wfd import AudioFormat, H264Format, RtpTarget, WfdSession, start_wfd

__all__ = [
    "AudioFormat",
    "Capability",
    "DEFAULT_RTSP_PORT",
    "DiscoveredSink",
    "DtlsError",
    "FallbackRequired",
    "H264Format",
    "MiceError",
    "PinChallenge",
    "PinResponse",
    "ProtocolError",
    "RtpTarget",
    "RtspEndpoint",
    "SecurityHandshake",
    "SecurityOptions",
    "Session",
    "SessionRequest",
    "Sink",
    "Source",
    "SourceReady",
    "StopProjection",
    "TCP_PORT",
    "VendorExtension",
    "WfdSession",
    "decode_message",
    "discover_sinks",
    "pin_hash",
    "start_wfd",
]
