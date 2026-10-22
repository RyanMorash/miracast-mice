# Miracast source library

Python library for Miracast source mode. A Home Assistant media player uses it to list sinks, open an MS-MICE session, and run the Wi-Fi Display RTSP setup on the TCP stream the sink opens back. The RTSP setup returns a plain RTP target. The integration encodes with ffmpeg and sends MPEG-TS to that target. This package does not encode video or start ffmpeg.

`cryptography` is the only runtime dependency.

## Tests

From the repository root:

```bash
python3 -m pytest
```

## Public API

```python
from miracast_mice import Source, discover_sinks, start_wfd

sinks = await discover_sinks(timeout=5)
session = await Source("Laptop").connect(sinks[0])
wfd = await start_wfd(session.rtsp_endpoint)

target = wfd.rtp
# target.host is the sink address.
# target.port is the sink UDP port from wfd_client_rtp_ports.
# target.video is the chosen constrained-baseline H.264 mode.
# target.audio is the chosen audio mode.
# target.content_protection is "none".
# target.server_port is the RTP port named in the SETUP response.

await wfd.teardown()
await session.close()
```

`discover_sinks` browses `_display._tcp` and returns `DiscoveredSink` values a config flow can list: `name`, `hostname`, `addresses`, `port`, `container_id`, `unique_id`, and `capability` when known. `DiscoveredSink.from_vendor_extension` loads the same record from beacon or probe vendor-extension bytes.

Default `connect` does not request stream encryption or a PIN. Opt in with `use_encryption=True`, or `use_pin=True` and a `pin` string or async callable. `use_pin` turns encryption on. After a protected session, `session.encryption_key` is the exported DTLS key. `session.pin_used` and `session.stream_encryption` record what this session selected. RTP stays a clear UDP target either way: MS-MICE does not define how that key wraps an RTP packet.

`start_wfd` uses the reader and writer already on `session.rtsp_endpoint`. It sends M1, answers M2, sends M3 and M4, triggers SETUP, and answers the sink's SETUP and PLAY. `keepalive_timeout` defaults to 30 seconds and must be at least 10. `server_port` defaults to 5000 and is only a header value; nothing binds it. `wfd.pause`, `wfd.resume`, and `wfd.teardown` ask the sink through an M5 trigger and then answer the sink's PAUSE, PLAY, or TEARDOWN. `wfd.teardown` leaves the TCP stream open for `session.close`. `wfd.wait_idr` completes when the sink sends `wfd_idr_request`, and `wfd.idr_requests` counts those requests. A keep-alive GET_PARAMETER runs until teardown.

`Sink` is the other MICE role: `start`, `stop`, and `info`. `FallbackRequired.reason` is a short string when infrastructure setup stops. Wi-Fi Direct is not implemented.

## Implemented

- Control messages, TLVs, the vendor extension, and the PIN hash
- Source and sink setup on the control connection, including stop from either side
- DNS-SD advertisement and browse of the display service
- DTLS 1.2 when encryption or a PIN is requested
- Wi-Fi Display RTSP source setup, pause, resume, teardown, IDR requests, and keep-alive

## Deferred

- RTP encryption and UIBC. The MS-MICE spec requires both to use the DTLS key after a security handshake and does not define the transform.
- WFD R2 `wfd2_*` parameters and Microsoft `wfdx_*` parameters
- MPEG-TS, H.264 encoding, ffmpeg, and screen capture
- Wi-Fi Direct
- Building 802.11 beacon and probe frames
- DTLS handshake fragmentation and retransmission
