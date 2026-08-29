# Media protocol design references — research note (verified 2026-08-28)

Scope: the *specs and reference implementations* behind plan §B.4/§B.5/§B.7 (datagram
sizing, GCC-style ABR, Opus low-latency, timestamps/A-V sync, FEC choice, intra-refresh
knobs, chroma/bit-depth matrices, dirty regions, pacing, jitter buffers). No new crates are
introduced; pins for the crates involved (`quinn`, `opus`, `raptorq`) are in
`docs/research/quic.md` and `docs/research/codecs.md` and are cross-referenced here.

Every numeric claim cites a URL (RFC/draft text, vendor header or doc) or a `file:line` into a
source file downloaded on 2026-08-28 from the URL given in §12. Line numbers refer to those
snapshots (branch heads on that date); FFmpeg files are from tag/branch `release/8.0`.

---

## 0. TL;DR for implementers

| Topic | Number to code with | Source |
|---|---|---|
| QUIC datagram payload | **1162 B** at MTU 1200 (before DPLPMTUD), 1312 @1350, 1414 @1452; re-read `Connection::max_datagram_size()` on *every* frame packetize | quic.md §7 (measured), RFC 9221 §5, RFC 9000 §14 |
| Our video datagram header | 12 B (§2.3) → **symbol/fragment payload = max_datagram_size − 12 − 4 (FEC id) → 1144 B @1200** (multiple of 8 for `raptorq`) | codecs.md §7; RFC 6330 §4.2 |
| ABR = GCC delay-based + loss-based | burst_time 5 ms; Kalman q=1e-3, e0=0.1; threshold 12.5 ms, K_u 0.01, K_d 0.00018, over-use ≥10 ms, clamp [6,600] ms; ×1.08/s or +½ pkt per (RTT+100 ms); ×0.85 on over-use; A ≤ 1.5·R; loss <2 % ×1.05, 2–10 % hold, >10 % ×(1−0.5p); feedback once per frame (≥30 ms, ≤100 ms) | draft-ietf-rmcat-gcc-02 §3–6 (§3 below) |
| libwebrtc trendline variant | window 20, smoothing 0.9, gain 4.0, k_up 0.0087, k_down 0.039, adapt cap 15 ms, max Δt 100 ms | `trendline_estimator.cc:37-38,112-115,173-176,311-322` |
| Pacing | GCC: send a burst every 5 ms; libwebrtc pace factor **2.5×** target (1.1× with send-side BWE) → a frame's packets leave within ≈40 %/90 % of the frame interval; burst window 40 ms; Sunshine instead shapes at 80 % of 1 Gbit/s in ≤64-packet/≤64 KB batches (no spreading) | §4 |
| Opus | 48 kHz, `RESTRICTED_LOWDELAY` (CELT-only, 2.5 ms lookahead), 10 ms frames (=480 samples, RTP ts +480), CBR or constrained VBR, complexity 5–10, 64–256 kbit/s stereo, DTX off; LBRR FEC exists **only in SILK/hybrid** → app-level redundancy (previous frame piggy-backed) + PLC | §5 |
| Timestamps | video 90 kHz (RFC 3551 §5; RFC 6184 §5.1 & RFC 7798 §4.1 "MUST"), audio 48 kHz (RFC 7587 §4.1); both derived from one monotonic sender clock; receiver estimates `offset = min(arrival − send)` like GCC's d(i); lip-sync window ≤60 ms | §6 |
| FEC | RaptorQ: ≥99 % with K, 99.99 % K+1, **99.9999 % K+2**; K ∈ [1, 56403]; T multiple of Al. XOR parity (RFC 5109) recovers **one** loss per group. Sunshine: RS, 20 % default, ≤255 shards/block, ≤4 blocks/frame; audio RS 4+2 | §7 decision table |
| Intra-refresh | x264 `intra-refresh=1`+`g=huge`; NVENC `intra-refresh=1` (`intraRefreshPeriod/Cnt`, needs infinite GOP; `single-slice-intra-refresh`); QSV `int_ref_type/int_ref_cycle_size/int_ref_cycle_dist`; AMF `intra_refresh_mb` (H.264 only in FFmpeg; HEVC/AV1 need raw AMF props); **VAAPI: none in FFmpeg** (libva has `VAEncMiscParameterRIR`); **VideoToolbox: none** → short GOP + `ForceKeyFrame` | §8 |
| 4:4:4 / 10-bit | NVENC: H.264+HEVC 4:4:4 all gens (Turing→Blackwell), HEVC 10-bit, H.264 10-bit Blackwell only, AV1 4:2:0 only (FFmpeg rejects 4:4:4); Intel: HEVC 8/10-bit 4:4:4 encode ICL/Gen11+, AV1 4:2:0 only; AMD: **no 4:4:4 in hardware** (AMD, Jan 2024); VideoToolbox: FFmpeg lists NV12/P010/P210 for HEVC (4:2:2 max), 4:4:4 constants undocumented | §9 |
| Dirty regions | WGC `Direct3D11CaptureFrame.DirtyRegions` + `GraphicsCaptureSession.DirtyRegionMode` (Win11 24H2 / build 26100+); PipeWire `SPA_META_VideoDamage` (array of `spa_meta_region`, invalid entry terminates); SCKit `SCStreamFrameInfo.dirtyRects`/`contentRect` (macOS 12.3+) | §10 |
| Jitter buffer (Moonlight) | No RTP jitter buffer: frame is delivered when K shards arrive; a frame is abandoned when the *next* frame's packets arrive; 10 ms OOS wait; client pacer keeps ≤1 (strict) / ≤3 (lenient) frames, 500 ms history; audio 5 ms packets, RS 4+2, 10 ms OOS wait | §11 |

---

## 1. Versions & pins involved (no new crates)

| Crate | Pin (from sibling notes) | Used for in this note |
|---|---|---|
| `quinn` | 0.11.11 (quic.md §1.2) | `max_datagram_size()`, `send_datagram`, `stats().path.{rtt,cwnd,current_mtu}` |
| `opus` → `opusic-sys` | 0.4.0 → 0.7.x (libopus 1.6.1) (codecs.md §5) | encoder/decoder ctls in §5 |
| `raptorq` | **2.0.1** (crates.io `max_version` 2.0.1, updated 2026-03-09 — re-checked today) | per-frame RaptorQ in §7 |
| (optional reference) `windows-capture` | 2.0.1 (docs.rs) — has `DirtyRegionSettings::{Default, ReportOnly, ReportAndRender}` (`src/settings.rs`) | proves the WinRT dirty-region API is reachable from Rust; we use `windows` directly |

Everything in this note is implementable in pure Rust on this VM (GCC controller, pacer,
packetizer, XOR/RaptorQ FEC, timestamp math). Encoder knobs in §8/§9 need the CI
FFmpeg build (codecs.md §9).

---

## 2. QUIC datagram payload sizes

### 2.1 What the RFCs fix

- RFC 9221 §3: `max_datagram_frame_size` "represents the maximum size of a DATAGRAM frame
  (including the frame type, length, and payload) the endpoint is willing to receive";
  "it is RECOMMENDED to send a value of 65535 ... to indicate that this endpoint will accept
  any DATAGRAM frame that fits inside a QUIC packet". §5: "DATAGRAM frames cannot be
  fragmented; therefore, application protocols need to handle cases where the maximum
  datagram size is limited by other factors" (the `max_udp_payload_size` parameter and path
  MTU). §5.4: "DATAGRAM frames employ the QUIC connection's congestion controller ... a
  connection might be unable to send a DATAGRAM frame ... until the congestion controller
  allows it." — https://www.rfc-editor.org/rfc/rfc9221.html
- RFC 9000 §14: endpoints "MUST support a maximum datagram size of at least 1200 bytes";
  "QUIC assumes a minimum IP packet size of at least 1280 bytes" (IPv6 minimum MTU); larger
  sizes are discovered via PMTUD/DPLPMTUD (`rfc9000.txt:4589-4626`).
  https://www.rfc-editor.org/rfc/rfc9000.txt

### 2.2 What quinn exposes (measured in quic.md §7, `/tmp/probe-quic`)

`Connection::max_datagram_size() -> Option<usize>` = `current_mtu − (1 + 8 CID + 4 PN + 16 AEAD) − 9 (frame type + length)`:

| Path MTU (UDP payload) | `max_datagram_size()` |
|---|---|
| 1200 (`initial_mtu` default; also the post-black-hole floor) | **1162** |
| 1350 | 1312 |
| 1452 (`MtuDiscoveryConfig::upper_bound` default) | **1414** (after DPLPMTUD, ~1–2 RTT after handshake) |
| 1472 (raise `upper_bound` on LAN) | 1434 |

Rules: never hard-code; DPLPMTUD is per direction; black-hole detection drops back to 1200 —
re-fragment dynamically per frame. (quic.md §7 lines 466-476.)

### 2.3 Tornect datagram header budget

Plan §B.4's header (flags u8, frame_id u16, frag_idx u16, frag_count u16, rtp_ts u32) is
11 B; round to **12 B** (add `u8 stream_id/codec`). With RaptorQ the 4-byte `PayloadId`
(`raptorq::EncodingPacket::serialize`, codecs.md §7) follows. Symbol size must be a
multiple of the OTI alignment (crate default 8; RFC 6330 §4.3 recommends Al=4):

```
payload = max_datagram_size()          // 1162 @1200 MTU
symbol  = round_down(payload - 12 - 4, 8)   // 1144 @1200 ; 1392 @1452 (1414-16=1398→1392)
```

Sunshine/Moonlight reference numbers for comparison: Moonlight caps the *video payload* at
**1024 B for remote IPv4** and **1184 B for remote IPv6** (`Connection.c:413-422`), rounds
packetSize down to a multiple of 16 (`Connection.c:293-295`, "FEC only works in 16 byte
chunks"), and says "use 1024 if unsure" (`Limelight.h:57-60`); Sunshine's own limits are
`PACKETSIZE_MIN 200 / SMALL 500 / LARGE 1456 / MAX 65535` (`config.h:20-23`) and the RTP
video packet adds `MAX_RTP_HEADER_SIZE` on top (`stream.cpp:1547`). Our 1144–1392 B symbols
are in the same band but adapt to the measured MTU instead of a guess.

---

## 3. GCC delay-gradient congestion controller (implementable summary)

Sources: draft-ietf-rmcat-gcc-02 (text: https://www.ietf.org/archive/id/draft-ietf-rmcat-gcc-02.txt;
html: https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02) and libwebrtc `main`
(`modules/congestion_controller/goog_cc/*`, `modules/remote_bitrate_estimator/aimd_rate_control.cc`).
Tornect runs the **sender-side** variant (draft §3, first option): the receiver returns
`{seq, arrival_time}` per packet on the `stats`/`ctrl` stream; the sender maps them to send
times. This is exactly RFC 8888's shape (per-packet 16-bit block: R bit, 2-bit ECN, 13-bit
arrival-time offset in 1/1024 s relative to a report timestamp — `rfc8888.txt:184-245`);
we can copy that layout for the feedback message.

### 3.1 Feedback cadence (draft §3)

"The RECOMMENDED feedback interval is once per received video frame or at least once every
30 ms if audio-only or multi-stream. If the feedback overhead needs to be limited this
interval can be increased to 100 ms." (`gcc-02.txt:234-238`). REMB-style (receiver-side)
variant: "send the REMB message as soon as congestion is detected, and otherwise at least
once every second" (`:256-258`). Packet loss ratio comes from sequence gaps in the same
feedback (`:242-244`).

### 3.2 Pre-filtering / packet groups (draft §5.1–5.2)

- Groups: packets sent within `burst_time` belong to one group; additionally a packet with
  inter-arrival < `burst_time` **and** d(i) < 0 is merged into the current group
  (`gcc-02.txt:348-357`). `burst_time = 5 ms` (§5.6 table).
- Per group i: `d(i) = t(i) − t(i−1) − (T(i) − T(i−1))` where t = arrival of the group's
  last packet, T = departure of the group's last packet (§5.1).
- libwebrtc: `kBurstDeltaThreshold = 5 ms`, `kMaxBurstDuration = 100 ms`,
  `kReorderedResetThreshold = 3`, `kSendTimeGroupLength = 5 ms`
  (`inter_arrival_delta.cc:23-24`, `.h:28`, `delay_based_bwe.cc:43`); it is a burst if
  `propagation_delta < 0 && arrival_delta <= 5 ms && (arrival − first_arrival) < 100 ms`
  (`inter_arrival_delta.cc:128-131`).

### 3.3 Arrival-time filter — Kalman (draft §5.3) — the spec's estimator

```
z(i)   = d(i) − m̂(i−1)
k(i)   = (e(i−1) + q) / (var_v̂(i) + e(i−1) + q)
m̂(i)   = m̂(i−1) + z(i)·k(i)
e(i)   = (1 − k(i))·(e(i−1) + q)
var_v̂(i) = max(α·var_v̂(i−1) + (1−α)·z(i)², 1)      // z clipped to 3·sqrt(var_v̂) before use
α      = (1 − χ)^(30 / (1000·f_max))                // f_max = max group rate over last K groups
q = 1e-3, e(0) = 0.1, χ ∈ [0.1, 0.001]
```
(`gcc-02.txt:396-425`, §5.6 table.)

### 3.4 Arrival-time filter — trendline (libwebrtc's replacement, simpler & what Chrome ships)

`trendline_estimator.cc`: keep the last **20** (send_time, smoothed accumulated delay)
pairs; `smoothed = 0.9·smoothed + 0.1·accumulated_delay` (`:207-208`); fit a least-squares
line, `trend` = slope (ms/ms); `modified_trend = min(num_deltas, 60) · trend · 4.0`
(`:272-273`). Constants: `kDefaultTrendlineWindowSize = 20` (`.h:29`),
`kDefaultTrendlineSmoothingCoeff = 0.9`, `kDefaultTrendlineThresholdGain = 4.0` (`:37-38`),
`kMinNumDeltas = 60`, `kMaxAdaptOffsetMs = 15`, `kOverUsingTimeThreshold = 10` (`:112-114`).

### 3.5 Over-use detector (draft §5.4; libwebrtc `:275-322`)

- Signal **over-use** only if `m(i) > del_var_th(i)` for ≥ `overuse_time_th = 10 ms`
  **and** `m(i) ≥ m(i−1)` (draft `:427-436`; libwebrtc `time_over_using_ > 10 && overuse_counter_ > 1 && trend >= prev_trend` `:286-290`).
  libwebrtc starts `time_over_using_ = ts_delta/2` on first exceedance (`:280`).
- **Under-use** when `m(i) < −del_var_th(i)`; otherwise normal.
- Adaptive threshold: `del_var_th(i) = del_var_th(i−1) + (t(i)−t(i−1))·K(i)·(|m(i)| − del_var_th(i−1))`,
  `K = K_u = 0.01` if `|m| > th` else `K_d = 0.00018`; `del_var_th(0) = 12.5 ms`; skip the
  update when `|m(i)| − del_var_th(i−1) > 15 ms`; "RECOMMENDED to clamp del_var_th(i) to the
  range [6, 600]" ms (draft `:439-495`, clamp at `:481`, values at `:494-495`). libwebrtc: `k_up = 0.0087`, `k_down = 0.039`, `threshold = 12.5`, `time_delta`
  capped at 100 ms, clamp `[6, 600]` (`:173-176, 311-322`) — note libwebrtc's K_u/K_d are
  *per ms of modified_trend*, not the draft's units; pick one implementation and keep its
  constants together.

### 3.6 Rate controller (draft §5.5)

State machine (`gcc-02.txt:525-541`, blank = stay):

| signal \ state | Hold | Increase | Decrease |
|---|---|---|---|
| Over-use | Decrease | Decrease | — |
| Normal | Increase | — | Hold |
| Under-use | — | Hold | Hold |

Start in Increase. Increase mode selection: multiplicative while far from convergence,
additive when `R_hat` is within 3σ of the EMA (factor 0.95) of the incoming rate measured at
previous Decrease events (`:555-575`). Reset that average (back to multiplicative) when
`R_hat` exceeds it by 3σ (`:575-578`).

```
R_hat(i) = Σ L(j) / T           over the last T ∈ [0.5, 1] s of received payload bytes    (:583-587)
multiplicative: η = 1.08^min(Δt_ms/1000, 1);  A = η·A                                   (:592-594)
additive:  response_time_ms = 100 + rtt_ms
           α = 0.5·min(Δt_ms / response_time_ms, 1)
           A = A + max(1000, α·expected_packet_size_bits)                                 (:597-603)
           expected_packet_size_bits: bits_per_frame = A/30; packets = ceil(bits_per_frame/(1200·8)); avg = bits_per_frame/packets (:608-612)
cap:       A(i) < 1.5·R_hat(i)                                                            (:627)
decrease:  A = β·R_hat, β = 0.85 (range [0.8, 0.95])                                     (:632-635)
run the update at least once per response_time                                           (:648-649)
```
libwebrtc: `kDefaultBackoffFactor = 0.85`, `kDefaultRtt = 200 ms` (`aimd_rate_control.cc:34-35`),
`alpha = 1.08` (`:346`), near-max additive rate uses `response_time = (rtt + 100 ms)·2`
(`:200-204`), Increase is capped at `1.5·throughput + 10 kbps` (`:239`), and its own
receiver-side feedback interval is clamped to **[200 ms, 1000 ms]** from an 80-byte RTCP
budget (`:111-116`) — that is the REMB path, not the per-frame transport feedback we use.

### 3.7 Loss-based controller (draft §6) and combination

```
p < 2 %      : A_s = 1.05·A_s
2 % ≤ p ≤ 10 %: hold
p > 10 %     : A_s = A_s·(1 − 0.5·p)
target = min(A_s, A_delay)
```
(WebFetch summary of draft §6 + html; constants also in §5.6 summary table.)

### 3.8 Tornect binding

- Feedback message on `stats` (per video frame, min 30 ms): `report_ts_us (u32)`, base
  `seq (u16)`, N × `{received: bool, ato_1024ths: u13}` — RFC 8888 layout.
- Sender keeps `(seq → send_time_us, bytes)` for ≥ 1 s; feeds groups to the trendline
  estimator, AIMD as above; output `target_bps` → plan's "85 % of estimated capacity" is
  the *pacing* margin (draft: pacer sends target × burst_time every 5 ms, §4), the
  encoder bitrate should be `target − fec_overhead − audio` (Sunshine does exactly this:
  `configuredBitrateKbps /= 100/(100 − fec_percentage)` when `fec ≤ 80`, `rtsp.cpp:1261-1262`).
- Floors/ceilings from plan §B.4 (min 500 kbit/s; user cap) clamp `target`.

---

## 4. Pacing

- draft-ietf-rmcat-gcc-02 §4: "The Pacer sends a group of packets to the network every
  burst_time interval. RECOMMENDED value for burst_time is 5 ms. The size of a group of
  packets is computed as the product between the target bitrate and the burst_time."
  (`gcc-02.txt:261-268`).
- libwebrtc: pacing rate = `kDefaultPaceMultiplier = 2.5` × target, or
  `kDefaultPaceMultiplierWithSendSideBwe = 1.1` once transport feedback is flowing
  (`goog_cc_network_control.cc:50-58, 657-664`); `PacerConfig::kDefaultTimeInterval = 40 ms`
  burst window (`api/transport/network_types.h:237`); `kMaxBurstSize = 63 000 B`,
  `kMaxExpectedQueueLength = 2000 ms`, `kMinSleepTime = 1 ms`, `kCongestedPacketInterval = 500 ms`
  (`pacing_controller.h:89-92`, `.cc:40-49`). Consequence: an average-size frame is
  emitted within ≈ 1/2.5 = **40 %** of a frame interval (2.5×) or ≈ **90 %** (1.1×) — this
  is where plan §B.4's "spread over 0.5–0.9 of the frame interval" lives.
- Sunshine (`stream.cpp:1604-1767`): **does not spread over the frame interval**; it shapes
  bursts to "around 80 % of 1 Gbps" (`ratecontrol_packets_in_1ms = 1e9·80/100/1000/blocksize/8`,
  `:1605-1606`), sends batches of ≤ 64 KB and ≤ 64 packets ("Generic Segmentation Offload on
  Linux can't do more than 64", `:1608-1616`), sleeps with a high-precision timer until the
  1-ms budget slot is due (`:1719-1727`) and carries the last slot over to the next frame
  (`:1765-1767`). RTP timestamps = 90 kHz ticks since a `video_epoch` (`:1668-1676`).
- Tornect rule (derived): pace at `min(2.0 × target_bps, link_floor)` where `link_floor`
  = 800 Mbit/s on LAN like Sunshine, i.e. a 1080p60 frame at 20 Mbit/s (≈42 KB ≈ 37
  datagrams) drains in ≈ 8 ms (half of 16.7 ms); send in GSO-friendly batches ≤ 64 datagrams
  (`quinn` GSO is on by default, quic.md §8). "Prefer latency" mode = 2.5×, "prefer
  smoothness" = 1.1×. Never let the pacer queue exceed one frame interval — drop the oldest
  *frame* (quinn's datagram queue already drops oldest datagrams, quic.md §7) and request
  intra-refresh acceleration instead of queuing.

---

## 5. Opus low-latency settings

### 5.1 libopus API facts (opus_api 1.5 docs, https://opus-codec.org/docs/opus_api-1.5/)

- `OPUS_APPLICATION_RESTRICTED_LOWDELAY`: "configures low-delay mode that disables the
  speech-optimized mode in exchange for slightly reduced delay. This mode can only be set on
  an newly initialized or freshly reset encoder because it changes the codec delay."
  (`group__opus__encoder.html`). Fs ∈ {8000, 12000, 16000, 24000, 48000}; channels 1|2.
- Frame sizes: "2.5, 5, 10, 20, 40 or 60 ms" = 120/240/480/960/1920/2880 samples at 48 kHz;
  frames < 10 ms "will prevent the encoder from using the LPC or hybrid modes" (ibid.).
- CTLs (`group__opus__encoderctls.html`): `OPUS_SET_BITRATE` "500 to 512000 bits per
  second ... OPUS_AUTO / OPUS_BITRATE_MAX"; `OPUS_SET_PACKET_LOSS_PERC` 0–100 (default 0);
  `OPUS_SET_INBAND_FEC` 0 off (default) / 1 "If the packet loss rate is sufficiently high,
  Opus will automatically switch to SILK" / 2 "does not necessarily switch to SILK if we have
  music"; `OPUS_SET_DTX` 0/1 — "only applicable to the LPC layer"; `OPUS_SET_VBR` 0 hard CBR /
  1 VBR (default); `OPUS_SET_VBR_CONSTRAINT` 1 (default); `OPUS_SET_COMPLEXITY` 0–10;
  `OPUS_GET_LOOKAHEAD` samples; `OPUS_SET_EXPERT_FRAME_DURATION` ARG|2.5…120 ms;
  `OPUS_SET_PREDICTION_DISABLED`; `OPUS_SET_LSB_DEPTH` 8–24; `OPUS_SET_DRED_DURATION`
  (1.5+, speech DNN redundancy — not for us).
- Decoder (`group__opus__decoder.html`): `opus_decode(st, data|NULL, len, pcm, frame_size, decode_fec)`;
  "In the case of PLC (data==NULL) or FEC (decode_fec=1), then frame_size needs to be
  exactly the duration of audio that is missing ... frame_size must be a multiple of 2.5 ms."
- Codec delay (RFC 6716 §2): SILK "requires an additional 5 ms look-ahead" (+ up to 1.5 ms
  resampling), CELT "requires an additional 2.5 ms look-ahead due to the overlapping MDCT
  windows" and in hybrid the CELT input is delayed "an additional 2.7 ms"
  (`rfc6716.txt:455-520`). → `RESTRICTED_LOWDELAY` (CELT-only) ⇒ **2.5 ms** algorithmic
  delay + 10 ms frame = 12.5 ms codec latency; `AUDIO` mode ⇒ ~6.5 ms + frame.

### 5.2 In-band FEC reality (matters for plan §B.4 "Opus LBRR")

- RFC 6716 §2.1.7: FEC = "Packets that are determined to contain perceptually important
  speech information, such as onsets or transients, are encoded again at a lower bitrate and
  this re-encoded information is added to a subsequent packet" (`rfc6716.txt:640-646`);
  §4.2.5: LBRR frames are SILK-layer, "only meant to be transmitted for active speech"
  (`:2037-2039`). RFC 7587 §3.3: "This FEC scheme adds redundant information about the
  previous packet (N-1) to the current output packet N ... the decision to send in-band FEC
  information is entirely controlled by the encoder" (`rfc7587.txt:295-305`).
- ⇒ with `RESTRICTED_LOWDELAY` (CELT only) or music/desktop audio, **no LBRR is produced**
  (codecs.md §5.3 reached the same conclusion from the encoder-ctl docs). Keep
  `set_inband_fec(true)` + `set_packet_loss_perc(p)` only if we choose `Application::Audio`;
  otherwise rely on §5.4 redundancy.

### 5.3 Decoding with FEC / PLC — the reference call order (libopus `src/opus_demo.c:1141-1155`)

When packet N arrives and N−1 was lost (`lost_count ≥ 1`):
```c
opus_decoder_ctl(dec, OPUS_GET_LAST_PACKET_DURATION(&dur));          // frame size of the lost frame(s)
if (opus_packet_has_lbrr(data, len))
    n = opus_decode24(dec, data, len, out, dur, /*decode_fec=*/1);   // reconstruct N-1 from N's LBRR
else
    n = opus_decode24(dec, NULL, 0, out, dur, 0);                    // PLC for N-1
n = opus_decode24(dec, data, len, out, max_frame_size, 0);           // then decode N normally
```
(`opus_demo.c:1142-1155`). Rust `opus` 0.4 wrapper: `dec.decode(&next, &mut one_frame, true)`
then `dec.decode(&next, &mut buf, false)`; the wrapper derives `frame_size` from the output
slice length, so the FEC/PLC call must get a buffer of exactly one frame (codecs.md §5.2/5.3).
`opus_packet_has_lbrr` is not exposed by the crate — calling `decode(.., fec=true)` without
LBRR is documented to behave like PLC ("If no such data is available, the frame is decoded as
if it were lost", codecs.md §5.3), so it is safe to call unconditionally.

### 5.4 RTP timing & bitrates (RFC 7587)

- §4.1 "The RTP timestamp is incremented with a 48000 Hz clock rate for all modes of Opus and
  all sampling rates" → 10 ms = **+480**, 5 ms = +240, 20 ms = +960 (§4.2 table).
- §3.1.1 sweet spots: "48-64 kbit/s for FB mono music", "64-128 kbit/s for FB stereo music";
  speech 28–40 kbit/s FB. Plan's 64–256 kbit/s stereo is above the sweet spot at the top —
  fine for desktop audio; 128 kbit/s is the sensible default, 256 for "studio" toggle.
- §3.1.3: DTX vs loss distinguished by sequence-number gaps — irrelevant since DTX stays off.

### 5.5 What Sunshine/Moonlight do (reference behaviour)

- Sunshine `audio.cpp:120-137`: `opus_multistream_encoder_create(48000, ..., OPUS_APPLICATION_RESTRICTED_LOWDELAY)`,
  `OPUS_SET_BITRATE(stream.bitrate)`, **`OPUS_SET_VBR(0)`** (hard CBR, so RS-FEC shards are
  equal-size), `frame_size = packetDuration·48` with `x-nv-aqos.packetDuration` default **5 ms**
  (`rtsp.cpp:1129,1149`; Moonlight `samplesPerFrame = 48·AudioPacketDuration`, `AudioStream.c:440`).
- Audio FEC: Reed–Solomon **4 data + 2 parity** per block (`RtpAudioQueue.h:11-14`,
  `stream.cpp:1801,1865-1889`), parity packets carry `AUDIO_FEC_HEADER{fecShardIndex, payloadType 97, baseSequenceNumber, baseTimestamp, ssrc}`
  on RTP PT 127. Receiver waits `AudioPacketDuration·4 + 10 ms` for out-of-order shards before
  giving up (`RtpAudioQueue.c:547`, `RTPQ_OOS_WAIT_TIME_MS 10`), drops the first 500 ms on
  start (`AudioStream.c:248`), and passes lost packets to the decoder as NULL for PLC
  (`AudioStream.c:162-167`). `MAX_AUDIO_PACKET_SIZE = 1400` (`stream.cpp:314`).

### 5.6 Tornect audio recipe

```rust
let mut enc = opus::Encoder::new(48_000, Channels::Stereo, Application::LowDelay)?; // CELT-only, 2.5 ms lookahead
enc.set_bitrate(Bitrate::Bits(128_000))?;           // 64_000..=256_000 user range
enc.set_vbr(true)?; enc.set_vbr_constraint(true)?;  // or set_vbr(false) if equal-size frames wanted for FEC
enc.set_complexity(8)?;                             // 5 on weak CPUs
enc.set_inband_fec(false)?;                         // no effect in CELT anyway; keep false to save bits
enc.set_packet_loss_perc(0)?;                       // idem
enc.set_expert_frame_duration(FrameSize::Ms10)?;   // 480 samples/ch → rtp_ts += 480
```
Datagram = `{hdr 12 B, ts48k u32, seq u16, cur_frame (~120–320 B), prev_frame (same)}`:
two consecutive losses are needed to lose a frame; cost = 2× audio bitrate (≈ +128 kbit/s),
zero added latency. Receiver: tiny jitter buffer of 2 frames (20 ms) default, PLC on holes
(`decode(&[], one_frame, false)`), re-sync (drop/insert) when queue > 4 frames.

---

## 6. Timestamps and A/V sync

### 6.1 Clock rates (spec)

- RFC 3550 §5.1: "The timestamp reflects the sampling instant of the first octet in the RTP
  data packet ... derived from a clock that increments monotonically and linearly in time to
  allow synchronization and jitter calculations. The resolution of the clock MUST be
  sufficient for the desired synchronization accuracy and for measuring packet arrival jitter
  ... The initial value of the timestamp SHOULD be random" (https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1).
- RFC 3551 §5: "All of these video encodings use an RTP timestamp frequency of 90,000 Hz ...
  yields exact integer timestamp increments for the typical 24 ... 25 ... 29.97 ... 30 Hz frame
  rates and 50, 59.94 and 60 Hz field rates" (`rfc3551.txt:1638-1642`, §5 "Video"); RFC 6184
  §5.1 (H.264) "A 90 kHz clock rate MUST be used" (`rfc6184.txt:593`); RFC 7798 §4.1 (HEVC)
  same wording (`rfc7798.txt:1186`);
  Opus 48 kHz (§5.4). 60 fps ⇒ +1500 ticks/frame; wrap: 2³²/90 000 ≈ 13.3 h, 2³²/48 000 ≈ 24.9 h.
- RFC 3550 §6.4.1: cross-media sync needs the (NTP wall-clock, RTP ts) pair from Sender
  Reports: "The RTP timestamp is related to the sampling instant by pairing it with a
  timestamp from a reference clock (wallclock) that represents the time when the data
  corresponding to the RTP timestamp was sampled" (WebFetch of §6.4.1).

### 6.2 NTP-free design (what we implement)

One **monotonic sender clock** `t_us` (µs since session start; `Instant`-based) is the single
media clock; `video.rtp_ts = (t_capture_us · 90 / 1000) mod 2³²`, `audio.ts = (t_capture_us · 48 / 1000) mod 2³²`.
Because both derive from the same clock, the receiver needs only **one** offset:

```
// per received datagram (video or audio), in the receiver's monotonic µs:
send_us   = ts_to_us(rtp_ts)                        // ×1000/90 or ×1000/48, unwrap 32-bit
d         = recv_us − send_us                       // = clock_offset + one_way_delay + queueing
offset    = running_min(d, window = 2–5 s)          // min ≈ offset + min OWD; queueing removed
// presentation target:
present_us = send_us + offset + playout_delay       // playout_delay = jitter buffer (§11) + decode budget
```
This is the same `d(i)` GCC already computes (§3.2) and what Moonlight does implicitly:
`presentationTimeUs = rtp_timestamp·1000/90` (`RtpVideoQueue.c:18,158`) is compared to local
receive times. Drift: consumer clocks differ by ≤ ±100 ppm ⇒ ≤ 6 ms/min; the sliding-min
re-estimation (and slewing `offset` at ≤ 1 ms/s) absorbs it. This mirrors WebRTC's
`abs-capture-time` extension ("stamp RTP packets with a NTP timestamp showing when the first
audio or video frame in a packet was originally captured" + "estimated capture clock offset",
https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-capture-time/README.md)
minus NTP, and `abs-send-time` ("24-bit 6.18 fixed point ... 64s wraparound and 3.8us
resolution", `.../abs-send-time/README.md`) — we carry a full u32 send time, no need for 6.18.

Lip-sync policy (plan §B.4): audio is master (its `present_us` drives the DAC schedule);
video frames are presented when `present_us ≤ now` and within `[−60 ms, +20 ms]` of the audio
position; otherwise present immediately (video never blocks audio). Sunshine stamps video
with the *capture* time (`packet->frame_timestamp`, `stream.cpp:1668-1676`) and audio with a
running `timestamp += packetDuration` (`:1847`) — i.e. it has no A/V sync at all; we do better
cheaply because both stamps come from capture time.

Also carry the host-side processing latency in the `stats` stream like Moonlight's
`frameHostProcessingLatency` "in 1/10 ms units" (`Limelight.h:151-155`, Sunshine
`stream.cpp:1531-1539`) for the HUD.

---

## 7. FEC: RaptorQ (RFC 6330) vs XOR parity (RFC 5109)

### 7.1 Spec facts

- RFC 6330 §3.3.2: "Symbol Size (T): 16-bit unsigned integer ... less than 2^16"; §3.3.3
  "symbol alignment parameter (Al): 8-bit"; §4.3 "The recommended setting for the input
  parameter Al is 4" and T "MUST be a multiple of Al"; §5.1.2 `K'_max = 56403`; "source
  blocks with between 1 and 56403 source symbols" (WebFetch of rfc6330; `rfc6330.txt`).
  The RFC itself gives **no** failure-probability numbers (grep "probabilit" → none).
- Qualcomm "RaptorQ Technical Overview" (https://www.qualcomm.com/media/documents/files/raptorq-technical-overview.pdf,
  extracted text lines 89-104): recovery "with probability greater than: 99% from reception of
  K encoded symbols, 99.99% from reception of K+1 encoded symbols, 99.9999% from reception of
  K+2 encoded symbols. These recovery probabilities hold across the entire range of possible
  numbers of source symbols, source symbol sizes, and loss probabilities". The general GF(256)
  bound is 1 − 1/256^(h+1) (lines 312-330) — the same formula the `raptorq` README quotes
  (codecs.md §7).
- RFC 5109 §4: single XOR parity over a group — "if b is lost, a and f(a,b) can be used to
  recover b"; §5: "if any one of the three packets ... is lost, the original payload data can
  still be recovered" — i.e. **one loss per group**, overhead 1/group_size
  (`rfc5109.txt:345-385`). RFC 5109 also notes Reed–Solomon as the MDS alternative (`:369-372`).
- `raptorq` 2.0.1 constraints (codecs.md §7, `base.rs:120-146`): `symbol_size % alignment == 0`,
  ≤ 56 403 symbols/block, OTI derivable from (len, symbol_size) so it need not be sent;
  systematic (source symbols are the plain fragments); ~10–20 Gbit/s encode.

### 7.2 Reference implementations

- Sunshine video (`stream.cpp:753-884, 1544-1602`): Reed–Solomon (nanors) per frame;
  `fec_percentage` default **20** (`config.cpp:815`, range 1–255); parity = ⌈data·pct/100⌉ but
  ≥ client's `minRequiredFecPackets` (`:816-822`; Moonlight sends `x-nv-vqos[0].fec.minRequiredFecPackets`,
  default "0", `rtsp.cpp:1131`); RS limit 255 shards ⇒ `max_data_shards = 255·100/(100+pct)`
  (`:1556-1563`); ≤ 4 FEC blocks per frame (2-bit field), FEC disabled for larger frames
  ("over 800 packets at 20%", `:1553-1575`); 10-bit shard index ⇒ ≤ 1024 packets/block (`:1587-1591`).
  Moonlight recovers when `received ≥ data_shards` (`RtpVideoQueue.c:194-231`), predicts
  unrecoverable frames early (`missingPackets > parity`) and reports loss to the host
  (`:210-222`, "speculative RFI").
- Sunshine audio: RS 4+2 fixed (§5.5).
- WebRTC: FlexFEC/ULPFEC (XOR) — not fetched; RFC 5109 semantics above.

### 7.3 Decision table (Tornect)

Let K = source symbols of the frame (≈ frame_bytes / symbol), p = smoothed loss ratio from
feedback (§3.7), `h` = repair symbols.

| Condition | Scheme | Parameters | Why |
|---|---|---|---|
| p < 0.5 % and K ≤ 8 (typical P-frames at ≤ 10 Mbit/s) | **none** | conceal + intra-refresh acceleration on `ctrl` | any FEC costs ≥ 12 %; recovery via refresh is cheaper than 1 parity/8 |
| p < 2 %, K ≤ 40 | **XOR** (RFC 5109 style) | groups of g = 8 (g = 4 when p ≥ 1 %), 1 parity/group → overhead 12.5 %/25 % | single loss per group; O(K) XOR; no decoder state |
| 2 % ≤ p ≤ 10 %, or keyframe/IDR, or K > 40 | **RaptorQ** per frame | `h = max(2, ceil(K·p·2) + 2)`, capped at 0.30·K; symbol = §2.3; K ≥ 2 (pad 1-symbol frames to 2 or use XOR) | K+2 ⇒ 99.9999 %; bursts up to h losses tolerated regardless of position |
| p > 10 % | RaptorQ at 30 % + ABR down | GCC loss branch already cuts rate ×(1−0.5p) | RS/RaptorQ beyond 30 % is bandwidth better spent on bitrate |
| audio, any p | previous-frame redundancy (§5.6); at p > 5 % also RaptorQ over 4 frames with h = 2 (like Sunshine's RS 4+2) | +100 % audio bytes / +50 % | latency-free |

Sizing sanity (1080p60 HEVC 20 Mbit/s, symbol 1144 B): P-frame ≈ 42 KB ⇒ K ≈ 37; IDR ≈ 150–300 KB ⇒ K ≈ 130–260;
RaptorQ encode of K=260 at 1144 B ≈ 300 KB ⇒ tens of µs (codecs.md §7 throughput). With
`h = K·p·2 + 2` at p = 3 %, K = 37 ⇒ h = 5 (13.5 %); at p = 3 %, K = 260 ⇒ h = 18 (7 %).
Receiver rule: attempt RaptorQ decode as soon as ≥ K symbols of the frame are in; if the
next frame's first datagram arrives before that, abandon (Moonlight semantics,
`RtpVideoQueue.c:591-600`), conceal, and count a loss for the ABR.

Reed–Solomon note: RS is MDS (exactly K of K+h suffice, no +2) and Sunshine's block sizes
are small, but its arithmetic is O(K·h) per symbol and shard counts are capped at 255;
RaptorQ has no such cap and is already verified here (codecs.md §7). Keep RS out of v1;
revisit if RaptorQ's +2 overhead on tiny K matters (open question).

---

## 8. Intra-refresh & GOP knobs per encoder (FFmpeg 8.0 option names + native API)

| Encoder | Infinite GOP | Intra-refresh | On-demand IDR | Notes / source |
|---|---|---|---|---|
| **x264 / libx264** | `g` → `i_keyint_max` (`libx264.c:1151-1152`); `X264_KEYINT_MAX_INFINITE = 1<<30` (`x264.h:232`) — pass `g=1<<30` or `x264-params keyint=infinite` | `intra-refresh=1` → `b_intra_refresh` ("Whether or not to use periodic intra refresh instead of IDR frames", `x264.h:366`; `libx264.c:1214-1215,1523`); refresh wave length follows keyint (see x264.h:989-995: with `b_intra_refresh` the client can ask for a refresh on loss "keyint can be set to an extremely high value") | `forced-idr=1` + `pict_type=I` → `X264_TYPE_IDR` (`libx264.c:517`) | `tune=zerolatency` (`x264.h:716`), `rc-lookahead=0`, `sliced-threads` (`libx264.c:1325`) |
| **NVENC** (`h264_nvenc`, `hevc_nvenc`, `av1_nvenc`) | FFmpeg: `gop_size > 0` → `gopLength = gop_size`; `gop_size == 0` → intra-only (`frameIntervalP = 0, gopLength = 1`); `bf` → `frameIntervalP = max_b_frames + 1` (`nvenc.c:1916-1926`). `NVENC_INFINITE_GOPLENGTH = 0xffffffff` (`nvEncodeAPI.h:129`) is applied automatically when `intra-refresh=1`; otherwise pass a huge `g` (Sunshine native: `gopLength = NVENC_INFINITE_GOPLENGTH; frameIntervalP = 1; idrPeriod = INFINITE`, `nvenc_base.cpp:260-261,364`; API: "Low latency application client can set goplength to NVENC_INFINITE_GOPLENGTH so that keyframes are not inserted automatically", `nvEncodeAPI.h:2203`) | `intra-refresh=1` ("Use Periodic Intra Refresh instead of IDR frames", `nvenc_h264.c:226`, `nvenc_hevc.c:204`, `nvenc_av1.c:151`) → `enableIntraRefresh=1; intraRefreshPeriod = gopLength; intraRefreshCnt = gopLength−1; gopLength = INFINITE` (`nvenc.c:1300-1304,1491-1495,1686-1690`); `single-slice-intra-refresh=1` (SDK ≥ 11.1, cap `NV_ENC_CAPS_SINGLE_SLICE_INTRA_REFRESH`, `nvenc.c:613-629`). API doc: `intraRefreshPeriod` "Will be disabled if NV_ENC_CONFIG::gopLength is not set to NVENC_INFINITE_GOPLENGTH"; `intraRefreshCnt` "should be smaller than intraRefreshPeriod" (`nvEncodeAPI.h:1882-1884`). Sunshine native uses period **300**, cnt **299**, `outputRecoveryPointSEI=1` (`nvenc_base.cpp:338-342`). NVIDIA guide: period "small like 30 for a highly error prone network" | `forced-idr=1` (`NV_ENC_PIC_FLAG_FORCEIDR`, Sunshine `nvenc_base.cpp:740`) | Low latency: `tune=ull` (`NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY`, `nvEncodeAPI.h:2227`), `rc=cbr`, `delay=0`, `zerolatency=1`, `cbr_padding=0`, `bf=0`, `vbvBufferSize = bitrate/framerate` (`nvenc_base.cpp:278-279`), `lowDelayKeyFrameScale=1`, `enableLookahead=0`, `zeroReorderDelay=1` (`:263-265`); Sunshine FFmpeg path options `video.cpp:754-761` |
| **QSV / libvpl** | `g` + `idr_interval` ("Distance (in I-frames) between IDR frames", `qsvenc_h264.c:128`) | `int_ref_type` = `none`(0) / `vertical`(1) / `horizontal`(2) / `slice`(3) ("B frames should be set to 0"), `int_ref_cycle_size` ("Number of frames in the intra refresh cycle"), `int_ref_qp_delta`, `recovery_point_sei`, `int_ref_cycle_dist` ("Distance between the beginnings of the intra-refresh cycles in frames") (`qsvenc_h264.c:143-151`); mapped to `mfxExtCodingOption2::IntRefType/IntRefCycleSize/IntRefQPDelta`, `ExtCodingOption3::IntRefCycleDist`, runtime-updatable (`qsvenc.c:2269-2295`, H.264/HEVC only) | `forced_idr=1` | Sunshine: `async_depth=1`, `low_delay_brc=1`, `preset` (`video.cpp:846-849`) |
| **AMF** (`h264_amf`, `hevc_amf`, `av1_amf`) | `gops_per_idr=0` = "no IDR will be inserted" (HEVC option, `amfenc_hevc.c:93`); H.264 has `header_spacing` | FFmpeg exposes **only H.264**: `intra_refresh_mb` → `AMF_VIDEO_ENCODER_INTRA_REFRESH_NUM_MBS_PER_SLOT` (`amfenc_h264.c:126,576-578`). Native props exist for all three: `AMF_VIDEO_ENCODER_INTRA_REFRESH_NUM_MBS_PER_SLOT` (`VideoEncoderVCE.h:268`), `AMF_VIDEO_ENCODER_HEVC_INTRA_REFRESH_NUM_CTBS_PER_SLOT` "in 64x64 CTB" (`VideoEncoderHEVC.h:179`), `AMF_VIDEO_ENCODER_AV1_INTRA_REFRESH_MODE` {DISABLED, GOP_ALIGNED, CONTINUOUS} + stripes count (`VideoEncoderAV1.h:166-170,288`; `AMF_Video_Encode_AV1_API.md:1371-1394`). Not supported together with LTR user control or SVC (`AMF_Video_Encode_API.md:714,1810`) | `forced_idr=1` | `usage=ultralowlatency`/`lowlatency` (HEVC `amfenc_hevc.c:32-33`; AV1 `latency=lowest_latency` `amfenc_av1.c:82-86`), `rc=cbr`, `async_depth=1`, `header_insertion_mode=idr`, `gops_per_idr=1` (Sunshine `video.cpp:982-996`). Sunshine H.264 forces `usage=2 (LOW_LATENCY)` as a workaround for AMF issue #410 (`video.cpp:1044`) |
| **VAAPI** (`h264_vaapi`, `hevc_vaapi`, `av1_vaapi`) | `g` + `idr_interval` (`gop_per_idr = idr_interval + 1`, `hw_base_encode.c:709`); Sunshine sets `idr_interval = INT_MAX` and flags VAAPI `LIMITED_GOP_SIZE` ("Some encoders don't like it when you have an infinite GOP_SIZE. e.g. VAAPI", `video.cpp:389,1206,1246`) | **none**: no option in `vaapi_encode*.c` (grep "RIR/intra_refresh" → nothing). libva has `VAEncMiscParameterTypeRIR` / `VAEncMiscParameterRIR{rir_flags{enable_rir_column,enable_rir_row}, intra_insertion_location, intra_insert_size, qp_delta}` gated by `VAConfigAttribEncIntraRefresh` (`va.h:2389-2711, 1329-1331`) — usable only via raw libva, not FFmpeg | `pict_type=I` forces a keyframe (FFmpeg hw_base) | `async_depth=1`, `sei=0`, `blbrc` (Sunshine `video.cpp:1204-1236`); VAAPI defaults `bf=2`, `g=120` (codecs.md §10.4) |
| **VideoToolbox** (`h264_videotoolbox`, `hevc_videotoolbox`) | `g` → `kVTCompressionPropertyKey_MaxKeyFrameInterval` (`videotoolboxenc.c:1378-1387`) | **none** — the FFmpeg option table has no intra-refresh (`videotoolboxenc.c:2775-2792`, h264 options `:2800-2838`), and VideoToolbox exposes no such key ⇒ use a **short GOP** (Sunshine uses `gop_size = keyint_min = 120` for encoders without on-demand IDR, `video.cpp:2003-2006`) and `kVTEncodeFrameOptionKey_ForceKeyFrame` for on-demand IDR (`videotoolboxenc.c:2462`) | `ForceKeyFrame` | `realtime=1`, `prio_speed=1`, `allow_sw`, `constant_bit_rate=1` (macOS 13+), `max_slice_bytes`, `max_ref_frames`, `AllowFrameReordering=false` (`:1529`) |
| **MediaFoundation** (Qualcomm/Win-on-ARM) | fixed GOP 120 — "MF encoder doesn't support on-demand IDR frames" (`video.cpp:1108, 2003-2006`) | none | none | `rate_control=cbr`, `scenario=display_remoting` (`:1068-1071`) |

Cross-encoder GOP recipe (Sunshine `video.cpp:1999-2027`): `max_b_frames = 0`; `gop_size =
INT_MAX`/limited; `keyint_min = INT_MAX`; `flags |= CLOSED_GOP | LOW_DELAY`; `flags2 |= FAST`;
`rc_max_rate = bit_rate`; `rc_buffer_size = bitrate/framerate` (`:2163-2185`); `slices` per
client request (`:2092-2107`). Recovery ladder for us: conceal → `ctrl` "refresh now"
(x264: `x264_encoder_intra_refresh`, NVENC: shorten `intraRefreshPeriod` via reconfigure,
QSV: `int_ref_cycle_size` reconfigure) → forced IDR (NVENC also has `NvEncInvalidateRefFrames`
reference-picture invalidation, which Moonlight/Sunshine use as the mid step —
`Limelight.h:252-277`, `video.cpp:565-570`).

---

## 9. Chroma (4:4:4) and bit-depth support matrix (verified 2026-08-28)

| Vendor / API | H.264 4:4:4 | H.264 10-bit | HEVC 4:4:4 | HEVC 10-bit | HEVC 4:2:2 | AV1 8/10-bit | AV1 4:4:4 | Source |
|---|---|---|---|---|---|---|---|---|
| **NVIDIA NVENC** | ✅ all gens Turing→Blackwell ("only CAVLC" footnote) | Blackwell only ("Starting from Blackwell ... H264 high-10 profile") | ✅ all gens | ✅ (Pascal+) | Blackwell only | Ada+ (Main, 4:2:0 8/10-bit) | ❌ FFmpeg: "AV1 High Profile not supported, required for 4:4:4 encoding" (`nvenc.c:1673-1675`); app note lists AV1 4:2:0 only | NVENC Application Note 13.1 (https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-application-note/index.html), support matrix (https://developer.nvidia.com/video-encode-and-decode-gpu-support-matrix-new), SDK 13 blog (https://developer.nvidia.com/blog/nvidia-video-codec-sdk-13-0-powered-by-nvidia-blackwell/: "New YUV 4:2:2 encoding support (H.264 and HEVC)", `NV_ENC_BUFFER_FORMAT_NV16/P210`); FFmpeg caps checks `NV_ENC_CAPS_SUPPORT_YUV444_ENCODE`, `_10BIT_ENCODE`, `_YUV422_ENCODE` (`nvenc.c:500-553`, `nvEncodeAPI.h:1080,1122,1243`); H.264 4:4:4 ⇒ profile High 4:4:4 Predictive forced (`nvenc.c:1388-1391`), HEVC 4:4:4/4:2:2 ⇒ RExt (`:1593-1595`) |
| **Intel (VA-API / QSV, media-driver)** | not in feature table (QSV `high_444p` profile exists in Sunshine `video.cpp:129,927` — probe) | ❌ (VAAPI H.264 rejects non-4:2:0 profiles, `vaapi_encode_h264.c:1021-1028`; High10 listed `:950`) | ✅ **encode from ICL (Gen11) onward**: "HEVC 8bit 444 ... D/E" for NVL, PTL, BMG, LNL, MTLx, DG2, DG1, TGLx, EHL, ICL; blank for KBL/BXT/SKL/BDW | ✅ (row "HEVC 10bit") | ✅ same gens as 4:4:4 (row "HEVC 8bit 422"/"10bit 422", MTL decode-only) | encode DG2 (Arc) and MTL/LNL/BMG/PTL/NVL; TGL/DG1 decode-only | ❌ only "AV1 8bit"/"AV1 10bit" rows (4:2:0) | `intel/media-driver README.md:106-133` (columns `NVL, PTL, BMG, LNL, MTLx, DG2/ATSM, DG1/SG1, TGLx, EHL/JSL, ICL, KBLx, BXTx, SKL, BDW`). FFmpeg VAAPI HEVC maps `AV_PROFILE_HEVC_REXT` (`vaapi_encode_h265.c:1011`) — needs `hevc_vaapi -profile rext` with 4:4:4 input; verify per driver at runtime |
| **AMD (AMF / VCN, and VA-API on Mesa)** | ❌ | ❌ (AMF `COLOR_BIT_DEPTH` 8/10 for HEVC/AV1 only; H.264 10-bit absent) | ❌ **"At this point, 4:4:4 encoding is not supported by the hardware."** — AMD (rhutsAMD), 2024-01-22, GPUOpen AMF issue #441 (7900 XTX, `AMF_INVALID_FORMAT`) | ✅ (driver ≥ 23.30 per `amfenc.c:176-177`, `AMF_VIDEO_ENCODER_HEVC_COLOR_BIT_DEPTH`) | ❌ | ✅ (RDNA3+, `AMF_VIDEO_ENCODER_AV1_COLOR_BIT_DEPTH`) | ❌ | https://github.com/GPUOpen-LibrariesAndSDKs/AMF/issues/441 (comments via GitHub API); AMF headers have no chroma-format property (`VideoEncoderVCE.h`, `VideoEncoderHEVC.h`, `VideoEncoderAV1.h` grep 444/CHROMA → none); Sunshine `amdvce` declares no 4:4:4 formats (`video.cpp:942-951`) |
| **Apple VideoToolbox** | ❌ (FFmpeg `avc_pix_fmts` = NV12/YUV420P, `videotoolboxenc.c:2722-2727`) | ❌ | ⚠️ undocumented: FFmpeg `hevc_pix_fmts` = NV12, YUV420P, BGRA, AYUV, **P010LE, P210** (`:2729-2738`) ⇒ 4:2:0 and 4:2:2 10-bit only; `kVTProfileLevel_HEVC_Main444*` constants are reported by `VTSessionCopySupportedPropertyDictionary` on Apple Silicon but undocumented (HandBrake issue #4885) | ✅ `kVTProfileLevel_HEVC_Main10_AutoLevel` (`:965-983`) | ✅ `Main42210` (HandBrake #4885; FFmpeg P210) | decode only (M3+; plan §A.2) | ❌ | https://github.com/HandBrake/HandBrake/issues/4885 ; Sunshine `videotoolbox` lists NV12/P010, no 4:4:4 (`video.cpp:1327-1335`) |
| **x264 / x265 (software)** | ✅ `high444` (`libx264.c:314-315,818-821,1273-1274`) | ✅ `high10` | ✅ (x265 RExt) | ✅ | ✅ | rav1e/SVT-AV1: 4:4:4 supported by the codec spec (High profile) — CPU cost prohibitive at 1080p60 (codecs.md §4) | — | Sunshine `software` lists YUV444P/YUV444P10 (`video.cpp:1123-1124`) |

Moonlight/Sunshine capability bits mirror this: `VIDEO_FORMAT_H264_HIGH8_444`, `H265_REXT8_444`,
`H265_REXT10_444`, `AV1_HIGH8_444`, `AV1_HIGH10_444` (`Limelight.h:225-241`) — AV1 4:4:4
is *defined* on the wire but no hardware encoder above produces it.

Implication for plan §B.5 "text-mode 4:4:4": offer it on NVENC (H.264/HEVC), Intel Gen11+
(HEVC), x264 fallback; hide it on AMD, VideoToolbox, and for AV1 everywhere. Probe with
`avcodec_open2` on the 4:4:4 pix_fmt (NVENC/VAAPI fail fast) rather than trusting tables.

---

## 10. Dirty-region / damage tracking per capture API

| API | Mechanism | Availability | Source |
|---|---|---|---|
| **Windows.Graphics.Capture** | `Direct3D11CaptureFrame.DirtyRegions : IVectorView<RectInt32>` (read-only per frame); `GraphicsCaptureSession.DirtyRegionMode : GraphicsCaptureDirtyRegionMode { ReportOnly = 0, ReportAndRender = 1 }` (get/set); contract attribute `ContractVersion(UniversalApiContract, 1245184)` (= 19.0) | docs monikers `winrt-26100`, `winrt-28000`, `winrt-insider` ⇒ **Windows 11 24H2 (build 26100) or later**; MS pages carry no prose — semantics per `windows-capture` 2.0.1 `src/settings.rs`: "ReportOnly: Only report the dirty regions without rendering them separately" / "ReportAndRender: Report and render the dirty regions" | https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframe.dirtyregions ; https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscapturesession.dirtyregionmode ; https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscapturedirtyregionmode ; https://docs.rs/crate/windows-capture/latest/source/src/settings.rs |
| **PipeWire (xdg-desktop-portal ScreenCast)** | `SPA_META_VideoDamage`: "array of struct spa_meta_region with damage, where an invalid entry or end-of-array marks the end." `struct spa_meta_region { struct spa_region region; }`, valid iff `size.width != 0 && size.height != 0` (`spa_meta_region_is_valid`); iterate with `spa_meta_for_each`. Sibling metas: `SPA_META_VideoCrop`, `SPA_META_Cursor` (`spa_meta_cursor`/`spa_meta_bitmap`), `SPA_META_Header` (pts/seq/flags), `SPA_META_VideoTransform`, `SPA_META_SyncTimeline` | The client must *request* the meta in its buffer params (`SPA_PARAM_Meta` with `SPA_META_VideoDamage`); whether the compositor fills it is compositor-specific (open question §14) | `spa/include/spa/buffer/meta.h:29-40, 93-99` (https://gitlab.freedesktop.org/pipewire/pipewire/-/raw/master/spa/include/spa/buffer/meta.h) — docs.pipewire.org page for the group 404s |
| **macOS ScreenCaptureKit** | Sample-buffer attachment dictionary keys `SCStreamFrameInfo`: `.dirtyRects` — "A key to retrieve the areas of a video frame that contain changes. The associated value is an array of rectangles that represents a union of the rectangles redrawn and moved."; `.contentRect` "content rectangle of a video frame"; `.boundingRect`, `.screenRect`, `.contentScale`, `.scaleFactor`, `.displayTime`, `.status` (complete/idle/blank/…) | all macOS **12.3+** | https://developer.apple.com/documentation/screencapturekit/scstreamframeinfo (JSON: `.../scstreamframeinfo.json`, `.../scstreamframeinfo/dirtyrects.json`) |

Use: dirty rects feed (a) the "static screen ⇒ skip encode / send heartbeat" path (SCKit
`status == .idle`, WGC empty `DirtyRegions`, PipeWire empty damage array), (b) encoder ROI/
skip hints later (NVENC `qpDeltaMap`, x264 `mb_info`, QSV ROI — v2), (c) HUD stats. Never
send partial frames over the wire in v1 — the codecs handle unchanged blocks cheaply already.

---

## 11. Jitter buffer & frame-queue heuristics in Moonlight/Sunshine (and libwebrtc)

- **moonlight-common-c video (`RtpVideoQueue.c`)**: no time-based jitter buffer. A frame is
  reassembled from packets in `pendingFecBlockList`; `reconstructFrame` returns the frame as
  soon as `count ≥ bufferDataPackets` (FEC-decodes only if some data shards are missing,
  `:194-231, 261-336`); if a packet of a *newer* frame/block arrives while the current frame
  is incomplete, the current frame is dropped and reported ("Reinitialize the queue if ...
  we can't finish a frame before receiving the next one", `:591-600`). Out-of-order tolerance
  is `RTP_QUEUE_DELAY 10` ms ("bounds the time that the RTP queue will wait for missing/
  reordered packets", `VideoStream.c:23-26`); socket buffer sized for `RTP_RECV_PACKETS_BUFFERED 2048`
  packets ("probably 2 or 3 frames", `:28-35`). Frame loss ⇒ reference-frame invalidation
  request (`connectionDetectedFrameLoss`) or IDR after `CONSECUTIVE_DROP_LIMIT 120` frames
  (`VideoDepacketizer.c:30,116-128`); decode-unit queue depth 15 (`:63`).
- **moonlight-qt Pacer (`pacer.cpp`)**: `MAX_QUEUED_FRAMES 3`, `PACER_MAX_OUTSTANDING_FRAMES = 3+1+1`
  (`pacer.h:14`, `pacer.cpp:21-23`), `TIMER_SLACK_MS 3`. V-sync path: drop target **1**
  frame, relaxed to **3** if the queue was ≤ 1 at any point in a rolling 500 ms history
  (`:207-231`); render path: drop target **0** (or 1 for non-buffering renderers), relaxed to
  **2** with the same 500 ms history (`:354-381`). I.e. "present-on-arrival, allow ≤ 1 frame
  of buffering, catch up by dropping" — matches plan §B.4's 0–3 frames clamp.
- **Audio**: 5 ms packets, RS 4+2, OOS wait 20+10 ms (§5.5), audio queue overflow ⇒ flush
  (`AudioStream.c:150-156`).
- **libwebrtc receive timing** (for the "smooth" mode): playout delay = `max(min_delay, jitter_delay)
  + decode + render_delay`; low-latency rendering only if `max_playout_delay ≤ 500 ms`
  (`timing.cc:37-38, 60-72`); base min delay range [0, 10 s] (`video_receive_stream2.cc:108-109`).

Tornect jitter target (plan §B.4) restated with sources: `target = clamp(p95(inter-arrival
jitter over 2 s), 0, 3 frames)`; "prefer latency" = present-on-arrival + Moonlight drop
targets (1/0); "prefer smoothness" = vsync-aligned with target 1–2 frames. Abandon an
incomplete frame when the next frame's first datagram arrives or after `frame_interval + 10 ms`,
whichever is first.

---

## 12. Sources snapshot (downloaded 2026-08-28; line numbers refer to these)

Scratch copies live in `/tmp/claude-1000/-home-mx-Tornect/b2f3e64f-485b-49d6-9b2f-633094bb7a19/scratchpad/src/`
(session-temporary). Canonical URLs:

- RFCs: https://www.rfc-editor.org/rfc/rfc{3550,3551,5109,6184,6330,6716,7587,7798,8888,9000,9221}.txt
- draft-ietf-rmcat-gcc-02: https://www.ietf.org/archive/id/draft-ietf-rmcat-gcc-02.txt
- libwebrtc (`main`): https://webrtc.googlesource.com/src/+/refs/heads/main/{modules/congestion_controller/goog_cc/trendline_estimator.cc,.h, modules/congestion_controller/goog_cc/inter_arrival_delta.cc,.h, modules/remote_bitrate_estimator/aimd_rate_control.cc, modules/congestion_controller/goog_cc/delay_based_bwe.cc, modules/congestion_controller/goog_cc/goog_cc_network_control.cc, modules/pacing/pacing_controller.cc,.h, api/transport/network_types.h, modules/video_coding/timing/timing.cc, video/video_receive_stream2.cc, docs/native-code/rtp-hdrext/abs-capture-time/README.md, docs/native-code/rtp-hdrext/abs-send-time/README.md}
- FFmpeg `release/8.0`: https://raw.githubusercontent.com/FFmpeg/FFmpeg/release/8.0/libavcodec/{nvenc.c,nvenc_h264.c,nvenc_hevc.c,nvenc_av1.c,libx264.c,amfenc.c,amfenc_h264.c,amfenc_hevc.c,amfenc_av1.c,vaapi_encode.c,vaapi_encode_h264.c,vaapi_encode_h265.c,hw_base_encode.c,videotoolboxenc.c,qsvenc.c,qsvenc_h264.c}
- nv-codec-headers `nvEncodeAPI.h` (NVENCAPI 13.1): https://raw.githubusercontent.com/FFmpeg/nv-codec-headers/master/include/ffnvcodec/nvEncodeAPI.h
- x264: https://code.videolan.org/videolan/x264/-/raw/master/x264.h
- libva: https://raw.githubusercontent.com/intel/libva/master/va/va.h
- Intel media-driver README: https://raw.githubusercontent.com/intel/media-driver/master/README.md
- AMF headers/docs: https://raw.githubusercontent.com/GPUOpen-LibrariesAndSDKs/AMF/master/amf/public/include/components/{VideoEncoderVCE.h,VideoEncoderHEVC.h,VideoEncoderAV1.h}, `.../amf/doc/AMF_Video_Encode_{,HEVC_,AV1_}API.md`; issue https://github.com/GPUOpen-LibrariesAndSDKs/AMF/issues/441
- NVIDIA: https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-video-encoder-api-prog-guide/index.html , https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-application-note/index.html , https://developer.nvidia.com/blog/nvidia-video-codec-sdk-13-0-powered-by-nvidia-blackwell/
- Sunshine (`master`): https://raw.githubusercontent.com/LizardByte/Sunshine/master/src/{stream.cpp,audio.cpp,config.cpp,config.h,video.cpp,rtsp.cpp,nvenc/nvenc_base.cpp}
- moonlight-common-c (`master`): https://raw.githubusercontent.com/moonlight-stream/moonlight-common-c/master/src/{RtpVideoQueue.c,.h,RtpAudioQueue.c,.h,VideoStream.c,AudioStream.c,VideoDepacketizer.c,Connection.c,Limelight.h}
- moonlight-qt: https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/streaming/video/ffmpeg-renderers/pacer/{pacer.cpp,pacer.h}
- libopus: https://gitlab.xiph.org/xiph/opus/-/raw/main/src/opus_demo.c ; API docs https://opus-codec.org/docs/opus_api-1.5/
- PipeWire: https://gitlab.freedesktop.org/pipewire/pipewire/-/raw/master/spa/include/spa/buffer/meta.h
- Qualcomm RaptorQ Technical Overview PDF: https://www.qualcomm.com/media/documents/files/raptorq-technical-overview.pdf
- Apple: https://developer.apple.com/documentation/screencapturekit/scstreamframeinfo (+ `.json` data endpoints); HandBrake issue https://github.com/HandBrake/HandBrake/issues/4885
- Microsoft Learn WGC pages (§10)

---

## 13. Compatibility / build requirements

- **Nothing new to build.** GCC controller, pacer, packetizer, XOR/RaptorQ FEC, clock/offset
  math, jitter buffer are pure Rust over `quinn` 0.11.11, `raptorq` 2.0.1, `opus` 0.4.0 — all
  three compile on this VM (quic.md §2, codecs.md §9). No rand_core/digest/rustls/wgpu
  coupling is introduced (feedback messages are CBOR/fixed structs; no crypto).
- Encoder knobs (§8) and chroma probing (§9) require the CI FFmpeg 8.0 build with
  `libavcodec-dev` + libclang (codecs.md §9); NVENC/AMF/QSV/VideoToolbox only on the
  respective CI runners/hardware — nothing here runs on this VM.
- Dirty regions (§10): WGC needs the `windows` crate with `Graphics_Capture` feature and a
  runtime check for Windows ≥ 26100 (`ApiInformation::IsPropertyPresent("Windows.Graphics.Capture.Direct3D11CaptureFrame","DirtyRegions")`);
  PipeWire needs `pipewire`/`pipewire-sys` (bindgen, CI only — wayland.md); SCKit needs
  `objc2-screen-capture-kit` (macOS CI).

---

## 14. Gotchas

1. `max_datagram_size()` can shrink mid-session (black-hole ⇒ 1200); the packetizer must
   re-derive symbol size per frame, and the receiver must accept a per-frame symbol size
   (put it in the frame's first datagram or derive from `frame_len/frag_count`).
2. RaptorQ symbol size must be a multiple of the alignment (crate default 8) — 1162−16 =
   1146 ⇒ use 1144; 1414−16 = 1398 ⇒ 1392.
3. GCC constants are unit-sensitive: draft K_u/K_d apply to `m(i)` in ms with Δt in ms;
   libwebrtc's k_up/k_down apply to `modified_trend` (dimensionless slope × 4 × 60). Copy one
   implementation whole.
4. Draft's Kalman assumes the receiver-side variant; for sender-side (ours) the "arrival
   time" is the feedback's ATO and the "departure time" is our send time — losses of
   *feedback* datagrams must not be counted as media loss (send feedback on a reliable stream
   or make it idempotent).
5. Opus LBRR never fires in `RESTRICTED_LOWDELAY`/CELT; do not budget for it. Passing a
   wrong `frame_size` to PLC/FEC decode corrupts decoder state (docs §5.1) — always one frame.
6. 90 kHz/48 kHz timestamps must come from *capture* time, not encode-complete time, or the
   offset estimator absorbs encoder latency variance into "network jitter".
7. NVENC intra-refresh silently disables itself unless `gopLength == NVENC_INFINITE_GOPLENGTH`
   (`nvEncodeAPI.h:1883`); FFmpeg sets that automatically when `intra-refresh=1`, Sunshine's
   native path sets it explicitly. `intraRefreshCnt < intraRefreshPeriod` is required.
8. VAAPI has no intra-refresh in FFmpeg; and "infinite GOP" is flaky ⇒ Sunshine's
   `LIMITED_GOP_SIZE`. Plan on periodic IDR every N s on VAAPI with `idr_interval=INT_MAX`
   and `g` large but finite (e.g. 2400 = 40 s @60), and a smaller `rc_buffer_size` to
   flatten the IDR spike.
9. AMD: no 4:4:4 at all; AMF intra-refresh for HEVC/AV1 is not reachable through FFmpeg's
   `hevc_amf`/`av1_amf` options — only `h264_amf intra_refresh_mb`.
10. VideoToolbox: no intra-refresh, no on-demand refresh other than a full keyframe; keep
    `MaxKeyFrameInterval` ≈ 2 s and rely on `ForceKeyFrame` + FEC.
11. WGC dirty regions are absent before Windows 11 24H2 — feature-detect; `ReportAndRender`
    changes what the frame texture contains (only dirty areas rendered) — use `ReportOnly`
    for a full-frame encode pipeline.
12. PipeWire `SPA_META_VideoDamage` is only present if requested *and* supported by the
    compositor (GNOME/Mutter vs KWin vs wlroots differ) — treat "no damage meta" as
    "everything dirty".
13. Sunshine's FEC percentage is applied *after* the encoder bitrate is reduced by the same
    ratio (`rtsp.cpp:1261-1262`) — our ABR must subtract FEC + audio + redundancy from the
    GCC target before programming the encoder, or the delay estimator will oscillate.
14. Moonlight caps payload at 1024 B on remote IPv4 because it has no PMTUD; quinn does
    DPLPMTUD for us — do not copy the 1024 constant.

---

## 15. Open questions

1. **Trendline vs Kalman**: both are cited; libwebrtc abandoned the Kalman in favour of the
   trendline (simpler, better with bursty video). Recommend trendline; needs a simulation
   harness (netem loss/delay) before M5 to tune `threshold_gain`/window for 60–120 fps feedback.
2. RaptorQ on tiny K (P-frames of 3–8 symbols): the +2 repair floor is 25–66 % overhead —
   XOR wins there (table §7.3); measure whether a single-parity XOR path is worth the code,
   or whether Reed–Solomon (`reed-solomon-erasure` crate, MDS) should replace both. Not
   evaluated in codecs.md.
3. Whether compositors actually populate `SPA_META_VideoDamage` for portal ScreenCast streams
   (Mutter/KWin/wlroots) — verify in the Wayland probe on this VM (GNOME) once the capture
   crate exists.
4. WGC `DirtyRegions` semantics under `ReportAndRender` (does the texture keep stale pixels
   outside dirty rects?) — MS docs have no prose; test on a Windows runner.
5. VideoToolbox HEVC 4:4:4: the `Main444*` profile constants are undocumented (HandBrake
   #4885); decide whether to probe `VTSessionCopySupportedPropertyDictionary` at runtime or
   just declare macOS 4:2:0/4:2:2-only.
6. Intel H.264 4:4:4 encode (QSV `high_444p`) is not in the media-driver feature table;
   HEVC RExt via `hevc_vaapi -profile rext` needs a hardware test.
7. Sender-side feedback transport: unreliable datagrams (RFC 8888-style, lossy) vs the
   reliable `stats` stream (head-of-line blocking delays feedback under loss). Draft assumes
   RTCP (unreliable); prototype both.
8. Audio redundancy vs RaptorQ-over-4-frames at bursty loss (also codecs.md §11.6).
