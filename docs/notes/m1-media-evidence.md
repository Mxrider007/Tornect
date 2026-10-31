# The Tor media path, live: `tornect host --capture test-card` ↔ `tornect connect` (2026-09-21, fifth session)

**What ran.** Two instances on the build VM, each with its own `TORNECT_HOME` (`target/tornect-test/s61-host`,
`s61-client`) and its own PTY, over the real Tor network (direct Tor, no bridges needed). Binary: the
tree at `51e31fc` (`tornect-session`, decision M1-43). The driver is the appendix: it pairs with the SAS
compared by the driver, runs a control session with media for three pings, then a view-only session
ended by `tornect panic`.

**Result: the media path works end to end over Tor.**
- The media stream opened on port 4001 in about 1 s after `SESSION_ACCEPT`, riding the signaling
  stream's rendezvous circuit (one isolation group), and bound with the handshake's token and
  transcript.
- Session 1 (control, 3 pings, about 23 s of video): **146 of 146 test-card pictures decoded, 0
  errors, every frame index in order from 0** (`MEDIA CARD first=0 last=145 in-order`), 1280×720,
  **6.3 fps**, one keyframe.
- Session 2 (view-only): 38 pictures in order, then `tornect panic` ended both the media stream and
  the session: the host printed `screen sharing stopped (session over, ended by the host)`, and the
  client printed `SESSION ENDED by the host (PANIC)`.

**What the numbers say.**
- **The frame rate is bounded by the ack window, not by the codec or the circuit.** With 8 access
  units in flight and a round trip of about 1.0–1.3 s, the host can send at most about 8 per round
  trip: 6–7 fps against the card's and the encoder's 15. Raising `MediaLimits::window_frames` to
  about 20 would allow 15 fps at this RTT; the 512 KiB byte cap still bounds what can queue. This is
  a tuning decision for the next session, to be re-measured.
- **3–8 kbit/s is real, not a counting error.** The card is static apart from a small moving square,
  so a P-frame is a few dozen bytes (session 1: 153 pictures, 9 KiB in all). A real desktop will
  cost far more.

**The driver's verdict was FAIL, for a wording check only.**
- All eight results the driver had recorded were true.
- It then waited for `MEDIA ENDED by the host` after the panic. The client printed `MEDIA ENDED (by
  you)` instead, because the host's `BYE` arrived before its media `Close`, and the client's own stop
  signal won the race.
- The end was the host's, so the wording was wrong. The client now reports it from the session's end
  (`MEDIA ENDED by the host (the session ended)`); that change is in the tree and in the gate, but
  the live run has not been repeated with it.
- The host's Ctrl-C exit (the driver's last check) was not reached.

**Seen on the host terminal.** OpenH264 prints its own warning at encoder start (`bEnableFrameSkip =
0, bitrate can't be controlled …`). It is harmless but noisy on the consent terminal.

## Driver log

```text
[    3.1s] host ID xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion
[  153.2s] not REACHABLE yet (FAIL: timeout waiting for /REACHABLE/ in host); proceeding
[  153.2s] run: tornect ping xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion --count 3
[  216.0s]   exit 1; stdout: ''
[  225.9s] run: tornect ping xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion --count 3
[  255.8s]   exit 0; stdout: 'ping 1/3: rtt 2813.2 ms\nping 2/3: rtt 924.6 ms\nping 3/3: rtt 1773.8 ms\nPING OK n=3 min/avg/max=924.6/1837.2/2813.2 ms'
[  267.1s] SAS host=413 050 client=413 050
[  270.4s] media bound 1280x720
[  293.8s] media summary: MEDIA OK pictures=146 units=146 keyframes=1 errors=0 size=1280x720 fps=6.3 kbps=3
[  293.8s] card: MEDIA CARD first=0 last=145 in-order
[  294.4s] connect1 exit 0
[  314.3s] run: tornect panic
[  314.3s]   exit 0; stdout: 'Sessions ended. every handshake and session was ended; suspending the grant behind an unattended session lands at M4 (docs/PLAN.md §B.8.14)'
[  318.0s] RESULTS {'ping': True, 'sas_match': True, 'media_bound': True, 'media_pictures': True, 'media_card_in_order': True, 'connect1_exit': True, 'no_second_pairing': True, 'panic_ok': True}
[  318.0s] MEDIA LIVE CHECK FAIL
FAIL: connect2 exited (0) before /MEDIA ENDED by the host/
```

## Client, session 1 (`connect <id> --pings 3 --forget`)

```text
2026-09-21T22:24:14.617094Z  INFO tornect_signal::tor::node: onion stream open host=xzcxheyl port=4000
connected in 7.7 s
SESSION LIVE faca85e8e409a90c with "build-vm" (control)
2026-09-21T22:24:17.042396Z  INFO tornect_signal::tor::node: connecting to host over Tor host=xzcxheyl port=4001
2026-09-21T22:24:18.089151Z  INFO tornect_signal::tor::node: onion stream open host=xzcxheyl port=4001
MEDIA BOUND 1280x720 (control)
session ping 1: rtt 857.8 ms
video: 34 pictures, 6.8 fps, 1280x720
video: 66 pictures, 6.5 fps, 1280x720
session ping 2: rtt 1104.3 ms
video: 98 pictures, 6.4 fps, 1280x720
video: 130 pictures, 6.4 fps, 1280x720
session ping 3: rtt 1325.6 ms
MEDIA OK pictures=146 units=146 keyframes=1 errors=0 size=1280x720 fps=6.3 kbps=3
MEDIA CARD first=0 last=145 in-order
MEDIA ENDED (by you)
SESSION ENDED (by you)
```

## Client, session 2 (`connect <id>`, view-only, ended by `tornect panic`)

```text
connected in 9.2 s
SESSION LIVE e2641a86775d873b with "build-vm" (view-only)
MEDIA BOUND 1280x720 (view-only)
session ping 1: rtt 1108.6 ms
video: 35 pictures, 6.9 fps, 1280x720
MEDIA OK pictures=38 units=38 keyframes=1 errors=0 size=1280x720 fps=6.9 kbps=8
MEDIA CARD first=0 last=37 in-order
MEDIA ENDED (by you)
SESSION ENDED by the host (PANIC)
```

## Host

```text
sharing: a synthetic test card (no desktop; viewers' input goes nowhere)
Tornect ID: xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion
SESSION REQUEST from "build-vm" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE faca85e8e409a90c
session with "build-vm" is live (control); `tornect panic` ends it
[OpenH264] this = 0x0x785c7c000cc0, Warning:bEnableFrameSkip = 0,bitrate can't be controlled for RC_QUALITY_MODE,RC_BITRATE_MODE and RC_TIMESTAMP_MODE without enabling skip frame.
SHARING faca85e8e409a90c
sharing this screen with "build-vm" (synthetic 1280x720; their input goes nowhere here); `tornect panic` stops it
SHARING STOPPED faca85e8e409a90c
screen sharing stopped (the viewer left): 153 pictures, 9 KiB sent
SESSION ENDED faca85e8e409a90c
session ended: the client left (USER)
SESSION REQUEST from "build-vm" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE e2641a86775d873b
session with "build-vm" is live (view-only); `tornect panic` ends it
[OpenH264] this = 0x0x785c7c3856b0, Warning:bEnableFrameSkip = 0,bitrate can't be controlled for RC_QUALITY_MODE,RC_BITRATE_MODE and RC_TIMESTAMP_MODE without enabling skip frame.
SHARING e2641a86775d873b
sharing this screen with "build-vm" (synthetic 1280x720; view-only); `tornect panic` stops it
SESSION ENDED e2641a86775d873b
session ended: ended here (PANIC)
SHARING STOPPED e2641a86775d873b
screen sharing stopped (session over, ended by the host): 38 pictures, 5 KiB sent
```

## Re-run, 2026-09-22 (seventh session): a 20-unit window

Same driver, same homes, the tree at `2be80fc` plus the window change.
- **Run 1:** session 1 gave 309/309 pictures, 0 errors, the card in order (0–308), **13.2 fps**.
  The client then shut Tor down right after its `BYE`, and the host logged the end as `io`: the
  flushed `BYE` never left. The driver stopped there, waiting for "the client left (USER)".
- **Run 2:** 296 pictures, **13.0 fps**, and **all 10 checks true**, including `tornect panic`
  ending media and session and a clean host exit. The driver said FAIL only because it asked for
  11 results from its 10 checks, fixed below.
- **Fix for run 1** (`4377916`): `ClientSession::bye` waits for the host to close (it closes once
  it has read the `BYE`) before closing, within 3 s.

## The loopback demo (the quality design's step 18), 2026-10-24

`tornect demo --loopback --headless-stats` (`apps/tornect/src/demo_cmd.rs`, `e8475168`): a real `MediaHost` and
`MediaViewer` in one process over a 4 MiB `tokio::io::duplex`, no Tor, no network, no window. The source is the
stamped test card; the host serves it as it serves a Tor stream (`Route::Tor`, so each preset runs its Tor row:
Best quality 12 fps, Balanced 15, Best performance 20) with `MediaLimits`' defaults and the given encoder
threads. End to end (e2e) runs from the card's capture stamp of picture *n* to the viewer having decoded and
converted picture *n* (one in-process clock). `encode p50` is the median of the host's per-second mean encode
times; B7 `convert+encode` is the host's scale + convert + encode per picture sent; `capture` is the card's own
paint per fresh picture; `lost` is pictures sent minus pictures decoded.

**Where it ran:** not the dev VM (GNOME, VMware): this build container (4 vCPU "Intel(R) Xeon(R) Processor @
2.10GHz", x86_64, no GPU, no display), as root (the demo serves nobody, so the host's root refusal of M1-67
does not apply to it). Binary: `cargo build --release -p tornect` (thin LTO, codegen-units 1) of the working tree
during this work: before the pre-bind log budget (`e6ca6411`) and the demo's last edit (`e8475168`'s error
text for a viewer left behind); neither touches the loopback path's timing, and `e2034c61` changes only the
Wayland source. Each run 10 s, the card at 30 fps, one run at a
time, nothing else running. Command, for each row:
`target/release/tornect demo --loopback --headless-stats --size <WxH> --quality <preset> --threads <n> --seconds 10`
(stderr, OpenH264's own warnings, left out).

| `--size` | `--quality` | `--threads` | picture | fps | e2e p50 / p95 ms | encode p50 ms | decode p50 ms | lost | B7 capture | B7 convert+encode | B7 decode | exit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1280x720 | best-quality | 1 | 1280x720 | 11.8 | 8.5 / 13.1 | 5.5 | 1.3 | 0 | 0.7/4 PASS | 6.8/5 FAIL | 1.4/4 PASS | 0 |
| 1280x720 | balanced | 1 | 1280x720 | 14.8 | 8.6 / 12.2 | 5.6 | 1.3 | 0 | 0.7/4 PASS | 6.8/5 FAIL | 1.4/4 PASS | 0 |
| 1280x720 | best-performance | 1 | 1280x720 | 19.7 | 8.4 / 13.5 | 5.6 | 1.3 | 0 | 0.7/4 PASS | 6.9/5 FAIL | 1.3/4 PASS | 0 |
| 1920x1080 | best-quality | 1 | 1920x1080 | 11.7 | 18.0 / 27.4 | 11.6 | 3.0 | 0 | 1.7/4 PASS | 14.1/5 FAIL | 3.3/4 PASS | 0 |
| 1920x1080 | balanced | 1 | 1920x1080 | 14.6 | 19.3 / 26.3 | 12.3 | 3.0 | 0 | 1.6/4 PASS | 15.3/5 FAIL | 3.3/4 PASS | 0 |
| 1920x1080 | best-performance | 1 | 1280x720 | 19.3 | 11.6 / 15.8 | 5.3 | 1.3 | 0 | 1.5/4 PASS | 10.0/5 FAIL | 1.3/4 PASS | 0 |
| 2560x1440 | best-quality | 1 | 2560x1440 | 11.6 | 31.7 / 49.2 | 20.6 | 5.3 | 0 | 2.9/4 PASS | 24.9/5 FAIL | 5.6/4 FAIL | 0 |
| 2560x1440 | balanced | 1 | 1920x1080 | 14.4 | 25.0 / 33.1 | 11.5 | 3.0 | 0 | 2.9/4 PASS | 21.0/5 FAIL | 3.1/4 PASS | 0 |
| 2560x1440 | best-performance | 1 | 1280x720 | 18.9 | 10.8 / 16.6 | 5.5 | 1.3 | 0 | 2.8/4 PASS | 9.3/5 FAIL | 1.3/4 PASS | 0 |
| 3538x1918 | best-quality | 1 | 3538x1918 | 10.3 | 387.8 / 975.3 | 41.9 | 9.7 | 9 | 5.3/4 FAIL | 49.5/5 FAIL | 10.4/4 FAIL | 1 |
| 3538x1918 | balanced | 1 | 1920x1040 | 13.9 | 32.3 / 41.3 | 17.1 | 3.0 | 0 | 5.3/4 FAIL | 28.5/5 FAIL | 3.2/4 PASS | 0 |
| 3538x1918 | best-performance | 1 | 1280x692 | 18.1 | 16.7 / 20.6 | 6.5 | 1.5 | 0 | 5.1/4 FAIL | 14.6/5 FAIL | 1.6/4 PASS | 0 |
| 1280x720 | best-quality | 0 | 1280x720 | 11.9 | 8.1 / 11.8 | 5.3 | 1.4 | 0 | 0.8/4 PASS | 6.6/5 FAIL | 1.5/4 PASS | 0 |
| 1280x720 | balanced | 0 | 1280x720 | 14.8 | 8.2 / 12.9 | 5.2 | 1.3 | 0 | 0.7/4 PASS | 6.7/5 FAIL | 1.4/4 PASS | 0 |
| 1280x720 | best-performance | 0 | 1280x720 | 19.7 | 8.6 / 11.7 | 5.8 | 1.4 | 0 | 0.7/4 PASS | 6.9/5 FAIL | 1.4/4 PASS | 0 |
| 1920x1080 | best-quality | 0 | 1920x1080 | 11.8 | 17.2 / 25.0 | 10.6 | 2.9 | 0 | 1.7/4 PASS | 13.5/5 FAIL | 3.2/4 PASS | 0 |
| 1920x1080 | balanced | 0 | 1920x1080 | 14.6 | 17.2 / 25.1 | 11.0 | 2.9 | 0 | 1.6/4 PASS | 13.7/5 FAIL | 3.1/4 PASS | 0 |
| 1920x1080 | best-performance | 0 | 1280x720 | 19.3 | 11.8 / 16.6 | 5.6 | 1.3 | 0 | 1.6/4 PASS | 10.4/5 FAIL | 1.4/4 PASS | 0 |
| 2560x1440 | best-quality | 0 | 2560x1440 | 11.6 | 28.9 / 45.5 | 18.0 | 5.1 | 0 | 2.9/4 PASS | 23.0/5 FAIL | 5.6/4 FAIL | 0 |
| 2560x1440 | balanced | 0 | 1920x1080 | 14.4 | 24.7 / 33.1 | 11.0 | 2.9 | 0 | 3.0/4 PASS | 21.3/5 FAIL | 3.1/4 PASS | 0 |
| 2560x1440 | best-performance | 0 | 1280x720 | 18.9 | 10.9 / 15.8 | 5.6 | 1.4 | 0 | 2.9/4 PASS | 9.3/5 FAIL | 1.5/4 PASS | 0 |
| 3538x1918 | best-quality | 0 | 3538x1918 | 10.7 | 349.1 / 590.5 | 40.3 | 9.2 | 5 | 5.5/4 FAIL | 48.0/5 FAIL | 10.1/4 FAIL | 1 |
| 3538x1918 | balanced | 0 | 1920x1040 | 13.9 | 30.9 / 38.7 | 15.6 | 3.0 | 0 | 5.3/4 FAIL | 27.0/5 FAIL | 3.1/4 PASS | 0 |
| 3538x1918 | best-performance | 0 | 1280x692 | 18.1 | 17.2 / 24.4 | 6.6 | 1.5 | 0 | 5.3/4 FAIL | 15.7/5 FAIL | 1.6/4 PASS | 0 |

A whole run as printed (the other 23 have the same shape):

```
### tornect demo --loopback --headless-stats --size 1920x1080 --quality balanced --threads 1 --seconds 10
DEMO START size=1920x1080 fps=30 quality=balanced picture=1920x1080 threads=1
STATS t=1 fps=15.9 picture=1920x1080 kbps=75 grab_ms=2.7 age_ms=0.0 scale_ms=0.0 convert_ms=2.1 encode_ms=18.5 send_ms=0.2 ack_ms=7.0 decode_ms=4.5 yuv2rgb_ms=1.9 e2e_ms=27.0
STATS t=2 fps=14.5 picture=1920x1080 kbps=8 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=2.1 encode_ms=14.1 send_ms=0.2 ack_ms=5.0 decode_ms=3.1 yuv2rgb_ms=1.6 e2e_ms=21.5
STATS t=3 fps=14.7 picture=1920x1080 kbps=9 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.7 encode_ms=11.8 send_ms=0.2 ack_ms=4.8 decode_ms=2.9 yuv2rgb_ms=1.5 e2e_ms=18.1
STATS t=4 fps=14.5 picture=1920x1080 kbps=9 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.7 encode_ms=11.6 send_ms=0.2 ack_ms=5.2 decode_ms=3.3 yuv2rgb_ms=1.6 e2e_ms=18.5
STATS t=5 fps=14.5 picture=1920x1080 kbps=9 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.8 encode_ms=12.3 send_ms=0.2 ack_ms=5.3 decode_ms=3.4 yuv2rgb_ms=1.7 e2e_ms=19.7
STATS t=6 fps=14.6 picture=1920x1080 kbps=8 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.8 encode_ms=16.3 send_ms=0.2 ack_ms=4.9 decode_ms=2.9 yuv2rgb_ms=1.6 e2e_ms=22.7
STATS t=7 fps=14.6 picture=1920x1080 kbps=9 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.8 encode_ms=12.9 send_ms=0.2 ack_ms=4.8 decode_ms=2.9 yuv2rgb_ms=1.6 e2e_ms=19.5
STATS t=8 fps=14.6 picture=1920x1080 kbps=8 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.7 encode_ms=11.9 send_ms=0.2 ack_ms=4.9 decode_ms=3.0 yuv2rgb_ms=1.6 e2e_ms=18.6
STATS t=9 fps=14.5 picture=1920x1080 kbps=9 grab_ms=1.5 age_ms=0.0 scale_ms=0.0 convert_ms=1.8 encode_ms=12.2 send_ms=0.2 ack_ms=5.0 decode_ms=3.2 yuv2rgb_ms=1.6 e2e_ms=19.2
SUMMARY frames=147 fps=14.6 e2e_p50_ms=19.3 e2e_p95_ms=26.3 encode_p50_ms=12.3 decode_p50_ms=3.0 lost=0 unreadable=0
B7 capture=1.6/4 PASS convert+encode=15.3/5 FAIL decode=3.3/4 PASS (B.7 targets are hardware, 1080p60, direct path)
### exit=0
```

**Read against §B.7** (its targets are for hardware encoders at 1080p60 on the direct path; this is the
software OpenH264 path of the slice, so the misses are expected and stated, not waived):

- **convert+encode: FAIL in all 24 runs** (6.6 ms at 720p … 49.5 ms at 3538×1918 Best quality, against
  5 ms). OpenH264 alone takes 5.2–5.8 ms per 720p picture here.
- **decode: FAIL at 2560×1440 Best quality** (5.6/4 ms) **and 3538×1918 Best quality** (10.1–10.4/4); PASS
  at every picture of 1920 wide or less (1.3–3.3 ms).
- **capture: FAIL at 3538×1918** (5.1–5.5/4 ms): this is the test card's paint of 6.8 Mpx, not a capture
  backend; real backends report their own `Frame.grab` (NEEDS-DEVICE rows in `docs/VERIFICATION.md`).
- **Delivered rates match the Tor rows:** Best quality 11.6–11.9 fps of 12, Balanced 13.9–14.8 of 15, Best
  performance 18.1–19.7 of 20: at least 90 % of each cap, with nothing lost, except Best quality at
  3538×1918 (10.3–10.7 fps; next point).
- **Best quality at 3538×1918 does not keep up (exit 1 both times):** the viewer's RGBA conversion takes
  73–103 ms per picture (STATS `yuv2rgb_ms`), slower than the host's 12 fps, so pictures queue in the ack
  window: `ack_ms` climbs from 168 to 896 ms over 9 s and e2e p50 is 349–388 ms (p95 590–975). At the
  host's end the viewer is still 5–9 pictures behind, its next write meets the closed pipe ("broken pipe"),
  and the demo exits 1. A re-run with the new error text (`e8475168`) said the same with 3 pictures behind.
- **The cause is the picture's width, not its size:** the `openh264` crate converts with SIMD only when the
  width is a multiple of 8 (`openh264-0.9.8/src/decoder.rs:604`, `write_rgba8`) and otherwise falls back to a
  scalar loop. Every scaled picture's width is a multiple of 8 (`picture_size`), but a desktop under a
  preset's cap is encoded at its own width (only an odd edge cropped): 3538 (the dev VM), 1366 (common
  laptops). Measured side by side (10 s, Best quality, `--threads 1`; STATS lines but the last left out):

```
### --size 3536x1918 --quality best-quality --threads 1
DEMO START size=3536x1918 fps=30 quality=best-quality picture=3536x1918 threads=1
STATS t=9 fps=11.2 picture=3536x1918 kbps=9 grab_ms=5.0 age_ms=0.0 scale_ms=0.0 convert_ms=6.0 encode_ms=38.4 send_ms=0.2 ack_ms=16.0 decode_ms=10.5 yuv2rgb_ms=5.3 e2e_ms=60.6
SUMMARY frames=113 fps=11.2 e2e_p50_ms=64.5 e2e_p95_ms=90.3 encode_p50_ms=41.4 decode_p50_ms=10.3 lost=0 unreadable=0
B7 capture=5.8/4 FAIL convert+encode=51.0/5 FAIL decode=11.0/4 FAIL (B.7 targets are hardware, 1080p60, direct path)
### exit=0
### --size 1366x768 --quality best-quality --threads 1
DEMO START size=1366x768 fps=30 quality=best-quality picture=1366x768 threads=1
STATS t=9 fps=11.8 picture=1366x768 kbps=6 grab_ms=0.8 age_ms=0.0 scale_ms=0.0 convert_ms=1.0 encode_ms=7.8 send_ms=0.2 ack_ms=15.4 decode_ms=1.5 yuv2rgb_ms=13.8 e2e_ms=24.1
SUMMARY frames=119 fps=11.8 e2e_p50_ms=23.9 e2e_p95_ms=31.6 encode_p50_ms=7.8 decode_p50_ms=1.8 lost=0 unreadable=0
B7 capture=0.8/4 PASS convert+encode=8.5/5 FAIL decode=1.8/4 PASS (B.7 targets are hardware, 1080p60, direct path)
### exit=0
### --size 1368x768 --quality best-quality --threads 1
DEMO START size=1368x768 fps=30 quality=best-quality picture=1368x768 threads=1
STATS t=9 fps=11.8 picture=1368x768 kbps=14 grab_ms=0.8 age_ms=0.0 scale_ms=0.0 convert_ms=1.0 encode_ms=8.0 send_ms=0.2 ack_ms=3.5 decode_ms=1.9 yuv2rgb_ms=1.1 e2e_ms=12.3
SUMMARY frames=119 fps=11.8 e2e_p50_ms=11.0 e2e_p95_ms=19.5 encode_p50_ms=8.0 decode_p50_ms=1.8 lost=0 unreadable=0
B7 capture=0.9/4 PASS convert+encode=9.0/5 FAIL decode=1.9/4 PASS (B.7 targets are hardware, 1080p60, direct path)
### exit=0
```

  12–19 times the conversion cost (13.8 against 1.1 ms; 73–103 against 5.3 ms) for 2 columns. Recorded as an OPEN finding in `docs/VERIFICATION.md`
  ("RGBA conversion of a picture whose width is not a multiple of 8"); not fixed here: either the host fits
  every picture's width to a multiple of 8 (a crop of up to 7 columns, which amends M1-74 (3)'s "the whole
  desktop but for an odd last column") or `tornect-codec` converts the last columns itself. Fixed since by a variant of
  the second (`9ad7e9f9`: the codec converts such a width whole): the next section.
- **Encoder threads (`--threads 0`, automatic: 3 on 4 vCPU) against 1:** encode p50 1.04–1.14× faster at
  1080p and above (20.6 → 18.0 ms at 2560×1440 Best quality, 41.9 → 40.3 ms at 3538×1918), no change at 720p.
  Far from the 1.5× that design §9 asks before the default may change: the default stays 1 (M1-74 (5)).
- **`unreadable=0` in every run:** each decoded picture's index was read back from the strip and matched to
  its capture stamp, so the e2e numbers are per picture, not estimates.
- `kbps` falls to 6–14 after the first second: the card is a still picture with a moving square and strip,
  so it measures CPU stages, not link rates (those come from the live Tor run, design §9 row 1, NEEDS-DEVICE).

## The loopback demo after the final reviews' fixes, 2026-10-24

The same container, command and reading as the section above, with a binary built at `7301bc70` (`cargo build
--release -p tornect`, 4 min 6 s): the codec's own RGBA conversion for a width that is not a multiple of 8
(`9ad7e9f9`), the stop-aware pacing (`2f7ea666`), the gate's turn (`17303ea2`) and the Wayland retry
(`7301bc70`, not on this path). The commit after it changes only a doc comment and the docs. Each run 10 s, one at
a time, nothing else running; stderr (OpenH264's warnings) left out. `yuv2rgb` is the range of the viewer's
per-second conversion means.

| `--size` | `--quality` | `--threads` | picture | fps | e2e p50 / p95 ms | encode p50 ms | decode p50 ms | yuv2rgb ms | lost | B7 capture | B7 convert+encode | B7 decode | exit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 3538x1918 | best-quality | 1 | 3538x1918 | 11.2 | 79.8 / 109.8 | 39.8 | 10.1 | 22.8–26.5 | 0 | 5.4/4 FAIL | 48.1/5 FAIL | 10.8/4 FAIL | 0 |
| 3538x1918 | best-quality | 0 | 3538x1918 | 11.3 | 71.8 / 103.6 | 32.5 | 9.5 | 23.4–26.3 | 0 | 5.4/4 FAIL | 41.4/5 FAIL | 10.1/4 FAIL | 0 |
| 3538x1918 | balanced | 1 | 1920x1040 | 13.9 | 31.2 / 39.3 | 16.4 | 3.0 | 1.4–1.7 | 0 | 5.3/4 FAIL | 27.1/5 FAIL | 3.1/4 PASS | 0 |
| 1366x768 | best-quality | 1 | 1366x768 | 11.8 | 14.1 / 19.8 | 8.1 | 1.8 | 4.0–5.2 | 0 | 0.9/4 PASS | 8.6/5 FAIL | 1.8/4 PASS | 0 |
| 1368x768 | best-quality | 1 | 1368x768 | 11.8 | 10.5 / 15.8 | 7.5 | 1.8 | 0.7–1.0 | 0 | 0.8/4 PASS | 8.4/5 FAIL | 1.7/4 PASS | 0 |
| 1920x1080 | balanced | 1 | 1920x1080 | 14.6 | 18.4 / 26.1 | 12.1 | 2.9 | 1.4–1.8 | 0 | 1.6/4 PASS | 14.7/5 FAIL | 3.0/4 PASS | 0 |

The first row as printed:

```
### tornect demo --loopback --headless-stats --size 3538x1918 --quality best-quality --threads 1 --seconds 10
DEMO START size=3538x1918 fps=30 quality=best-quality picture=3538x1918 threads=1
STATS t=1 fps=12.0 picture=3538x1918 kbps=422 grab_ms=9.2 age_ms=0.0 scale_ms=0.0 convert_ms=6.4 encode_ms=52.4 send_ms=0.2 ack_ms=41.9 decode_ms=15.0 yuv2rgb_ms=25.5 e2e_ms=98.8
STATS t=2 fps=11.2 picture=3538x1918 kbps=8 grab_ms=4.8 age_ms=0.0 scale_ms=0.0 convert_ms=5.6 encode_ms=38.6 send_ms=0.2 ack_ms=32.5 decode_ms=9.7 yuv2rgb_ms=22.8 e2e_ms=77.5
STATS t=3 fps=11.3 picture=3538x1918 kbps=10 grab_ms=5.0 age_ms=0.0 scale_ms=0.0 convert_ms=5.7 encode_ms=37.7 send_ms=0.2 ack_ms=33.5 decode_ms=9.1 yuv2rgb_ms=23.9 e2e_ms=76.4
STATS t=4 fps=11.3 picture=3538x1918 kbps=8 grab_ms=4.9 age_ms=0.0 scale_ms=0.0 convert_ms=5.7 encode_ms=38.4 send_ms=0.2 ack_ms=34.3 decode_ms=9.9 yuv2rgb_ms=24.3 e2e_ms=78.3
STATS t=5 fps=11.3 picture=3538x1918 kbps=10 grab_ms=4.8 age_ms=0.0 scale_ms=0.0 convert_ms=5.8 encode_ms=36.8 send_ms=0.2 ack_ms=36.1 decode_ms=10.6 yuv2rgb_ms=25.1 e2e_ms=78.6
STATS t=6 fps=11.0 picture=3538x1918 kbps=10 grab_ms=4.8 age_ms=0.0 scale_ms=0.0 convert_ms=6.2 encode_ms=39.8 send_ms=0.4 ack_ms=34.9 decode_ms=10.9 yuv2rgb_ms=24.8 e2e_ms=82.7
STATS t=7 fps=10.9 picture=3538x1918 kbps=8 grab_ms=4.8 age_ms=0.0 scale_ms=0.0 convert_ms=6.2 encode_ms=39.8 send_ms=0.4 ack_ms=34.9 decode_ms=10.3 yuv2rgb_ms=25.0 e2e_ms=89.4
STATS t=8 fps=11.8 picture=3538x1918 kbps=8 grab_ms=5.5 age_ms=0.0 scale_ms=0.0 convert_ms=6.2 encode_ms=47.0 send_ms=0.2 ack_ms=36.5 decode_ms=10.9 yuv2rgb_ms=26.5 e2e_ms=91.3
STATS t=9 fps=11.2 picture=3538x1918 kbps=9 grab_ms=4.6 age_ms=0.0 scale_ms=0.0 convert_ms=5.9 encode_ms=47.7 send_ms=0.2 ack_ms=37.7 decode_ms=10.8 yuv2rgb_ms=24.9 e2e_ms=83.2
SUMMARY frames=113 fps=11.2 e2e_p50_ms=79.8 e2e_p95_ms=109.8 encode_p50_ms=39.8 decode_p50_ms=10.1 lost=0 unreadable=0
B7 capture=5.4/4 FAIL convert+encode=48.1/5 FAIL decode=10.8/4 FAIL (B.7 targets are hardware, 1080p60, direct path)
### exit=0
```

- **Best quality at 3538×1918 now keeps up (exit 0 with `--threads 1` and `0`, nothing lost):** the viewer's
  conversion takes 22.8–26.5 ms a picture, against 73–103 ms before, so `ack_ms` stays at 32–42 ms instead of
  climbing to 896, and e2e p50 is 72–80 ms instead of 349–388. 11.2–11.3 fps of 12 is 93 %.
- **1366×768:** 4.0–5.2 ms against 13.8 before; the ×8 width beside it (1368, still `openh264`'s AVX2 path)
  0.7–1.0. The codec's converter is not as fast as that path (here about 4–5× its cost per pixel, in a
  process whose encoder is busy on another core), but it is no longer the stage that limits the viewer: decode
  plus conversion at 3538×1918 (about 35 ms) fits in Best quality's 83 ms interval.
- **Unchanged by the fixes:** 1920×1080 Balanced (14.6 fps, e2e p50 18.4 against 19.3 ms) and 3538×1918
  Balanced (13.9 fps, 31.2 against 32.3 ms) read as before, within run-to-run noise; §B.7's software-path
  FAILs stand as in the section above.

## Appendix: the driver (Python 3, standard library only)

Run from the repository root after `cargo build --workspace --bins`:
`python3 media_live_check.py <log-dir>`.

```python
#!/usr/bin/env python3
"""Live two-instance check of the Tor media path: `tornect host --capture test-card`
and `tornect connect` over the real Tor network, each instance under its own
TORNECT_HOME and PTY (the driver of docs/notes/m1-serve-host-evidence.md, extended
for media).

The pairing is confirmed on both sides only if the code the host shows equals the
code the client shows: the driver compares them instead of assuming.
"""
import os, pty, re, select, signal, subprocess, sys, time

ROOT = '/home/mx/Tornect'
BIN = f'{ROOT}/target/debug/tornect'
PT = f'{ROOT}/target/pt/linux-x86_64/tor/pluggable_transports'
H_HOST = f'{ROOT}/target/tornect-test/s61-host'
H_CLI = f'{ROOT}/target/tornect-test/s61-client'
LOG = sys.argv[1]
os.makedirs(LOG, exist_ok=True)
T0 = time.time()


def stamp(msg):
    line = f'[{time.time() - T0:7.1f}s] {msg}'
    print(line, flush=True)
    with open(f'{LOG}/driver.log', 'a') as f:
        f.write(line + '\n')


def env_for(home):
    return dict(os.environ, TORNECT_HOME=home, TORNECT_PT_DIR=PT, TMPDIR=f'{ROOT}/target/tmp',
                NO_COLOR='1')


class Proc:
    def __init__(self, name, args, home):
        self.name = name
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(BIN, [BIN] + args, env_for(home))
        self.pid, self.fd, self.buf, self.done = pid, fd, '', None
        self.log = open(f'{LOG}/{name}.log', 'w')

    def pump(self, timeout=0.2):
        try:
            r, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            return ''
        if not r:
            return ''
        try:
            data = os.read(self.fd, 65536).decode('utf-8', 'replace')
        except OSError:
            data = ''
        if data:
            self.buf += data
            self.log.write(data)
            self.log.flush()
        return data

    def send(self, line):
        os.write(self.fd, (line + '\n').encode())
        self.log.write(f'\n[[driver typed: {line}]]\n')
        self.log.flush()

    def exited(self):
        if self.done is not None:
            return True
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.done = -1
            return True
        if pid == 0:
            return False
        self.done = os.waitstatus_to_exitcode(status)
        return True

    def interrupt(self):
        try:
            os.kill(self.pid, signal.SIGINT)
        except ProcessLookupError:
            pass


def run(name, args, home, timeout):
    stamp(f'run: tornect {" ".join(args)}')
    p = subprocess.run([BIN] + args, env=env_for(home), capture_output=True, text=True,
                       timeout=timeout)
    with open(f'{LOG}/{name}.log', 'w') as f:
        f.write(f'exit={p.returncode}\n--- stdout\n{p.stdout}\n--- stderr\n{p.stderr}')
    stamp(f'  exit {p.returncode}; stdout: {p.stdout.strip()[-300:]!r}')
    return p


def wait_for(procs, pattern, who, timeout, since=0):
    """Pump every proc until `pattern` appears in `who`'s buffer at or after `since`."""
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < deadline:
        for p in procs:
            p.pump(0.05)
        m = rx.search(who.buf, since)
        if m:
            return m
        if who.exited():
            raise SystemExit(f'FAIL: {who.name} exited ({who.done}) before /{pattern}/')
    raise SystemExit(f'FAIL: timeout waiting for /{pattern}/ in {who.name}')


results = {}
host = Proc('host', ['host', '--capture', 'test-card'], H_HOST)
try:
    wait_for([host], r'sharing: a synthetic test card', host, 30)
    m = wait_for([host], r'Tornect ID: (\S+)', host, 240)
    onion = m.group(1)
    stamp(f'host ID {onion}')
    try:
        wait_for([host], r'REACHABLE', host, 150)
        stamp('host REACHABLE')
    except SystemExit as e:
        # REACHABLE is Arti's upload self-assessment, not a precondition (see the evidence note).
        stamp(f'not REACHABLE yet ({e}); proceeding')

    # 1. The pairing-free ping still works on the shared port (retried while the
    #    descriptor may still be propagating).
    for attempt in range(1, 5):
        p = run(f'ping{attempt}', ['ping', onion, '--count', '3'], H_CLI, 420)
        if p.returncode == 0:
            break
        for _ in range(100):
            host.pump(0.1)
    results['ping'] = p.returncode == 0 and 'PING OK n=3' in p.stdout

    # 2. First connect: pairing (codes compared) + attended control session with media, 3 pings.
    cli = Proc('connect1', ['connect', onion, '--pings', '3', '--forget'], H_CLI)
    hs = wait_for([host, cli], r'code: (\d{3} \d{3})', host, 420).group(1)
    cs = wait_for([host, cli], r'It must be exactly (\d{3} \d{3})', cli, 60).group(1)
    stamp(f'SAS host={hs} client={cs}')
    results['sas_match'] = hs == cs
    host.send('yes' if hs == cs else 'no')
    wait_for([host, cli], r'Did it show (\d{3} \d{3})\?', cli, 120)
    cli.send('yes' if hs == cs else 'no')
    wait_for([host, cli], r'SESSION REQUEST', host, 120)
    host.send('a')
    wait_for([host, cli], r'SESSION LIVE \S+ with "[^"]*" \(control\)', cli, 180)
    m = wait_for([host, cli], r'MEDIA BOUND (\d+)x(\d+) \(control\)', cli, 120)
    stamp(f'media bound {m.group(1)}x{m.group(2)}')
    results['media_bound'] = (m.group(1), m.group(2)) == ('1280', '720')
    wait_for([host, cli], r'SHARING \S+', host, 30)
    wait_for([host, cli], r'SESSION ENDED \(by you\)', cli, 240)
    m = wait_for([host, cli], r'MEDIA (OK|EMPTY) pictures=(\d+) units=(\d+) keyframes=(\d+) errors=(\d+) size=(\d+)x(\d+) fps=([\d.]+) kbps=(\d+)', cli, 60)
    stamp(f'media summary: {m.group(0)}')
    results['media_pictures'] = m.group(1) == 'OK' and int(m.group(2)) > 0 and m.group(5) == '0'
    card = re.search(r'MEDIA CARD first=(\d+) last=(\d+) in-order', cli.buf)
    stamp(f'card: {card.group(0) if card else None}')
    results['media_card_in_order'] = bool(card) and int(card.group(2)) > int(card.group(1))
    wait_for([host, cli], r'SHARING STOPPED \S+', host, 60)
    wait_for([host, cli], r'session ended: the client left \(USER\)', host, 60)
    while not cli.exited():
        cli.pump(0.1)
    results['connect1_exit'] = cli.done == 0 and cli.buf.count('session ping') == 3
    stamp(f'connect1 exit {cli.done}')

    # 3. Second connect: known host, view-only; `tornect panic` ends session and media.
    host_mark = len(host.buf)
    cli = Proc('connect2', ['connect', onion], H_CLI)
    wait_for([host, cli], r'SESSION REQUEST', host, 420, since=host_mark)
    results['no_second_pairing'] = 'PAIRING REQUEST' not in host.buf[host_mark:]
    host.send('v')
    wait_for([host, cli], r'MEDIA BOUND \d+x\d+ \(view-only\)', cli, 180)
    wait_for([host, cli], r'view-only\); `tornect panic` stops it', host, 60, since=host_mark)
    wait_for([host, cli], r'video: \d+ pictures', cli, 90)
    pan = run('panic', ['panic'], H_HOST, 60)
    results['panic_ok'] = pan.returncode == 0
    wait_for([host, cli], r'MEDIA ENDED by the host', cli, 60)
    wait_for([host, cli], r'SESSION ENDED by the host \(PANIC\)', cli, 60)
    wait_for([host, cli], r'SHARING STOPPED \S+', host, 30, since=host_mark)
    wait_for([host, cli], r'session ended: ended here \(PANIC\)', host, 60, since=host_mark)
    while not cli.exited():
        cli.pump(0.1)
    results['panic_ends_media_and_session'] = cli.done == 0
    stamp(f'connect2 exit {cli.done}')

    # 4. Ctrl-C stops the host cleanly.
    host.interrupt()
    deadline = time.time() + 60
    while not host.exited() and time.time() < deadline:
        host.pump(0.1)
    results['host_clean_exit'] = host.done == 0
finally:
    for p in [host]:
        if not p.exited():
            p.interrupt()
            time.sleep(3)
            if not p.exited():
                os.kill(p.pid, signal.SIGKILL)
    stamp(f'RESULTS {results}')
    ok = results and all(results.values()) and len(results) == 10
    stamp('MEDIA LIVE CHECK ' + ('PASS' if ok else 'FAIL'))
```
