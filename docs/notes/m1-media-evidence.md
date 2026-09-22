# The Tor media path, live: `tornect host --capture test-card` ↔ `tornect connect` (2026-09-21, fifth session)

**What ran.** Two instances on mx-vm, each with its own `TORNECT_HOME` (`target/tornect-test/s61-host`,
`s61-client`) and its own PTY, over the real Tor network (direct Tor, no bridges needed). Binary: the
tree at `fd672b7` (`tornect-session`, decision M1-43). The driver is the appendix: it pairs with the SAS
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
SESSION LIVE faca85e8e409a90c with "mx-VMware-Virtual-Platform" (control)
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
SESSION LIVE e2641a86775d873b with "mx-VMware-Virtual-Platform" (view-only)
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
SESSION REQUEST from "mx-VMware-Virtual-Platform" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE faca85e8e409a90c
session with "mx-VMware-Virtual-Platform" is live (control); `tornect panic` ends it
[OpenH264] this = 0x0x785c7c000cc0, Warning:bEnableFrameSkip = 0,bitrate can't be controlled for RC_QUALITY_MODE,RC_BITRATE_MODE and RC_TIMESTAMP_MODE without enabling skip frame.
SHARING faca85e8e409a90c
sharing this screen with "mx-VMware-Virtual-Platform" (synthetic 1280x720; their input goes nowhere here); `tornect panic` stops it
SHARING STOPPED faca85e8e409a90c
screen sharing stopped (the viewer left): 153 pictures, 9 KiB sent
SESSION ENDED faca85e8e409a90c
session ended: the client left (USER)
SESSION REQUEST from "mx-VMware-Virtual-Platform" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE e2641a86775d873b
session with "mx-VMware-Virtual-Platform" is live (view-only); `tornect panic` ends it
[OpenH264] this = 0x0x785c7c3856b0, Warning:bEnableFrameSkip = 0,bitrate can't be controlled for RC_QUALITY_MODE,RC_BITRATE_MODE and RC_TIMESTAMP_MODE without enabling skip frame.
SHARING e2641a86775d873b
sharing this screen with "mx-VMware-Virtual-Platform" (synthetic 1280x720; view-only); `tornect panic` stops it
SESSION ENDED e2641a86775d873b
session ended: ended here (PANIC)
SHARING STOPPED e2641a86775d873b
screen sharing stopped (session over, ended by the host): 38 pictures, 5 KiB sent
```

## Re-run, 2026-09-22 (seventh session): a 20-unit window

Same driver, same homes, the tree at `2ee219c` plus the window change.
- **Run 1:** session 1 gave 309/309 pictures, 0 errors, the card in order (0–308), **13.2 fps**.
  The client then shut Tor down right after its `BYE`, and the host logged the end as `io`: the
  flushed `BYE` never left. The driver stopped there, waiting for "the client left (USER)".
- **Run 2:** 296 pictures, **13.0 fps**, and **all 10 checks true**, including `tornect panic`
  ending media and session and a clean host exit. The driver said FAIL only because it asked for
  11 results from its 10 checks, fixed below.
- **Fix for run 1** (`c641ae6`): `ClientSession::bye` waits for the host to close (it closes once
  it has read the `BYE`) before closing, within 3 s.

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
