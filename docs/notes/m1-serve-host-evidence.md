# `serve_host` in `tornect host` — live evidence (2026-09-21, fourth session)

Decision M1-42. The build VM (Ubuntu 26.04, GNOME/Wayland), real Tor over the direct rung, two
instances on one machine under separate homes: `target/tornect-test/s61-host` and
`target/tornect-test/s61-client`. Both CLIs ran under pseudo-terminals driven by the script in
the appendix, which answers a pairing `yes` **only after comparing the code each side printed**.
Binary: `target/debug/tornect` built from the working tree that became the
`serve_host` commits (dev profile, optimized + debuginfo).

## Runs

| Run | Result | What it showed |
|---|---|---|
| 1 | stopped by the driver at 316 s | The driver waited at most 300 s for `REACHABLE`; Arti's own status stayed `Bootstrapping` the whole time. That status is Arti's upload self-assessment, not a precondition for connections (see the M1 rows of `docs/VERIFICATION.md`), so later runs proceed after 150 s. |
| 2 | 4/8, then the driver's fault | Ping, SAS match, pairing + control session and "no second pairing" passed. Then the driver matched the *previous* session question and typed `v` before the second question existed. The host's prompt discarded that stale line, as designed, and the popup ended `POPUP_TIMEOUT` — the stale-input protection working live. |
| 3 | 6/8, a real client bug | `unattended on` was refused during the session and `tornect panic` succeeded; the host logged `ended here (PANIC)`. But the client printed `SESSION ENDED (connection lost)` / `Circuit closed`: it read only at its next ping, and by then Tor had torn the circuit down, so the ping's write failed before the host's `BYE` was read. Fixed (the client now waits on the stream between pings) and pinned by `tor_cmd::tests::a_host_bye_between_pings_is_reported_as_the_hosts`, which fails on the old loop with `Lost(Frame(Io(Kind(BrokenPipe))))`. |
| 4 | **PASS, 8/8** | Below. |

## Run 4 — driver log

```text
[    2.8s] host ID xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion
[  152.8s] not REACHABLE yet (FAIL: timeout waiting for /REACHABLE/ in host); proceeding
[  152.8s] run: tornect ping xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion --count 3
[  162.9s]   exit 0; stdout: 'ping 1/3: rtt 566.2 ms\nping 2/3: rtt 612.5 ms\nping 3/3: rtt 705.5 ms\nPING OK n=3 min/avg/max=566.2/628.1/705.5 ms'
[  174.0s] SAS host=919 121 client=919 121
[  197.9s] connect1 exit 0
[  209.3s] run: tornect unattended on
[  209.3s]   exit 1; stdout: ''
[  209.3s] run: tornect panic
[  209.3s]   exit 0; stdout: 'Sessions ended. every handshake and session was ended; suspending the grant behind an unattended session lands at M4 (docs/PLAN.md §B.8.14)'
[  209.9s] connect2 exit 0
[  210.2s] RESULTS {'ping': True, 'sas_match': True, 'connect_pair_session': True, 'no_second_pairing': True, 'guard_refuses_on_during_session': True, 'panic_ok': True, 'panic_ends_session': True, 'host_clean_exit': True}
[  210.2s] LIVE CHECK PASS
```

## Run 4 — client, first connect (`connect <id> --pings 3 --forget`)

```text
forgot xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion; this connection pairs again
PAIRING: the host now shows a code. It must be exactly 919 121.
Did it show 919 121? Type `yes` only if the codes matched (50 s):
SESSION LIVE a72997036d6c27cb with "build-vm" (control)
session ping 1: rtt 1044.8 ms
session ping 2: rtt 710.5 ms
session ping 3: rtt 642.3 ms
SESSION ENDED (by you)
```

## Run 4 — client, second connect (`connect <id>`, ended by `tornect panic`)

```text
SESSION LIVE c7557e511c6b8d2d with "build-vm" (view-only)
session ping 1: rtt 1099.4 ms
SESSION ENDED by the host (PANIC)
```

## Run 4 — host

```text
Tornect ID: xzcxheylg6paxjxiropaw2jk7uuw2vcebtrvwbthtrlbqrf6qzn6puad.onion
PAIRING REQUEST: a device ALREADY PAIRED as "build-vm" asks to pair again (refusing does not unpair it)
  code: 919 121   <- must match the code on that device
2026-09-21T17:51:42.347610Z  INFO tornect_signal::fsm::host: device paired peer=imzrkzvbol4rkr62fr7e7epnp64fhenawtsmef45f4nsjmseitxa label=build-vm
SESSION REQUEST from "build-vm" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE a72997036d6c27cb
session with "build-vm" is live (control); `tornect panic` ends it
SESSION ENDED a72997036d6c27cb
session ended: the client left (USER)
SESSION REQUEST from "build-vm" (fingerprint b1e1-7c80-7022-9ddd)
SESSION LIVE c7557e511c6b8d2d
session with "build-vm" is live (view-only); `tornect panic` ends it
SESSION ENDED c7557e511c6b8d2d
session ended: ended here (PANIC)
Ctrl-C: shutting down
```

## Run 4 — `tornect unattended on` while the second session was live

```text
exit=1
--- stdout

--- stderr
Error: a remote session is live or ended less than 60 s ago (0x0101)
  A remote session is live or ended less than 60 s ago; access cannot be widened while someone may be watching.
```

## Appendix — the driver (Python 3, standard library only)

Run from the repository root after `cargo build --workspace --bins`:
`python3 serve_host_check.py <log-dir>`. It expects `TORNECT_PT_DIR` bridges only if direct Tor
fails.

```python
#!/usr/bin/env python3
"""Live two-instance check of `tornect host` + `tornect ping` / `connect` / `panic`
over the real Tor network, each instance under its own TORNECT_HOME and PTY.

The pairing is confirmed on both sides only if the code the host shows equals
the code the client shows: the driver compares them instead of assuming.
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
host = Proc('host', ['host'], H_HOST)
try:
    m = wait_for([host], r'Tornect ID: (\S+)', host, 240)
    onion = m.group(1)
    stamp(f'host ID {onion}')
    try:
        wait_for([host], r'REACHABLE', host, 150)
        stamp('host REACHABLE')
    except SystemExit as e:
        # REACHABLE is Arti's upload self-assessment, not a precondition for
        # connections (docs/VERIFICATION.md M1 rows): proceed and let the ping tell.
        stamp(f'not REACHABLE yet ({e}); proceeding')

    # 1. The pairing-free ping still works on the shared port (retried while
    #    the descriptor may still be propagating).
    for attempt in range(1, 5):
        p = run(f'ping{attempt}', ['ping', onion, '--count', '3'], H_CLI, 420)
        if p.returncode == 0:
            break
        for _ in range(100):
            host.pump(0.1)
    results['ping'] = p.returncode == 0 and 'PING OK n=3' in p.stdout

    # 2. First connect: pairing (codes compared) + attended session with control, 3 pings.
    # --forget: the client pairs again with a host that already pins it (M1-32).
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
    wait_for([host, cli], r'SESSION ENDED \(by you\)', cli, 180)
    wait_for([host, cli], r'session ended: the client left \(USER\)', host, 60)
    while not cli.exited():
        cli.pump(0.1)
    results['connect_pair_session'] = cli.done == 0 and cli.buf.count('session ping') == 3
    stamp(f'connect1 exit {cli.done}')

    # 3. Second connect: known host, view-only; guard refuses `unattended on`
    #    while the session is live; `tornect panic` ends it on both sides.
    host_mark = len(host.buf)
    cli = Proc('connect2', ['connect', onion], H_CLI)
    wait_for([host, cli], r'SESSION REQUEST', host, 420, since=host_mark)
    results['no_second_pairing'] = 'PAIRING REQUEST' not in host.buf[host_mark:]
    host.send('v')
    wait_for([host, cli], r'SESSION LIVE \S+ with "[^"]*" \(view-only\)', cli, 180)
    wait_for([host, cli], r'session ping 1:', cli, 60)
    on = run('unattended_on', ['unattended', 'on'], H_HOST, 60)
    results['guard_refuses_on_during_session'] = on.returncode != 0 and (
        'remote session' in (on.stdout + on.stderr).lower())
    pan = run('panic', ['panic'], H_HOST, 60)
    results['panic_ok'] = pan.returncode == 0 and 'Sessions ended' in pan.stdout
    wait_for([host, cli], r'SESSION ENDED by the host \(PANIC\)', cli, 60)
    wait_for([host, cli], r'session ended: ended here \(PANIC\)', host, 30, since=host_mark)
    while not cli.exited():
        cli.pump(0.1)
    results['panic_ends_session'] = cli.done == 0
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
    ok = results and all(results.values()) and len(results) == 8
    stamp('LIVE CHECK ' + ('PASS' if ok else 'FAIL'))
```
