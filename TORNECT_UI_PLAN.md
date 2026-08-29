# TORNECT — UI Plan

**Companion to `docs/PLAN.md` (the master plan). This document refines master-plan
decision D10 and fully specifies the user interface: framework choice, app
architecture, every screen, the design system, per-platform integration, and the
agent-driven UI workflow for Claude Code.** Commit as `docs/UI_PLAN.md`.

**Plan date:** 2026-08-28, framework landscape verified by web research on this date.

---

## 1. Hard requirements the UI stack must satisfy

Derived from the streaming system (master plan §B), in priority order. Any
framework proposal is scored against these — they are the spec, the framework is
an implementation detail.

- **R1 — Video surface.** The client's decoded frames arrive as GPU textures in a
  wgpu-centric pipeline (master §B.5). The stream view must present them with zero
  extra copies/compositors and no framework-imposed frame pacing. An overlay HUD
  must render *in the same pass* at negligible cost (<1 ms).
- **R2 — Trust surfaces that cannot fail.** Consent popup, pairing SAS dialog, and
  the persistent "sharing" indicator must appear reliably — including above
  fullscreen apps where the OS permits — on Windows, macOS, and Wayland. These are
  security UI; flakiness here is a product-killing bug.
- **R3 — Native Wayland first-class.** No X11-only paths, no components that
  routinely break on Wayland/NVIDIA. (This requirement alone reshapes the
  framework choice — see §2.)
- **R4 — Multi-window + tray.** Main shell, stream window(s), floating indicator,
  tray icon/menu, system notifications, file dialogs.
- **R5 — One language, no IPC seams.** UI must call directly into
  `tornect-session` (async Rust); serializing app state across a webview IPC
  boundary is pure liability for a real-time app.
- **R6 — Agent-verifiable.** Claude Code builds this UI; the stack must support
  headless rendering/screenshots and deterministic state injection so agents can
  *see* and test their work (workflow in §10).
- **R7 — Modern feel & velocity.** Themeable to a distinctive look (not
  "developer-tool gray"), smooth motion, fast iteration (hot reload strongly
  preferred).
- **R8 — Small footprint.** No bundled browser runtime; installers stay lean;
  RAM budget for the shell ≤ ~150 MB.
- **R9 — Future mobile path** (post-v1): the choice shouldn't paint us into a
  desktop-only corner, but v1 ships on desktop and mobile must not tax it.
- **R10 — Accessibility & i18n.** Screen-reader tree (AccessKit or platform
  native), full keyboard nav, IME support, runtime language switch.

## 2. Framework landscape — verified Aug 2026

| Candidate | State (verified) | R1 video | R3 Wayland | R5 no-IPC | R6 agent-testable | R7 velocity | Verdict |
|---|---|---|---|---|---|---|---|
| **Iced** | 0.14 (Dec 2025): reactive rendering, **headless testing**, **hot reload**, time-travel debugger, IME support. Battle-proven: **COSMIC desktop 1.0 shipped stable Dec 2025** (Pop!_OS 24.04 LTS) through 1.3 (Jul 2026) is built entirely on Iced, *on Wayland* | ✅ wgpu-native; `shader` widget hosts custom wgpu content | ✅ proven at DE scale | ✅ pure Rust | ✅ headless testing is a headline 0.14 feature | ✅ hot reload; Elm architecture is explicit and LLM-friendly | **PRIMARY — app shell** |
| **egui/eframe** | Mature, stable cadence, AccessKit integrated; immediate-mode | ✅ trivial `PaintCallback` into any wgpu pass | ✅ | ✅ | ✅ (`egui_kittest` snapshots) | Fast but utilitarian look without heavy styling | **KEPT — in-stream HUD overlay** (and risk-floor fallback for the shell) |
| **Tauri 2** | Healthy core: v2 stable Oct 2024, 2.10.x by Mar 2026, iOS/Android shipping | ⚠️ video must live in a separate native window regardless | ❌ **Tauri's own docs ship a "Linux Graphics Issues" page**: WebKitGTK vs (mostly NVIDIA) drivers → blank windows/artifacts; AppImage bundler still forces `GDK_BACKEND=x11` (open issue Jul 2026); NVIDIA-forum crash reports on Wayland | ❌ webview IPC | ⚠️ web testing fine, but two stacks | ✅✅ web UI velocity is unmatched | **Documented alternative** — only if web-polish + fastest mobile outweigh the Linux webview risk on our flagship platform |
| **Dioxus Native (Blitz)** | 0.7 (Oct 2025): first release of the WGPU HTML/CSS renderer (Stylo+Vello+Taffy), shadcn-style component set; officially **experimental**, CSS gaps; default desktop renderer is still a webview | ⚠️ texture embedding demoed (Bevy example) but young | ⚠️ native renderer young; webview mode inherits WebKitGTK issues | ✅ (native mode) | ⚠️ | ✅ React-like RSX + signals + hotpatching | **Watch list** — likely the strongest future option; re-evaluate at mobile/v2 |
| **GPUI** (Zed's) | Powers Zed at huge scale; standalone use still doc-sparse, API churn | ✅ capable | ✅ | ✅ | ⚠️ | ⚠️ steep, thin docs | Watch list |
| **Slint** | Solid, good tooling/a11y, declarative DSL | ⚠️ doable, clunkier | ✅ | ✅ | ✅ | ✅ DSL | Fine, but no advantage over Iced for us; embedded-first focus |
| **Flutter** (RustDesk's choice) | Proven for exactly this app category via texture interop | ⚠️ works but via FFI bridge | ⚠️ | ❌ Dart↔Rust bridge | ⚠️ | ✅ | Rejected: second language + heavy runtime violates R5/R8 |

**The deciding facts.** (a) Our hardest, headline platform is native Wayland; the
only shell framework *proven in production on Wayland at scale* is Iced — an entire
desktop environment runs on it. (b) The historical case against Iced (docs churn,
no hot iteration, hard to test) was specifically addressed by 0.14's hot reload +
headless testing + time-travel debugging. (c) The webview route now carries a
vendor-documented graphics-risk page for exactly our target users (Linux + NVIDIA).
(d) egui already had a reserved seat in the render loop for the HUD (master §B.5);
keeping it there costs nothing and gives us a proven fallback shell if Iced ever
blocks us.

## 3. Decision — the two-layer UI

```
┌─ Layer 2: APP SHELL ─────────────── Iced 0.14+ ───────────────────────────┐
│ onboarding · home/ID card · connect · settings · devices · session log ·  │
│ consent + pairing dialogs · tray-adjacent windows · notifications glue    │
│ (Elm: single AppState + Message enum; iced Tasks/subscriptions bridge     │
│  tokio channels from tornect-session)                                     │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ spawns / controls
┌─ Layer 1: STREAM SURFACE ────▼──── winit + wgpu + egui overlay ───────────┐
│ decoded-texture present path (zero-copy), HUD pill, toolbars, latency     │
│ overlay, gaming mode, pointer lock — owns its event loop & frame pacing   │
└───────────────────────────────────────────────────────────────────────────┘
Host-side floating "SHARING" indicator: tiny dedicated winit+egui window
(always-on-top strategies per OS, §6) — deliberately NOT part of the shell
process's Iced loop so it survives shell UI hangs.
```

Rules of engagement between layers: the shell never touches frames; the stream
surface never owns app state — both talk to `tornect-session` through typed
`UiCommand`/`UiEvent` channels defined in a new `tornect-ui-api` module (inside
`tornect-session`). This keeps the door open to swap either layer independently
(e.g. future Dioxus-Native shell, or a Tauri experiment) without touching the
other — that is the "flexibility" requirement made concrete.

**Alternative track (documented, not default):** Tauri 2 + SolidJS shell with the
same `tornect-ui-api` contract and the stream window unchanged. Choose only with
eyes open to the Linux webview caveats above; revisit for mobile in v2.
**Fallback (risk floor):** egui-everywhere shell (original master-plan D10) — two
days of work to stand up because the design system in §7 is expressed as tokens,
not framework code.

## 4. UI code architecture

```
crates/tornect-ui-kit/        # THE DESIGN SYSTEM (framework-agnostic core)
├── tokens.rs                 # colors, spacing, radii, type scale, motion durations
│                             #   (single source of truth; serialized to JSON for docs)
├── theme_iced.rs             # tokens → iced::Theme + widget style classes
├── theme_egui.rs             # tokens → egui::Style (HUD + indicator share the look)
├── widgets/                  # iced components: IdCard, StatusDot, DeviceRow,
│                             #   ConsentCard, SasCode, StagePill, QualityBadge,
│                             #   HotkeyHint, SettingRow, DangerZone…
├── icons.rs                  # Lucide SVG subset baked in (iced svg / egui image)
└── l10n/                     # fluent (.ftl) bundles: en-US + pt-BR at launch
apps/tornect/src/
├── main.rs                   # role dispatch, single-instance guard, tray bootstrap
├── shell/                    # Iced app: state.rs (AppState), update.rs (Message),
│                             #   view/<screen>.rs, subscriptions.rs (session events,
│                             #   tray events, hotkeys)
├── stream_window/            # Layer 1 (winit+wgpu+egui) — created in master M3,
│                             #   adopted here unchanged, egui styled via ui-kit
├── indicator/                # host sharing pill (per-OS topmost strategies)
├── platform/                 # tray (tray-icon), notifications (notify-rust /
│                             #   Windows toast / UNUserNotification via objc2),
│                             #   autostart, deep links to OS permission panes
└── preview/                  # §10 harness: render any screen/state headlessly
```

State discipline (this is what makes the UI agent-buildable): `AppState` is a pure
value; every mutation is a `Message`; `tornect-session` events arrive as
`Message::Session(UiEvent)` via subscription; **every screen must be constructible
from a synthetic `AppState`** — no screen may reach around the state to talk to
the network. That single rule powers previews, snapshot tests, and time-travel
debugging for free.

## 5. Screen inventory & flows

Every screen listed with purpose, key states, and the ui-kit widgets it exercises.
"States" are the synthetic `AppState` fixtures the preview harness must include.

**S1 · Onboarding (first run)** — 3–4 steps, skippable never.
Welcome (what Tornect is, 2 sentences) → Permissions (per-OS dynamic, §6.4: live
status chips that re-check on window focus) → "Your Tornect ID" (identity
generated; Tor bootstrap progress: `Connecting to Tor… → Publishing your address…
(first time can take ~2 min) → Ready`) → Done. States: fresh, permissions-partial,
tor-bootstrapping, tor-error(retry).

**S2 · Home** — the resting screen.
Top: **ID card** — onion address chunked in 4-char groups, mono font, copy button,
QR toggle, "share" hint. Middle: **Connect** field (paste onion / scan QR) with
inline validation + Connect button. Bottom: **Devices** list (paired machines:
name, trust badge [Always allow / Ask / View-only / Unattended], last-seen-locally
timestamp — *no presence polling; reachability is only tested on user action*).
Master toggle: "Accept incoming requests" (maps to onion service listening).
States: empty (no devices), populated, incoming-disabled, tor-degraded banner.

**S3 · Connecting (client-side)** — full-screen stage flow with cancel.
Stages (each with icon + elapsed): `Reaching host via Tor → Waiting for approval
(shows host name + your SAS during pairing) → Establishing direct link →
Connected` — on success, hand off to stream window. Failure taxonomy with human
copy + next actions: host-unreachable (offline? wrong ID? retry), denied,
timed-out-approval, punch-failed→auto-retry-via-Tor (banner: "Connecting the slow
way — quality will be limited"), version-mismatch. States: each stage, each error.

**S4 · Consent dialog (host-side)** — THE trust surface. Spec in §6.1.

**S5 · Pairing dialog (both sides)** — SAS verification. Spec in §6.2.

**S6 · Stream window (client)** — spec in §8.

**S7 · Sharing indicator (host)** — spec in §6.3.

**S8 · Settings** — sidebar nav, instant-apply, per-item reset.
General (device name, language, launch at login, theme) · Network (STUN list
editor + "no third parties" explainer, UPnP toggle, Paranoid mode with plain-
language trade-off copy, LAN-only) · Video (codec preference Auto/AV1/HEVC/H.264,
max resolution/fps, quality presets Speed/Balanced/Fidelity, HDR flag) · Audio ·
Input (hotkey editor incl. panic key, gaming-mode defaults) · Devices (rename,
revoke, per-device trust level, **Unattended access**: enable → set password
(strength meter, argon2) → warning copy) · Identity (view/backup key, **Rotate ID**
in a DangerZone with typed confirmation) · Advanced (logs folder, wire trace
toggle, netem-style diagnostics runner).

**S9 · Session log** — reverse-chron table: when, who, direction, duration,
transport (Direct/Tor-relay), how it ended. Local-only, exportable.

**S10 · Tray menu** — status line (Idle / Sharing with X / Connected to Y),
toggle incoming, open shell, end session, quit. Tray icon states: idle, incoming-
request (attention), sharing (recording-red glyph), relayed (amber).

Navigation model: shell is a single window, `Screen` enum routing, sidebar appears
only post-onboarding, every screen reachable by keyboard (§9).

## 6. Trust surfaces — exact behavior (R2)

### 6.1 Session consent dialog (host)
Content: requester device name + fingerprint art (identicon from device pk), trust
status, requested capabilities as chips (Control / View-only / Audio), buttons:
**Allow** · **View-only** · **Deny**, checkbox "Always allow this device",
**auto-deny countdown 30 s** (visible ring), rate-limit note if repeated. Delivery
per platform:
- Windows: dedicated topmost (`WS_EX_TOPMOST`) borderless window + toast
  notification mirror (actioning either resolves both). Fullscreen-game case: the
  toast is the reliable channel; dialog takes focus only on user click.
- macOS: `NSPanel` at `.screenSaver` level, non-activating, joins all Spaces;
  mirror `UNUserNotification` with Allow/Deny actions.
- Wayland: normal always-on-top hint where honored; **the reliable channel is a
  portal notification with actions** (GNOME/KDE both honor these); wlr-layer-shell
  overlay used when the compositor exposes it (wlroots family), never required.
Rule: **capture starts only after an affirmative click somewhere** — never on
timeout, never on focus quirks (master §B.6).

### 6.2 Pairing dialog (both sides)
Shows the 6-digit SAS in giant mono type + "numbers must match on both screens"
illustration; host side embeds it inside the consent dialog (S4 variant); client
side shows it in S3's waiting stage. Mismatch → single "codes don't match" path
that cancels pairing and explains what that could mean in one calm sentence.

### 6.3 Sharing indicator (host)
28 px pill, top-center by default (draggable, position remembered): red dot +
"Sharing with <name> · 12:41 · [End]". Always-on-top strategy: Windows TOPMOST;
macOS NSPanel .statusBar level; Wayland layer-shell where available else regular
window + **compositor-native cues** (GNOME's own screen-cast indicator + our tray
red state carry the guarantee). Panic hotkey (default Ctrl+Alt+End) always armed
host-side, ends session + flashes confirmation. Indicator process outlives shell
crashes (separate task; watchdog).

### 6.4 Permission walkthroughs (inside S1 + Settings▸repair)
- macOS: Screen Recording + Accessibility cards with live granted/denied chips,
  "Open Settings" deep links (`x-apple.systempreferences:…`), re-check on focus;
  explains *why* each is needed in one line.
- Wayland: "Test screen access" button fires a ScreenCast portal request and
  stores the restore token; explains the picker is the system's, not ours.
- Windows: nothing to grant; card explains the firewall prompt they may see.

## 7. Design system

**Direction:** "quiet instrument" — dark-first, calm surfaces, one confident
accent, information-dense but airy. It should read as a precision tool (think
audio interface), not a gamer skin and not a gray dev-tool.

- **Color (dark default):** bg `#0E1116`, surface `#151A21`, raised `#1C232C`,
  border `#2A3340`; text `#E8EDF2` / secondary `#9AA7B4`; **accent (Tor-violet)
  `#7D5CFF`** for interactive; semantic: connected-green `#3DDC97`, relayed-amber
  `#FFB454`, sharing-red `#FF5C6C`, info `#4FB3FF`. Light theme derived from the
  same tokens (auto per OS, manual override). Transport is always color+word,
  never color alone (a11y).
- **Type:** UI = Inter (variable); identifiers/SAS/stats = JetBrains Mono. Scale
  13/14/16/20/28 with 1.45 line height; SAS display 44 mono.
- **Shape & space:** 4 px base grid; radii 10 (controls) / 14 (cards); 1 px
  borders over shadows; focus ring 2 px accent, always visible on keyboard nav.
- **Motion:** 140–180 ms ease-out standard; stage-flow transitions 220 ms; respect
  OS reduced-motion (tokens expose `motion=off`). No looping animation except the
  Tor bootstrap spinner and countdown ring.
- **Iconography:** Lucide, 1.5 px stroke, 18/22 px sizes, baked-in SVG subset.
- **Voice & copy:** plain language, no protocol jargon in primary UI ("Relayed via
  Tor — slower" not "TURN fallback"); errors say what happened + what to try;
  never blame the user. All strings through fluent from day one; launch locales
  **en-US + pt-BR** to keep the i18n plumbing honest (mono ID strings excluded).
- Tokens live in `tornect-ui-kit::tokens` and export to `docs/design-tokens.json`
  so docs/screenshots/agents share one truth.

## 8. Stream window UX (Layer 1 spec)

- **HUD pill** (egui, top-center, auto-hide after 2.5 s, edge-reveal): connection
  badge (● Direct green / ◍ Relayed amber + tooltip), live stats (ms · fps ·
  Mbit/s · codec), quality preset menu, monitor switcher, gaming-mode toggle,
  clipboard sync toggle, fullscreen, disconnect. Hold `F1`: hotkey cheat-sheet
  overlay.
- **Latency overlay** (toggle `F3`): per-stage bars wired to master §B.7 stats —
  this is both a user feature and the agents' acceptance instrument.
- **Gaming mode:** pointer-lock + raw deltas, HUD suppressed, cursor drawn by
  host stream; exit via `Ctrl+Alt+G` or dedicated corner hot-zone.
- **Degraded banner:** when on Tor fallback, persistent slim banner "Relayed via
  Tor — quality limited · [Retry direct]".
- **Resize behavior:** letterbox to host aspect; optional "resize remote to fit"
  action when host supports it (post-v1 for virtual display).
- Window title = host name; never the onion address (privacy on screenshares).

## 9. Accessibility & i18n

AccessKit trees on both layers (iced + egui integrations); full keyboard model
(Tab order per screen documented in code, arrow-key lists, Esc = back/cancel,
Enter = primary); visible focus always; contrast AA against tokens verified by a
unit test on the palette; hit targets ≥ 32 px; reduced-motion respected; fluent
l10n with pseudo-locale test (`en-XA` expansion) in CI; IME-safe inputs (iced 0.14
IME support) — matters for CJK device names.

## 10. Agent workflow — how Claude Code builds UI it can see

1. **Preview harness** (`apps/tornect/src/preview/`):
   `cargo run -p tornect -- ui-preview --screen s3 --state punch-failed
   --theme dark --lang pt-BR --scale 1.25 --shot /tmp/s3.png` renders any screen
   from its synthetic `AppState` fixture to PNG via wgpu offscreen (iced 0.14
   headless testing APIs; egui surfaces via `egui_kittest`). `--list` enumerates
   every screen×state. Claude Code loop: edit → shot → **view the PNG** → refine.
2. **Snapshot tests:** `cargo test -p tornect --features ui-snapshots` renders the
   full fixture matrix and diffs against `tests/ui-snapshots/` (small tolerance;
   `xtask ui-bless` to accept). Runs in CI on Linux; matrix includes both themes,
   both locales, 1.0/1.5/2.0 scale.
3. **Semantic assertions:** AccessKit tree dumps per fixture asserted for roles/
   labels — catches "button lost its label" without pixel diffing.
4. **Interaction tests:** Elm makes flows pure — feed `Message` sequences into
   `update()` and assert `AppState` (e.g. consent auto-deny after 30 ticks; deny
   ⇒ no `UiCommand::StartCapture` ever emitted — encode §B.6 invariants as tests).
5. **Hot reload** (`iced` hot-reload feature) for the human-in-the-loop sessions.
6. **`ux-reviewer` agent** (add to `.claude/agents/`, roster below): given the
   shot matrix, critiques against §7 checklist (spacing grid, contrast, copy
   voice, focus visibility, truncation at pt-BR lengths) and files issues. Runs at
   each UI milestone close, complementing `security-reviewer` on trust surfaces.

```markdown
---
name: ux-reviewer
description: Reviews rendered UI screenshots and AccessKit dumps against the
  Tornect design system (docs/UI_PLAN.md §7–§9). Use after any UI change and at
  UI milestone gates.
tools: Read, Bash, Grep, Glob
---
Generate the shot matrix (`cargo run -p tornect -- ui-preview --all --shots-dir …`),
view every image, and audit: token compliance (no hardcoded colors/sizes — grep),
4px grid, contrast pairs, focus ring presence, copy voice, pt-BR overflow, empty/
error states present, trust-surface rules from §6 intact. Output: pass/fail per
screen with file:line pointers; block on any §6 violation.
```

## 11. UI milestones (interleaved with master Part C)

| UI | Ships with | Scope | Accept |
|---|---|---|---|
| **U0** | M0 | `tornect-ui-kit` tokens + themes; shell skeleton with `Screen` routing + empty fixtures; preview harness walking skeleton; ui snapshot CI job | `ui-preview --list` renders every stub screen to PNG in CI |
| **U1** | M1 | S1 onboarding (Tor states), S2 home (ID card/QR/connect), S4+S5 consent & pairing dialogs replacing the CLI prompt; tray minimal | Pairing between two machines driven entirely through UI; consent invariants encoded as interaction tests |
| **U2** | M4 | S3 connecting stages + full error taxonomy; stream window HUD v1 + latency overlay; disconnect/reconnect UX | WAN demo (master M4 accept) performed UI-only; every S3 error state snapshot-tested |
| **U3** | M5–M6 | S8 settings, S6 devices management, §6.4 permission walkthroughs per OS, notifications + indicator on all three platforms, S10 tray complete | 3-OS matrix: consent + indicator behave per §6 on each (recorded in VERIFICATION.md); a11y keyboard pass |
| **U4** | M7 | Degraded/relayed UX, quality presets wired to ABR, gaming mode polish, reduced-motion + contrast audits | netem "hotel" profile session is understandable start-to-finish without reading docs; ux-reviewer green |
| **U5** | M8 | Onboarding polish, S9 session log, unattended-access flow, empty/edge states sweep, icon/branding assets, pt-BR review, store/installer screenshots | Master M8 "non-developer in <10 min" test passes; full snapshot matrix green on both locales/themes |

## 12. Risks & mitigations (UI-specific)

| Risk | Mitigation |
|---|---|
| Iced 0.x API churn | Pin 0.14.x; all widgets flow through `tornect-ui-kit` (one adaptation layer); the egui-everywhere fallback stays live via shared tokens; `research-verifier` gates upgrades |
| Wayland always-on-top limits (GNOME) weaken indicator | §6.3 layered guarantee: portal notification + compositor's own cast indicator + tray state are the contract; layer-shell is enhancement only |
| Consent popup vs fullscreen games on Windows | Toast mirror is the reliable channel; test matrix includes exclusive-fullscreen title in U3 |
| Custom theming effort balloons | Token-first design; ship on stock-ish widgets in U1–U2, restyle in U4–U5; ux-reviewer keeps drift down |
| pt-BR string expansion breaks layouts | Pseudo-locale CI + snapshot matrix includes pt-BR from U0 |
| Preview harness drifts from real app | Harness renders the *actual* `view()` fns from real `AppState` fixtures — no parallel UI code allowed (review rule) |
