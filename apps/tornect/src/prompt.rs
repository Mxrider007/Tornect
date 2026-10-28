//! Terminal questions standing in for the consent popups (`docs/PLAN.md`
//! §B.2) until the GUI exists: the host's pairing and session questions, and
//! the client's SAS confirmation.
//!
//! Only a terminal can answer. When stdin is not one (a service, a pipe, a
//! script), nobody is there to compare a code or to consent, so the host denies
//! every request ([`tornect_signal::pairing::AutoDeny`]) and the client
//! confirms no pairing — "yes" never comes from a script.

use std::io::IsTerminal as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard, mpsc, watch};
use tornect_core::TornectId;
use tornect_core::levels::{
    ADMIN_LINE, ADMIN_LINE_NO_PROMPT, AdminPath, Answers, Availability, LINE_VIEW_ONLY,
    SENTENCE_ADMIN_NOT_GIVEN, SENTENCE_SECURE_DESKTOP_OFF,
};
use tornect_session::INTERNET_DIRECT;
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::fsm::client::ClientPairingUi;
use tornect_signal::pairing::{
    BoxFuture, Consent, PairDecision, PairingPeer, SessionDecision, SessionRequestSummary,
    TrustedPeer,
};

use crate::ui::model::Recognition;
use crate::ui::recognize::{GoneOnDrop, Recognizer};

/// How long the client waits for its user to confirm a code. The host gives the
/// client 60 s after `PAIR_ACCEPT` to send its `SESSION_REQUEST`, and the answer
/// still has to cross Tor.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(50);

/// How long after a question is shown before a line can answer it.
///
/// A line reaches the program only at Enter, so a line that comes sooner was
/// typed, at least in part, before the question was there: most likely for a
/// question that closed just before (its time ran out), whose half-typed `a`
/// would otherwise allow the next request (audit B22). Such a line is
/// ignored, and the terminal says so. The window's sheets arm after the same
/// second (`ui::view`'s `ARM_AFTER`).
pub(crate) const ARM_AFTER: Duration = Duration::from_secs(1);

/// What the terminal says of a line that came before [`ARM_AFTER`].
pub(crate) const TOO_SOON: &str = "That answer came less than a second after the question, so \
     it may have been typed for an earlier one: it was ignored. Answer again:";

/// Lines typed on stdin, answered one question at a time.
///
/// One thread reads stdin for the life of the process, because a blocking read
/// cannot be cancelled: a question that times out must not leave a read behind
/// that swallows the answer to the next one. The thread starts at the first
/// question, not before, so a host that only ever answers pings never touches
/// the terminal (a background job that reads it would be stopped by the shell).
/// Lines typed before a question is shown are discarded, so a stale answer
/// never counts for a new question, and a line that comes within
/// [`ARM_AFTER`] of it is ignored too. A block window goes before every
/// question ([`Prompter::priority`]).
pub struct Prompter {
    lines: Mutex<Option<mpsc::Receiver<String>>>,
    source: Source,
    /// Block windows holding the terminal now ([`Prompter::priority`]): while
    /// any does, the open question's read is cancelled and no question is
    /// shown.
    blocking: watch::Sender<u32>,
    /// How many times `block` was typed in a block window: each time blocks
    /// every window open then ([`Priority::block_every_open_window`]).
    blocks: watch::Sender<u64>,
    /// What the questions showed, in order ([`Prompter::scripted`] only).
    #[cfg(test)]
    shown: std::sync::Mutex<Vec<String>>,
}

/// Whether the terminal asks the questions: only when both its input and
/// the stream the questions go to (stderr) are a terminal.
fn asks_here(stdin_is_terminal: bool, stderr_is_terminal: bool) -> bool {
    stdin_is_terminal && stderr_is_terminal
}

enum Source {
    Stdin,
    #[cfg(test)]
    Scripted,
}

impl Prompter {
    /// Stdin, or `None` when stdin or stderr is not a terminal: the question
    /// goes to stderr, and a redirected stderr is a file or a log, where the
    /// requester's words and name must not go.
    #[must_use]
    pub fn stdin() -> Option<Arc<Self>> {
        asks_here(
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
        )
        .then(|| {
            Arc::new(Self {
                lines: Mutex::new(None),
                source: Source::Stdin,
                blocking: watch::channel(0).0,
                blocks: watch::channel(0).0,
                #[cfg(test)]
                shown: std::sync::Mutex::default(),
            })
        })
    }

    /// Show `question` and wait for the next line typed after it; `None` once
    /// stdin is closed. A line that comes within [`ARM_AFTER`] of the
    /// question is ignored, with [`TOO_SOON`]. Questions queue behind one
    /// another. A block window goes before them all ([`Prompter::priority`]):
    /// while one holds the terminal, the open question's wait ends with
    /// `None` and a question queued behind it is not shown (`None` too),
    /// which every question answers as a closed terminal does, a refusal.
    pub async fn ask(&self, question: &str) -> Option<String> {
        self.ask_then(question, None).await
    }

    /// [`Prompter::ask`], and when the wait is dropped before an answer
    /// (the request's time ran out, or it went away), `closed` is printed
    /// before the terminal is let go, so before the next question shows
    /// (audit B22).
    pub async fn ask_about(&self, question: &str, closed: &str) -> Option<String> {
        self.ask_then(question, Some(closed)).await
    }

    async fn ask_then(&self, question: &str, closed: Option<&str>) -> Option<String> {
        let mut lines = self.lines.lock().await;
        if self.block_window_open() {
            return None;
        }
        if lines.is_none() {
            *lines = self.start();
        }
        let rx = lines.as_mut()?;
        while rx.try_recv().is_ok() {}
        self.say(question);
        // Declared after the lock, so dropped before it: its line shows
        // before a question queued behind this one.
        let mut open = Unanswered {
            prompter: self,
            closed,
        };
        let armed = tokio::time::Instant::now() + ARM_AFTER;
        let mut blocking = self.blocking.subscribe();
        let answer = loop {
            let line = tokio::select! {
                // Checked first: a line typed for the block window is never
                // this question's answer.
                biased;
                _ = blocking.wait_for(|open| *open > 0) => break None,
                line = rx.recv() => line,
            };
            match line {
                Some(_) if tokio::time::Instant::now() < armed => self.say(TOO_SOON),
                line => break line,
            }
        };
        open.closed = None;
        answer
    }

    /// One line on stderr, where the questions go; a line that cannot be
    /// written is lost, and the question then runs out its time, a refusal.
    fn say(&self, line: &str) {
        match self.source {
            Source::Stdin => {
                use std::io::Write as _;
                let _ = writeln!(std::io::stderr().lock(), "{line}");
            }
            #[cfg(test)]
            Source::Scripted => self
                .shown
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line.to_owned()),
        }
    }

    /// What the questions showed so far.
    #[cfg(test)]
    pub(crate) fn shown(&self) -> Vec<String> {
        self.shown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The terminal for a block window (§B.8.6.3), taken ahead of every
    /// question: from this call on, the open question's read is cancelled
    /// and no question is shown until the returned hold is dropped. The
    /// caller prints its line at once, then reads with
    /// [`Priority::next_line`].
    pub fn priority(&self) -> Priority<'_> {
        self.blocking.send_modify(|open| *open += 1);
        Priority {
            prompter: self,
            lines: None,
            blocks_before: *self.blocks.borrow(),
        }
    }

    /// Whether a block window holds the terminal.
    pub(crate) fn block_window_open(&self) -> bool {
        *self.blocking.borrow() > 0
    }

    fn start(&self) -> Option<mpsc::Receiver<String>> {
        match self.source {
            Source::Stdin => {
                let (tx, rx) = mpsc::channel(16);
                std::thread::Builder::new()
                    .name("tornect-stdin".to_owned())
                    .spawn(move || {
                        let stdin = std::io::stdin();
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match stdin.read_line(&mut line) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {
                                    if tx.blocking_send(line.trim().to_owned()).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    })
                    .ok()?;
                Some(rx)
            }
            #[cfg(test)]
            Source::Scripted => None,
        }
    }

    /// A prompter fed by the returned sender instead of stdin.
    #[cfg(test)]
    pub(crate) fn scripted() -> (Arc<Self>, mpsc::Sender<String>) {
        let (tx, rx) = mpsc::channel(16);
        let prompter = Arc::new(Self {
            lines: Mutex::new(Some(rx)),
            source: Source::Scripted,
            blocking: watch::channel(0).0,
            blocks: watch::channel(0).0,
            shown: std::sync::Mutex::default(),
        });
        (prompter, tx)
    }
}

/// A shown question not answered yet: dropped so (its wait was dropped),
/// it says `closed`.
struct Unanswered<'a> {
    prompter: &'a Prompter,
    closed: Option<&'a str>,
}

impl Drop for Unanswered<'_> {
    fn drop(&mut self) {
        if let Some(line) = self.closed {
            self.prompter.say(line);
        }
    }
}

/// A block window's hold on the terminal ([`Prompter::priority`]).
///
/// Several windows can be open at once (unattended requests overlap), and
/// the lines typed go to the one that opened first, as they cannot say which
/// request they mean. So a `block` typed there blocks every window open then,
/// each one saying so (audit B20): one `block` never lets another request
/// through that the person may have meant.
pub struct Priority<'a> {
    prompter: &'a Prompter,
    lines: Option<MutexGuard<'a, Option<mpsc::Receiver<String>>>>,
    /// [`Prompter::blocks`] when this window opened: a `block` typed after
    /// that blocks it too, one typed before does not.
    blocks_before: u64,
}

impl Priority<'_> {
    /// Block windows open now, this one included.
    pub fn open_windows(&self) -> u32 {
        *self.prompter.blocking.borrow()
    }

    /// `block` was typed: every window open now is blocked, this one and
    /// those waiting for the terminal behind it ([`Priority::blocked_by_another`]).
    pub fn block_every_open_window(&self) {
        self.prompter.blocks.send_modify(|typed| *typed += 1);
    }

    /// Resolves once `block` was typed in a window open beside this one,
    /// after this one opened; pending otherwise. Borrows nothing of the
    /// hold, so it runs beside [`Priority::next_line`].
    pub fn blocked_by_another(&self) -> impl Future<Output = ()> + Send + use<> {
        let mut blocks = self.prompter.blocks.subscribe();
        let before = self.blocks_before;
        async move {
            if blocks.wait_for(|typed| *typed > before).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// The next line typed, trimmed; `None` once stdin has ended (or could not
    /// be read). Lines typed before the hold was taken count too: the block
    /// window only looks for `block`, so a stale line can only block.
    pub async fn next_line(&mut self) -> Option<String> {
        if self.lines.is_none() {
            let prompter = self.prompter;
            // The open question lets go at once (its read is cancelled), and
            // a question queued before this hold passes without being shown.
            let mut lines = prompter.lines.lock().await;
            if lines.is_none() {
                *lines = prompter.start();
            }
            self.lines = Some(lines);
        }
        self.lines.as_mut()?.as_mut()?.recv().await
    }
}

impl Drop for Priority<'_> {
    fn drop(&mut self) {
        // Before the terminal is let go (the guard is dropped after this), so
        // a question waiting for it is shown.
        self.prompter
            .blocking
            .send_modify(|open| *open = open.saturating_sub(1));
    }
}

/// The host's consent popups, asked on the terminal.
pub struct CliConsent {
    prompter: Arc<Prompter>,
    /// The device words and the look-alike alarm (§B.6.1); without them the
    /// pairing question shows the device fingerprint as before.
    words: Option<Arc<Recognizer>>,
    /// The policy the host signs at the accept (design `direct` §3.6): read
    /// at each session question, which then says what an accept discloses
    /// on a direct path.
    transport: TransportKnob,
}

impl CliConsent {
    /// Ask through `prompter`, for a host whose sessions read `transport`.
    #[must_use]
    pub fn new(prompter: Arc<Prompter>, transport: TransportKnob) -> Self {
        Self {
            prompter,
            words: None,
            transport,
        }
    }

    /// The pairing question names an unpinned key by its device words and
    /// runs the look-alike alarm; when it fires, only the code typed from
    /// the other device pairs (§B.6.1 W-B3). The key is derived before the
    /// question, off the network task, paced for a key nobody saved.
    #[must_use]
    pub fn with_words(mut self, words: Arc<Recognizer>) -> Self {
        self.words = Some(words);
        self
    }
}

impl Consent for CliConsent {
    fn pairing<'a>(&'a self, peer: &'a PairingPeer, sas: &'a str) -> BoxFuture<'a, PairDecision> {
        Box::pin(async move {
            let seen = match &self.words {
                None => None,
                Some(words) => {
                    let words = Arc::clone(words);
                    let (device, name) = (peer.device, peer.name.clone());
                    let pinned = peer.pinned_label.is_some();
                    // The FSM's popup timeout drops this future; a derivation
                    // still queued then never runs (F-3).
                    let gone = GoneOnDrop::default();
                    let flag = gone.flag();
                    match tokio::task::spawn_blocking(move || {
                        words.pairing_sheet_unless(&flag, &device, &name, pinned)
                    })
                    .await
                    {
                        Ok(Some(seen)) => Some(seen),
                        // No words, no alarm verdict: refuse.
                        Ok(None) | Err(_) => return PairDecision::Reject,
                    }
                }
            };
            let typed = seen.as_ref().is_some_and(Recognition::typed_only);
            let who = peer.pinned_label.as_deref().unwrap_or(&peer.name);
            match self
                .prompter
                .ask_about(
                    &pairing_question(peer, sas, seen.as_ref()),
                    &closed_line(who),
                )
                .await
            {
                Some(answer) if typed => parse_typed(&answer, sas),
                Some(answer) => parse_pairing(&answer),
                None => PairDecision::Reject,
            }
        })
    }

    fn session<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision> {
        Box::pin(async move {
            match self
                .prompter
                .ask_about(
                    &session_question(peer, self.transport.get()),
                    &closed_line(&peer.label),
                )
                .await
            {
                Some(answer) => parse_session(&answer),
                None => SessionDecision::Deny,
            }
        })
    }

    fn session_at<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
        levels: &'a Availability,
    ) -> BoxFuture<'a, SessionDecision> {
        Box::pin(async move {
            match self
                .prompter
                .ask_about(
                    &session_question_at(peer, levels, self.transport.get()),
                    &closed_line(&peer.label),
                )
                .await
            {
                Some(answer) => parse_session_at(&answer, levels.offered()),
                None => SessionDecision::Deny,
            }
        })
    }

    fn session_again<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
        levels: &'a Availability,
        _: Duration,
    ) -> BoxFuture<'a, SessionDecision> {
        Box::pin(async move {
            let question = format!(
                "\n{}{}",
                SENTENCE_ADMIN_NOT_GIVEN, ": the other answers are still open.",
            ) + &session_question_at(peer, levels, self.transport.get());
            match self
                .prompter
                .ask_about(&question, &closed_line(&peer.label))
                .await
            {
                Some(answer) => parse_session_at(&answer, levels.offered()),
                None => SessionDecision::Deny,
            }
        })
    }
}

/// What the terminal says when `who`'s pairing or session question closes
/// unanswered, before the next question shows (B22).
fn closed_line(who: &str) -> String {
    format!(
        "The request from \"{who}\" closed without an answer (its time ran out, or the device \
         went away), so it is refused."
    )
}

/// The note under a session question while an accept may let the session
/// connect directly (design `direct` §3.6, \[SEC\]), in this build's words
/// ([`direct_note_in`] with [`INTERNET_DIRECT`]).
fn direct_note(label: &str, policy: TransportPolicy) -> Option<String> {
    direct_note_in(label, policy, INTERNET_DIRECT)
}

/// The note under a session question while an accept may let the session
/// connect directly: what `label` then learns (this computer's internet
/// address where direct connections reach the internet, `internet`, and
/// the policy is `Any`; its local address under `lan_only` or in a build
/// whose direct connections stay on the local network), and, while it is
/// the switch's doing, how to relay every session instead. `lan_only` has
/// no Tor to relay through, so its note names no switch; Tor only has no
/// note.
fn direct_note_in(label: &str, policy: TransportPolicy, internet: bool) -> Option<String> {
    let what = if internet && policy == TransportPolicy::Any {
        "internet address"
    } else {
        "local address"
    };
    let note = format!("  note: accepting also lets \"{label}\" learn this computer's {what}");
    match policy {
        TransportPolicy::Any => Some(format!(
            "{note} (network.paranoid = true relays through Tor)"
        )),
        TransportPolicy::LanOnly => Some(note),
        TransportPolicy::TorOnly => None,
    }
}

/// The session question of a host in the row `levels` (§B.2.1): only the
/// answers the row offers in this build, what each does, and the row's
/// sentence. The administrator answer is the whole word, typed. Under the
/// answers, what an accept discloses while `direct` lets the session
/// connect directly ([`direct_note`]).
fn session_question_at(
    peer: &TrustedPeer,
    levels: &Availability,
    direct: TransportPolicy,
) -> String {
    let answers = levels.offered();
    let mut lines = vec![format!(
        "\nSESSION REQUEST: \"{}\" wants to connect to this computer",
        peer.label
    )];
    if answers.view_only {
        lines.push(format!("  `v`  view only: {LINE_VIEW_ONLY}"));
    }
    if answers.allow {
        lines.push(format!("  `a`  allow: {}", levels.allow_line()));
    }
    let admin_line = answers.admin.map(|path| match path {
        AdminPath::WindowsPrompt => ADMIN_LINE,
        AdminPath::TornectConfirmation { .. } => ADMIN_LINE_NO_PROMPT,
    });
    if let Some(line) = admin_line {
        lines.push(format!(
            "  `administrator`  allow as administrator (type the whole word): {line}"
        ));
    }
    // The row's sentence, once: on Linux it is the line under Allow, on the
    // no-prompt row the line under the administrator answer.
    if let Some(line) = levels.offered_sentence().filter(|line| {
        !(answers.allow && *line == levels.allow_line()) && admin_line != Some(*line)
    }) {
        lines.push(format!("  {line}"));
    }
    if levels.prompts_on_shared_screen {
        lines.push(format!("  {SENTENCE_SECURE_DESKTOP_OFF}"));
    }
    lines.extend(direct_note(&peer.label, direct));
    lines.push("Anything else refuses (60 s):".to_owned());
    lines.join("\n")
}

/// The answer to [`session_question_at`]: only an answer `offered` gives.
fn parse_session_at(answer: &str, offered: Answers) -> SessionDecision {
    let answer = answer.trim().to_ascii_lowercase();
    match answer.as_str() {
        "a" | "allow" if offered.allow => SessionDecision::AllowOnce,
        "v" | "view" | "view-only" if offered.view_only => SessionDecision::AllowOnceViewOnly,
        "administrator" if matches!(offered.admin, Some(AdminPath::TornectConfirmation { .. })) => {
            SessionDecision::AllowOnceAdmin
        }
        _ => SessionDecision::Deny,
    }
}

// Every string printed here is either computed locally (the code, the device
// words, the fingerprint) or already sanitized (`normalize_label` drops control
// and invisible characters from the declared name and the pinned label, and the
// saved name the alarm names was cleaned when it was saved), so a peer cannot
// write escape sequences to this terminal.
fn pairing_question(peer: &PairingPeer, sas: &str, seen: Option<&Recognition>) -> String {
    let who = match &peer.pinned_label {
        Some(label) => format!(
            "a device ALREADY PAIRED as \"{label}\" asks to pair again (refusing does not unpair it)"
        ),
        None => format!("a device calling itself \"{}\" asks to pair", peer.name),
    };
    // One short form (§B.6.1 item 6): the words in their labelled slot for an
    // unpinned key; a pinned one is named by its pinned label; the fingerprint
    // only where no words were derived.
    let short = match seen {
        Some(seen) if peer.pinned_label.is_none() => format!(
            "  device words: {} · not yet trusted · compare the code\n",
            seen.words.shown()
        ),
        Some(_) => String::new(),
        None => format!("  device fingerprint: {}\n", peer.fingerprint),
    };
    let typed = "Type the 6-digit code the other device shows (`<code>`, or `<code> <name>` to \
                 choose its label); this computer checks it against its own; anything else refuses (60 s):";
    match seen.and_then(|s| s.looks_like.as_deref()) {
        // The alarm: this computer's own code stays hidden; it is typed from
        // the other device's screen and compared here (W-B3).
        Some(like) => format!(
            "\nPAIRING REQUEST: {who}\n  LOOKS LIKE YOUR SAVED DEVICE \"{like}\", BUT IT IS A DIFFERENT \
             DEVICE\n{short}{typed}"
        ),
        // It could not be compared with every saved device (F-4): the same
        // typed code, never the click accept.
        None if seen.is_some_and(|s| s.unchecked) => format!(
            "\nPAIRING REQUEST: {who}\n  COULD NOT COMPARE IT WITH YOUR SAVED DEVICES: A FILE OF SAVED \
             ENTRIES COULD NOT BE READ\n{short}{typed}"
        ),
        None => format!(
            "\nPAIRING REQUEST: {who}\n{short}  code: {sas}   <- must match the code on that device\n\
             Pair? Type `yes`, or `yes <name>` to choose its label; anything else refuses (60 s):"
        ),
    }
}

/// The answer to a pairing question whose look-alike alarm fired: the six
/// digits the other device shows (spaces allowed), then optionally a label.
/// They pair only when they are this computer's own code; `yes` and
/// anything else refuse.
fn parse_typed(answer: &str, sas: &str) -> PairDecision {
    let mut code = String::new();
    let mut words = answer.split_whitespace().peekable();
    while let Some(word) = words.peek() {
        if code.len() >= 6 || !word.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        code.push_str(word);
        words.next();
    }
    let label = words.collect::<Vec<_>>().join(" ");
    let own: String = sas.chars().filter(char::is_ascii_digit).collect();
    if code.len() == 6 && code == own {
        PairDecision::Accept {
            label: (!label.is_empty()).then_some(label),
        }
    } else {
        PairDecision::Reject
    }
}

fn session_question(peer: &TrustedPeer, direct: TransportPolicy) -> String {
    let note = direct_note(&peer.label, direct)
        .map(|note| format!("{note}\n"))
        .unwrap_or_default();
    format!(
        "\nSESSION REQUEST from \"{}\" (fingerprint {})\n{note}\
         Allow once with control (`a`), allow once view-only (`v`), anything else refuses (60 s):",
        peer.label,
        peer.device.fingerprint()
    )
}

fn parse_pairing(answer: &str) -> PairDecision {
    let answer = answer.trim();
    let (word, rest) = answer
        .split_once(char::is_whitespace)
        .unwrap_or((answer, ""));
    if is_yes(word) {
        let label = rest.trim();
        PairDecision::Accept {
            label: (!label.is_empty()).then(|| label.to_owned()),
        }
    } else {
        PairDecision::Reject
    }
}

fn parse_session(answer: &str) -> SessionDecision {
    match answer.trim().to_ascii_lowercase().as_str() {
        // Not `y`/`yes`: that is the reflex answer to the pairing question, and
        // here it would hand over the keyboard and mouse (SLICE-B2 B2-7).
        "a" | "allow" => SessionDecision::AllowOnce,
        "v" | "view" | "view-only" => SessionDecision::AllowOnceViewOnly,
        _ => SessionDecision::Deny,
    }
}

fn is_yes(word: &str) -> bool {
    word.eq_ignore_ascii_case("yes") || word.eq_ignore_ascii_case("y")
}

/// The client's half of pairing on the terminal: show the code while the host
/// user compares, then ask this user whether it matched.
pub struct CliPairingUi {
    prompter: Option<Arc<Prompter>>,
}

impl CliPairingUi {
    /// Confirm through `prompter`; with `None`, never confirm.
    #[must_use]
    pub fn new(prompter: Option<Arc<Prompter>>) -> Self {
        Self { prompter }
    }
}

impl ClientPairingUi for CliPairingUi {
    fn show_sas<'a>(&'a self, _: &'a TornectId, sas: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            eprintln!(
                "\nPAIRING: the host now shows a code. It must be exactly {sas}.\n\
                 Waiting for the host's user to accept (up to 90 s)..."
            );
        })
    }

    fn confirm<'a>(
        &'a self,
        _: &'a TornectId,
        host_name: &'a str,
        sas: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some(prompter) = &self.prompter else {
                eprintln!(
                    "stdin is not a terminal: nobody can confirm the code, so pairing is refused"
                );
                return false;
            };
            // `host_name` comes from `PAIR_ACCEPT` through `normalize_label`.
            let question = format!(
                "The host accepted; it calls itself \"{host_name}\".\n\
                 Did it show {sas}? Type `yes` only if the codes matched ({} s):",
                CONFIRM_TIMEOUT.as_secs()
            );
            match tokio::time::timeout(CONFIRM_TIMEOUT, prompter.ask(&question)).await {
                Ok(Some(answer)) => is_yes(answer.trim()),
                Ok(None) => false,
                Err(_) => {
                    eprintln!("no answer in time; pairing refused");
                    false
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_answers() {
        assert_eq!(parse_pairing("yes"), PairDecision::Accept { label: None });
        assert_eq!(parse_pairing(" Y "), PairDecision::Accept { label: None });
        assert_eq!(
            parse_pairing("yes  Office PC "),
            PairDecision::Accept {
                label: Some("Office PC".to_owned())
            }
        );
        for no in ["", "no", "n", "yess", "ok", "sure yes"] {
            assert_eq!(parse_pairing(no), PairDecision::Reject, "{no:?}");
        }
    }

    #[test]
    fn session_answers() {
        assert_eq!(parse_session("a"), SessionDecision::AllowOnce);
        assert_eq!(parse_session("Allow"), SessionDecision::AllowOnce);
        assert_eq!(parse_session("v"), SessionDecision::AllowOnceViewOnly);
        assert_eq!(parse_session(" VIEW "), SessionDecision::AllowOnceViewOnly);
        for no in ["", "d", "deny", "no", "always"] {
            assert_eq!(parse_session(no), SessionDecision::Deny, "{no:?}");
        }
    }

    /// The session question offers `a` and `v`. `y`/`yes` is the reflex answer to
    /// a different question — the pairing one, two prompts earlier — and it must
    /// never hand over the keyboard and mouse (SLICE-B2 B2-7).
    #[test]
    fn a_reflex_yes_does_not_grant_control() {
        for yes in ["y", "yes", "Y", "YES", " yes "] {
            assert_eq!(parse_session(yes), SessionDecision::Deny, "{yes:?}");
        }
    }

    /// A line typed before the question was shown is not its answer.
    #[tokio::test(start_paused = true)]
    async fn stale_lines_never_answer_a_new_question() {
        let (prompter, tx) = Prompter::scripted();
        tx.send("yes".to_owned()).await.unwrap();
        let asking = {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move { prompter.ask("q?").await })
        };
        // Let the question drain the stale line and start waiting, armed.
        tokio::task::yield_now().await;
        tokio::time::sleep(ARM_AFTER + Duration::from_millis(20)).await;
        tx.send("no".to_owned()).await.unwrap();
        assert_eq!(asking.await.unwrap().as_deref(), Some("no"));
    }

    /// Questions are asked one at a time, each answered by its own line.
    #[tokio::test(start_paused = true)]
    async fn questions_queue_and_closed_input_answers_none() {
        let (prompter, tx) = Prompter::scripted();
        let first = prompter.ask("first?");
        tokio::pin!(first);
        // The first question takes the lock; the line sent now answers it.
        tokio::select! {
            biased;
            _ = &mut first => panic!("answered before a line arrived"),
            () = tokio::time::sleep(ARM_AFTER + Duration::from_millis(10)) => {}
        }
        tx.send("one".to_owned()).await.unwrap();
        assert_eq!(first.await.as_deref(), Some("one"));
        drop(tx);
        assert_eq!(prompter.ask("second?").await, None);
    }

    /// B22: device A's session question runs out of time while the person
    /// is typing `a` for it, and B's question, queued behind, shows at once.
    /// The line that comes with the Enter, 10 ms after B's question, is not
    /// B's answer: it is ignored, with a word, and B waits for its own. A's
    /// question says it closed before B's shows. Failed before the fix: B
    /// took the `a`, an attended Control session nobody meant to allow.
    #[tokio::test(start_paused = true)]
    async fn a_line_typed_for_a_question_that_closed_never_answers_the_next() {
        let (prompter, tx) = Prompter::scripted();
        let first = {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(60),
                    prompter.ask_about("SESSION REQUEST: \"A\"", &closed_line("A")),
                )
                .await
            })
        };
        tokio::task::yield_now().await;
        let second = {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move {
                prompter
                    .ask_about("SESSION REQUEST: \"B\"", &closed_line("B"))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(first.await.unwrap().is_err(), "A's time ran out");
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send("a".to_owned()).await.unwrap();
        tokio::time::sleep(ARM_AFTER).await;
        assert!(!second.is_finished(), "the early line did not answer B");
        tx.send("v".to_owned()).await.unwrap();
        assert_eq!(second.await.unwrap().as_deref(), Some("v"));
        assert_eq!(
            prompter.shown(),
            [
                "SESSION REQUEST: \"A\"".to_owned(),
                closed_line("A"),
                "SESSION REQUEST: \"B\"".to_owned(),
                TOO_SOON.to_owned(),
            ]
        );
    }

    /// B22: an answer, or a refusal, says nothing more; only a question
    /// dropped unanswered says it closed.
    #[tokio::test(start_paused = true)]
    async fn only_a_question_dropped_unanswered_says_it_closed() {
        let (prompter, tx) = Prompter::scripted();
        let asking = {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move { prompter.ask_about("q?", "closed").await })
        };
        tokio::time::sleep(ARM_AFTER).await;
        tx.send("no".to_owned()).await.unwrap();
        assert_eq!(asking.await.unwrap().as_deref(), Some("no"));
        drop(tx);
        assert_eq!(prompter.ask_about("again?", "closed").await, None);
        assert_eq!(prompter.shown(), ["q?", "again?"]);
    }

    /// §B.6.1 on the terminal: an unpinned key is named by its device words
    /// (no fingerprint beside them); when the alarm fired, the question names
    /// the saved device, hides this computer's code, and only the typed code
    /// pairs (`yes` refuses, W-B3).
    #[test]
    fn the_terminal_names_a_key_by_its_words_and_takes_the_typed_code() {
        use tornect_core::words::Words;

        let device = tornect_core::DeviceIdentity::from_seed(&[8; 32]).id();
        let peer = PairingPeer {
            device,
            name: "Office PC".to_owned(),
            fingerprint: device.fingerprint(),
            pinned_label: None,
        };
        let calm = Recognition {
            words: Words::from_cached("absurd citizen dinner harvest").unwrap(),
            identicon: None,
            looks_like: None,
            unchecked: false,
        };
        let asked = pairing_question(&peer, "123 456", Some(&calm));
        assert!(
            asked.contains(
                "device words: absurd · citizen · dinner · harvest · not yet trusted · compare \
                 the code"
            ),
            "{asked}"
        );
        assert!(asked.contains("code: 123 456") && !asked.contains("fingerprint"));
        let alarm = Recognition {
            looks_like: Some("Office PC".to_owned()),
            ..calm
        };
        let asked = pairing_question(&peer, "123 456", Some(&alarm));
        assert!(
            asked.contains("LOOKS LIKE YOUR SAVED DEVICE \"Office PC\""),
            "{asked}"
        );
        assert!(
            !asked.contains("123 456"),
            "this computer's code is hidden: {asked}"
        );
        assert_eq!(
            parse_typed("123 456", "123 456"),
            PairDecision::Accept { label: None }
        );
        assert_eq!(
            parse_typed(" 123456  Desk 2 ", "123 456"),
            PairDecision::Accept {
                label: Some("Desk 2".to_owned())
            }
        );
        for no in [
            "yes",
            "y",
            "",
            "654 321",
            "12345",
            "1234567",
            "123 4567",
            "yes 123456",
        ] {
            assert_eq!(parse_typed(no, "123 456"), PairDecision::Reject, "{no:?}");
        }
    }

    /// The consent seam maps answers to decisions, and a closed terminal denies.
    #[tokio::test]
    async fn consent_denies_when_the_terminal_is_gone() {
        let (prompter, tx) = Prompter::scripted();
        let consent = CliConsent::new(prompter, TransportKnob::fixed(TransportPolicy::Any));
        let peer = TrustedPeer {
            device: tornect_core::DeviceIdentity::from_seed(&[7; 32]).id(),
            label: "Laptop".to_owned(),
        };
        let summary = SessionRequestSummary {
            caps: tornect_signal::messages::Caps::default(),
        };
        drop(tx);
        assert_eq!(
            consent.session(&peer, &summary).await,
            SessionDecision::Deny
        );
    }

    /// B04 review: a requester that leaves now withdraws its question (the
    /// host FSM drops the consent future), at a moment the requester
    /// chooses. The terminal says that request closed before the question
    /// queued behind it shows, and a line typed for the withdrawn question
    /// does not answer the next one.
    #[tokio::test(start_paused = true)]
    async fn a_question_withdrawn_by_its_requester_never_takes_the_next_answer() {
        let (prompter, tx) = Prompter::scripted();
        let consent = Arc::new(CliConsent::new(
            Arc::clone(&prompter),
            TransportKnob::fixed(TransportPolicy::Any),
        ));
        let ask = |label: &str, seed: u8| {
            let consent = Arc::clone(&consent);
            let peer = TrustedPeer {
                device: tornect_core::DeviceIdentity::from_seed(&[seed; 32]).id(),
                label: label.to_owned(),
            };
            tokio::spawn(async move {
                let summary = SessionRequestSummary {
                    caps: tornect_signal::messages::Caps::default(),
                };
                consent.session(&peer, &summary).await
            })
        };
        let first = ask("A", 7);
        tokio::task::yield_now().await;
        let second = ask("B", 8);
        tokio::task::yield_now().await;
        // A's requester leaves: the FSM drops A's question.
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send("a".to_owned()).await.unwrap();
        tokio::time::sleep(ARM_AFTER).await;
        assert!(!second.is_finished(), "the early line did not answer B");
        tx.send("v".to_owned()).await.unwrap();
        assert_eq!(second.await.unwrap(), SessionDecision::AllowOnceViewOnly);
        let shown = prompter.shown();
        assert_eq!(shown.len(), 4, "{shown:?}");
        assert!(shown[0].contains("\"A\""), "{shown:?}");
        assert_eq!(shown[1], closed_line("A"));
        assert!(shown[2].contains("\"B\""), "{shown:?}");
        assert_eq!(shown[3], TOO_SOON);
    }

    /// The terminal asks only when both stdin and stderr are a terminal:
    /// with stderr redirected to a file or a log, nothing is asked there.
    #[test]
    fn the_terminal_asks_only_on_a_terminal() {
        assert!(asks_here(true, true));
        assert!(!asks_here(true, false), "stderr redirected");
        assert!(!asks_here(false, true), "stdin redirected");
        assert!(!asks_here(false, false));
    }

    /// The terminal's session question on a host of a given row (§B.2.1):
    /// only the row's answers and their lines, the row's sentence, and an
    /// answer the row does not offer refuses; the administrator answer is
    /// the whole word.
    #[test]
    fn the_terminal_offers_only_the_rows_answers() {
        use tornect_core::levels::{
            LINE_ALLOW_WINDOWS, SENTENCE_ALWAYS_ADMINISTRATOR, SENTENCE_LINUX, WindowsFacts,
        };
        let peer = TrustedPeer {
            device: tornect_core::DeviceIdentity::from_seed(&[7; 32]).id(),
            label: "Laptop".to_owned(),
        };
        let linux = Availability::LINUX;
        let asked = session_question_at(&peer, &linux, TransportPolicy::TorOnly);
        assert!(
            asked.contains("\"Laptop\" wants to connect to this computer"),
            "{asked}"
        );
        assert!(asked.contains(SENTENCE_LINUX) && asked.contains(LINE_VIEW_ONLY));
        assert_eq!(asked.matches(SENTENCE_LINUX).count(), 1, "{asked}");
        assert!(!asked.contains("administrator (type"), "{asked}");
        assert!(!asked.contains("fingerprint"), "{asked}");
        assert_eq!(
            parse_session_at("a", linux.offered()),
            SessionDecision::AllowOnce
        );
        assert_eq!(
            parse_session_at("v", linux.offered()),
            SessionDecision::AllowOnceViewOnly
        );
        assert_eq!(
            parse_session_at("administrator", linux.offered()),
            SessionDecision::Deny
        );
        assert_eq!(
            parse_session_at("yes", linux.offered()),
            SessionDecision::Deny
        );
        // UAC off: no plain Allow; the administrator answer, typed whole.
        let always = Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            enable_lua: Some(0),
            ..WindowsFacts::default()
        }));
        let asked = session_question_at(&peer, &always, TransportPolicy::TorOnly);
        assert!(!asked.contains("`a`"), "{asked}");
        assert!(asked.contains(SENTENCE_ALWAYS_ADMINISTRATOR), "{asked}");
        assert_eq!(
            parse_session_at("a", always.offered()),
            SessionDecision::Deny
        );
        assert_eq!(
            parse_session_at("admin", always.offered()),
            SessionDecision::Deny
        );
        assert_eq!(
            parse_session_at("Administrator", always.offered()),
            SessionDecision::AllowOnceAdmin
        );
        // Installed with UAC on: Windows' Allow line; no administrator
        // answer in this build, and the sentence says why.
        let installed = Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            ..WindowsFacts::default()
        }));
        let asked = session_question_at(&peer, &installed, TransportPolicy::TorOnly);
        assert!(asked.contains(LINE_ALLOW_WINDOWS), "{asked}");
        if !tornect_core::levels::ADMIN_HELPER {
            assert!(
                asked.contains(tornect_core::levels::SENTENCE_NO_HELPER),
                "{asked}"
            );
        }
    }

    /// Design `direct` §3.6 [SEC]: while an accept may let the session
    /// connect directly, the terminal's session question says what the
    /// asking device then learns (the internet address where direct
    /// connections reach the internet, the local address under `lan_only`
    /// or where they stay on the local network) and how to relay every
    /// session through Tor; under `lan_only` it names no switch;
    /// with every session relayed it says nothing of it. The question reads
    /// the knob when it is asked, so a changed policy reaches the next
    /// question.
    #[tokio::test(start_paused = true)]
    async fn the_session_question_says_what_an_accept_discloses_on_a_direct_path() {
        let peer = TrustedPeer {
            device: tornect_core::DeviceIdentity::from_seed(&[7; 32]).id(),
            label: "Laptop".to_owned(),
        };
        // A build whose direct connections stay on the local network
        // (Phase A), and one whose reach the internet (Phase B).
        const ANY_LAN: &str = "  note: accepting also lets \"Laptop\" learn this computer's \
                               local address (network.paranoid = true relays through Tor)";
        const ANY_INTERNET: &str = "  note: accepting also lets \"Laptop\" learn this \
                                    computer's internet address (network.paranoid = true \
                                    relays through Tor)";
        const LAN: &str = "  note: accepting also lets \"Laptop\" learn this computer's local \
                           address";
        for internet in [false, true] {
            let any = if internet { ANY_INTERNET } else { ANY_LAN };
            for (policy, note) in [
                (TransportPolicy::Any, Some(any)),
                (TransportPolicy::LanOnly, Some(LAN)),
                (TransportPolicy::TorOnly, None),
            ] {
                assert_eq!(
                    direct_note_in("Laptop", policy, internet).as_deref(),
                    note,
                    "{policy:?} {internet}"
                );
            }
        }
        const ANY: &str = if INTERNET_DIRECT {
            ANY_INTERNET
        } else {
            ANY_LAN
        };
        let linux = Availability::LINUX;
        for (policy, note) in [
            (TransportPolicy::Any, Some(ANY)),
            (TransportPolicy::LanOnly, Some(LAN)),
            (TransportPolicy::TorOnly, None),
        ] {
            for asked in [
                session_question_at(&peer, &linux, policy),
                session_question(&peer, policy),
            ] {
                let lines: Vec<&str> = asked.lines().collect();
                let noted: Vec<&&str> = lines.iter().filter(|l| l.contains("note:")).collect();
                match note {
                    Some(note) => assert_eq!(noted, vec![&note], "{policy:?}: {asked}"),
                    None => assert!(noted.is_empty(), "{policy:?}: {asked}"),
                }
                assert!(
                    lines.last().is_some_and(|l| l.contains("refuses (60 s):")),
                    "{asked}"
                );
            }
        }
        // Through the consent seam: the knob as it is at the question.
        let knob = TransportKnob::fixed(TransportPolicy::TorOnly);
        let (prompter, tx) = Prompter::scripted();
        let consent = CliConsent::new(Arc::clone(&prompter), knob.clone());
        let summary = SessionRequestSummary {
            caps: tornect_signal::messages::Caps::default(),
        };
        let answer = async {
            tokio::time::sleep(ARM_AFTER + Duration::from_millis(20)).await;
            tx.send("v".to_owned()).await.unwrap();
        };
        let (decided, ()) = tokio::join!(consent.session_at(&peer, &summary, &linux), answer);
        assert_eq!(decided, SessionDecision::AllowOnceViewOnly);
        // Direct connections on (config.toml's default) before the next one.
        knob.set_from(&tornect_core::config::Network::default());
        let answer = async {
            tokio::time::sleep(ARM_AFTER + Duration::from_millis(20)).await;
            tx.send("v".to_owned()).await.unwrap();
        };
        let (decided, ()) = tokio::join!(consent.session_at(&peer, &summary, &linux), answer);
        assert_eq!(decided, SessionDecision::AllowOnceViewOnly);
        let shown = prompter.shown();
        let questions: Vec<&String> = shown
            .iter()
            .filter(|s| s.contains("SESSION REQUEST"))
            .collect();
        assert_eq!(questions.len(), 2, "{shown:?}");
        assert!(!questions[0].contains("note:"), "{}", questions[0]);
        assert!(questions[1].contains(ANY), "{}", questions[1]);
    }
}
