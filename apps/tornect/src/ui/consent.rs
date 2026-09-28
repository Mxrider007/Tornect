//! The window's side of the two consent seams, replacing the terminal's
//! (`crate::prompt`) when the GUI runs: [`GuiConsent`] is the host's
//! pairing and session popups (`docs/UI_PLAN.md` §6.1, §6.2) and
//! [`GuiPairingUi`] the client's code comparison.
//!
//! A popup is on screen exactly as long as its question is open. It is taken
//! down when it is answered, when the handshake stops waiting for it (the
//! FSM's popup timeout drops the future, and an unanswered popup ends as the
//! FSM's `POPUP_TIMEOUT` refusal), and when it is **withdrawn**: a kill (Stop,
//! `tornect panic`) or another session going live while it is open answers
//! it as a refusal at once. Before, the popup stayed up until answered and
//! only its accept was refused (the SLICE-B1 B1-3 / B2-5 residual).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use tornect_core::TornectId;
use tornect_signal::fsm::client::ClientPairingUi;
use tornect_signal::fsm::host::KillSwitch;
use tornect_signal::fsm::timeouts;
use tornect_signal::pairing::{
    BoxFuture, Consent, PairDecision, PairingPeer, SessionDecision, SessionRequestSummary,
    TrustedPeer,
};

use super::model::{ClientStage, Confirm, Popup, PopupKind, Recognition, Shared, Wake};
use super::recognize::{GoneOnDrop, Recognizer};

/// How long the client's user has to say whether the codes matched for the
/// session to follow: the host gives the client 60 s after `PAIR_ACCEPT` to
/// ask for its session, and the answer still has to cross Tor (as
/// `crate::prompt` does).
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(50);

/// How long the code question stays up at most. It outlives the host's wait
/// ([`CONFIRM_TIMEOUT`]) so that it cannot run out unseen: the window never
/// takes the focus (SLICE-E E1-1), so its card can sit behind another window.
/// The host paired this device when its user accepted, so a late "the codes
/// match" still pairs this computer, and only the session has to be asked for
/// again.
pub const CONFIRM_LIMIT: Duration = Duration::from_secs(600);

/// How the client's code question ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeCheck {
    /// The codes match, answered while the host still waited.
    Matched,
    /// The codes match, answered after the host's wait: this computer pinned
    /// the host, but its session request is likely too late.
    MatchedLate,
    /// The codes differ.
    Differ,
    /// Nobody answered before the question closed.
    Unanswered,
}

/// Where an answer goes.
enum Answer {
    Pair {
        tx: oneshot::Sender<PairDecision>,
        /// The code this computer shows (and, when the alarm fired, hides).
        sas: String,
        /// The look-alike alarm fired: only the typed code pairs (W-B3).
        typed_only: bool,
    },
    Session(oneshot::Sender<SessionDecision>),
    Confirm(oneshot::Sender<bool>),
}

/// The open questions and their answer channels.
pub struct Popups {
    shared: Arc<Shared>,
    next: AtomicU64,
    answers: Mutex<HashMap<u64, Answer>>,
}

impl std::fmt::Debug for Popups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Popups").finish_non_exhaustive()
    }
}

impl Popups {
    /// No question open yet.
    #[must_use]
    pub fn new(shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Self {
            shared,
            next: AtomicU64::new(1),
            answers: Mutex::new(HashMap::new()),
        })
    }

    /// The model the questions are shown in.
    #[must_use]
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    fn take(&self, id: u64) -> Option<Answer> {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
    }

    /// The host user's answer to pairing popup `id`; `false` when it is no
    /// longer open.
    ///
    /// On a sheet whose look-alike alarm fired, an accept is a refusal: only
    /// the code typed from the other device pairs there
    /// ([`Popups::answer_pairing_code`]; §B.6.1 W-B3).
    pub fn answer_pairing(&self, id: u64, decision: PairDecision) -> bool {
        match self.take(id) {
            Some(Answer::Pair { tx, typed_only, .. }) => {
                let decision = match decision {
                    PairDecision::Accept { .. } if typed_only => PairDecision::Reject,
                    other => other,
                };
                tx.send(decision).is_ok()
            }
            _ => false,
        }
    }

    /// The code the host user typed on pairing sheet `id`, from the other
    /// device's screen: this computer compares it with its own code. The
    /// same six digits pair (as `label`, if one was typed); anything else
    /// refuses, a refusal like any other (it counts toward the temp-ban).
    pub fn answer_pairing_code(&self, id: u64, code: &str, label: Option<String>) -> bool {
        match self.take(id) {
            Some(Answer::Pair { tx, sas, .. }) => {
                let decision = if same_code(code, &sas) {
                    PairDecision::Accept { label }
                } else {
                    PairDecision::Reject
                };
                tx.send(decision).is_ok()
            }
            _ => false,
        }
    }

    /// The host user's answer to session popup `id`.
    pub fn answer_session(&self, id: u64, decision: SessionDecision) -> bool {
        match self.take(id) {
            Some(Answer::Session(tx)) => tx.send(decision).is_ok(),
            _ => false,
        }
    }

    /// The client user's answer to code question `id`.
    pub fn answer_confirm(&self, id: u64, matched: bool) -> bool {
        match self.take(id) {
            Some(Answer::Confirm(tx)) => tx.send(matched).is_ok(),
            _ => false,
        }
    }

    fn open(
        &self,
        answer: Answer,
        show: impl FnOnce(u64, &mut super::model::Model),
    ) -> OnScreen<'_> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, answer);
        self.shared.update(|m| show(id, m));
        self.shared.wake(Wake::Attention);
        OnScreen { popups: self, id }
    }
}

/// A question on screen; dropping it takes the question down, however it
/// ended: answered, withdrawn, timed out, or its task cancelled.
struct OnScreen<'a> {
    popups: &'a Popups,
    id: u64,
}

impl Drop for OnScreen<'_> {
    fn drop(&mut self) {
        let id = self.id;
        drop(self.popups.take(id));
        self.popups.shared.update(|m| {
            m.popups.retain(|p| p.id != id);
            m.recognition.remove(&id);
            if m.confirm.as_ref().is_some_and(|c| c.id == id) {
                m.confirm = None;
            }
        });
    }
}

/// What takes an open host popup down before it is answered.
#[derive(Clone)]
pub struct Withdraw {
    /// Any kill: the Stop button, `tornect panic`, shutting down.
    pub kill: KillSwitch,
    /// Bumped each time a session goes live on this host.
    pub started: watch::Receiver<u64>,
    /// Whether a session is live or reserved right now (`SessionActivity`).
    pub live: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl Withdraw {
    /// Resolves once the popup opened now must go: a kill after this call, or
    /// a session going live after it. Returns at once when a session is
    /// already live (the FSM refuses popups then, but one can go live between
    /// its check and the popup).
    fn armed(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut guard = self.kill.arm();
        let mut started = self.started.clone();
        started.borrow_and_update();
        let live_now = (self.live)();
        async move {
            if live_now {
                return;
            }
            tokio::select! {
                _ = guard.killed() => {}
                changed = started.changed() => {
                    if changed.is_err() {
                        // No sink left to say so: only a kill takes it down.
                        guard.killed().await;
                    }
                }
            }
        }
    }
}

/// Whether `typed` is the six digits of `sas` (spaces ignored).
fn same_code(typed: &str, sas: &str) -> bool {
    let digits =
        |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect::<String>() };
    let (typed, sas) = (digits(typed), digits(sas));
    typed.len() == 6 && typed.bytes().all(|b| b.is_ascii_digit()) && typed == sas
}

/// The host's popups in the window.
pub struct GuiConsent {
    popups: Arc<Popups>,
    withdraw: Withdraw,
    /// The device words and the look-alike alarm (§B.6.1); without them the
    /// sheets show neither.
    words: Option<Arc<Recognizer>>,
}

impl GuiConsent {
    /// Popups shown through `popups`, withdrawn on `withdraw`.
    #[must_use]
    pub fn new(popups: Arc<Popups>, withdraw: Withdraw) -> Self {
        Self {
            popups,
            withdraw,
            words: None,
        }
    }

    /// The sheets show device words and run the look-alike alarm: a pairing
    /// sheet's key is derived (paced) before the sheet is shown, off the
    /// network task, after the pairing rate limiter admitted the request.
    #[must_use]
    pub fn with_words(mut self, words: Arc<Recognizer>) -> Self {
        self.words = Some(words);
        self
    }
}

impl Consent for GuiConsent {
    fn pairing<'a>(&'a self, peer: &'a PairingPeer, sas: &'a str) -> BoxFuture<'a, PairDecision> {
        let withdrawn = self.withdraw.armed();
        Box::pin(async move {
            let deadline = Instant::now() + timeouts::POPUP;
            let mut withdrawn = std::pin::pin!(withdrawn);
            // The device words and the alarm, before the sheet is shown: the
            // FSM's limiter admitted this request; the derivation runs off
            // the network task, paced for a key nobody saved (W-B5).
            // Set when this answer is dropped — withdrawn, timed out by the
            // FSM, or the stream gone — so a derivation still queued on the
            // pacer never runs for a sheet nobody will see (F-3).
            let gone = GoneOnDrop::default();
            let seen = match &self.words {
                None => None,
                Some(words) => {
                    let words = Arc::clone(words);
                    let (device, name) = (peer.device, peer.name.clone());
                    let pinned = peer.pinned_label.is_some();
                    let flag = gone.flag();
                    let derived = tokio::task::spawn_blocking(move || {
                        words.pairing_sheet_unless(&flag, &device, &name, pinned)
                    });
                    tokio::select! {
                        biased;
                        () = &mut withdrawn => return PairDecision::Reject,
                        derived = derived => match derived {
                            Ok(Some(seen)) => Some(seen),
                            // No words, no alarm verdict: refuse.
                            Ok(None) | Err(_) => return PairDecision::Reject,
                        },
                    }
                }
            };
            let typed_only = seen.as_ref().is_some_and(Recognition::typed_only);
            let (tx, rx) = oneshot::channel();
            let kind = PopupKind::Pairing {
                name: peer.name.clone(),
                fingerprint: peer.fingerprint.clone(),
                sas: sas.to_owned(),
                pinned: peer.pinned_label.clone(),
            };
            let answer = Answer::Pair {
                tx,
                sas: sas.to_owned(),
                typed_only,
            };
            let _on_screen = self.popups.open(answer, |id, m| {
                if let Some(seen) = seen {
                    m.recognition.insert(id, seen);
                }
                m.popups.push(Popup { id, kind, deadline });
            });
            // A withdrawal wins over an answer given at the same moment.
            tokio::select! {
                biased;
                () = withdrawn => PairDecision::Reject,
                answer = rx => answer.unwrap_or(PairDecision::Reject),
            }
        })
    }

    fn session<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision> {
        let withdrawn = self.withdraw.armed();
        Box::pin(async move {
            let deadline = Instant::now() + timeouts::POPUP;
            let mut withdrawn = std::pin::pin!(withdrawn);
            // A paired device's identicon, beside its pinned label: a saved
            // key, derived once.
            let seen = match &self.words {
                None => None,
                Some(words) => {
                    let (words, device) = (Arc::clone(words), peer.device);
                    let derived = tokio::task::spawn_blocking(move || words.session_sheet(&device));
                    tokio::select! {
                        biased;
                        () = &mut withdrawn => return SessionDecision::Deny,
                        derived = derived => derived.ok(),
                    }
                }
            };
            let (tx, rx) = oneshot::channel();
            let kind = PopupKind::Session {
                label: peer.label.clone(),
                fingerprint: peer.device.fingerprint(),
            };
            let _on_screen = self.popups.open(Answer::Session(tx), |id, m| {
                if let Some(seen) = seen {
                    m.recognition.insert(id, seen);
                }
                m.popups.push(Popup { id, kind, deadline });
            });
            tokio::select! {
                biased;
                () = withdrawn => SessionDecision::Deny,
                answer = rx => answer.unwrap_or(SessionDecision::Deny),
            }
        })
    }
}

/// The client's code comparison in the window.
pub struct GuiPairingUi {
    popups: Arc<Popups>,
    /// How long the host waits for the session request.
    host_waits: Duration,
    /// How long the question stays up.
    wait: Duration,
    /// How the last question ended.
    ended: Mutex<Option<CodeCheck>>,
}

impl GuiPairingUi {
    /// Ask through `popups`, for up to [`CONFIRM_LIMIT`]; the session follows
    /// only an answer within [`CONFIRM_TIMEOUT`].
    #[must_use]
    pub fn new(popups: Arc<Popups>) -> Self {
        Self {
            popups,
            host_waits: CONFIRM_TIMEOUT,
            wait: CONFIRM_LIMIT,
            ended: Mutex::new(None),
        }
    }

    /// How the last code question ended; `None` if none was asked.
    pub fn ended(&self) -> Option<CodeCheck> {
        *self.ended.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ClientPairingUi for GuiPairingUi {
    fn show_sas<'a>(&'a self, _: &'a TornectId, sas: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.popups.shared().update(|m| {
                m.client = ClientStage::Pairing {
                    sas: sas.to_owned(),
                };
            });
        })
    }

    fn confirm<'a>(
        &'a self,
        _: &'a TornectId,
        host_name: &'a str,
        sas: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            // `host_name` comes from `PAIR_ACCEPT` through `normalize_label`.
            let now = Instant::now();
            let confirm = Confirm {
                id: 0,
                host_name: host_name.to_owned(),
                sas: sas.to_owned(),
                host_waits_until: now + self.host_waits,
                deadline: now + self.wait,
            };
            let _on_screen = self.popups.open(Answer::Confirm(tx), |id, m| {
                m.confirm = Some(Confirm { id, ..confirm });
            });
            let asked = tokio::time::Instant::now();
            let ended = match tokio::time::timeout(self.wait, rx).await {
                Ok(Ok(true)) if asked.elapsed() < self.host_waits => CodeCheck::Matched,
                Ok(Ok(true)) => CodeCheck::MatchedLate,
                Ok(Ok(false)) => CodeCheck::Differ,
                Ok(Err(_)) | Err(_) => CodeCheck::Unanswered,
            };
            *self.ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(ended);
            let matched = matches!(ended, CodeCheck::Matched | CodeCheck::MatchedLate);
            if matched {
                // Next: the session request, which the host's user answers.
                self.popups
                    .shared()
                    .update(|m| m.client = ClientStage::Asking);
            }
            matched
        })
    }
}

#[cfg(test)]
mod tests {
    use tornect_core::{DeviceIdentity, HostIdentity};
    use tornect_signal::messages::{Caps, bye};

    use super::super::model::Model;
    use super::*;

    fn popups() -> Arc<Popups> {
        Popups::new(Shared::new(Model::default(), Arc::new(|_| {})))
    }

    fn withdraw(kill: &KillSwitch, started: watch::Receiver<u64>) -> Withdraw {
        Withdraw {
            kill: kill.clone(),
            started,
            live: Arc::new(|| false),
        }
    }

    fn peer() -> TrustedPeer {
        TrustedPeer {
            device: DeviceIdentity::from_seed(&[7; 32]).id(),
            label: "Laptop".to_owned(),
        }
    }

    fn summary() -> SessionRequestSummary {
        SessionRequestSummary {
            caps: Caps::default(),
        }
    }

    fn pairing_peer() -> PairingPeer {
        let device = DeviceIdentity::from_seed(&[8; 32]).id();
        PairingPeer {
            device,
            name: "Phone".to_owned(),
            fingerprint: device.fingerprint(),
            pinned_label: None,
        }
    }

    /// Wait until the model shows `n` host popups.
    async fn shown(popups: &Popups, n: usize) -> Vec<Popup> {
        for _ in 0..500 {
            let open = popups.shared().read(|m| m.popups.clone());
            if open.len() == n {
                return open;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("{n} popup(s) never shown");
    }

    /// The answer goes to the FSM, and the popup leaves the screen.
    #[tokio::test]
    async fn an_answer_reaches_the_handshake_and_takes_the_popup_down() {
        let popups = popups();
        let kill = KillSwitch::new();
        let (_started_tx, started) = watch::channel(0);
        let consent = GuiConsent::new(Arc::clone(&popups), withdraw(&kill, started));
        let (peer, summary) = (peer(), summary());
        let asking = consent.session(&peer, &summary);
        tokio::pin!(asking);
        tokio::select! {
            _ = &mut asking => panic!("answered before anyone clicked"),
            open = shown(&popups, 1) => {
                assert!(matches!(&open[0].kind, PopupKind::Session { label, .. } if label == "Laptop"));
                assert!(popups.answer_session(open[0].id, SessionDecision::AllowOnceViewOnly));
            }
        }
        assert_eq!(asking.await, SessionDecision::AllowOnceViewOnly);
        assert!(popups.shared().read(|m| m.popups.is_empty()));
    }

    /// The B1-3 residual: a kill while the popup is open withdraws it at once,
    /// as a refusal, instead of leaving it up until someone answers.
    #[tokio::test]
    async fn a_kill_withdraws_an_open_popup() {
        let popups = popups();
        let kill = KillSwitch::new();
        let (_started_tx, started) = watch::channel(0);
        let consent = GuiConsent::new(Arc::clone(&popups), withdraw(&kill, started));
        let (peer, summary) = (peer(), summary());
        let asking = consent.session(&peer, &summary);
        tokio::pin!(asking);
        tokio::select! {
            _ = &mut asking => panic!("answered before the kill"),
            _ = shown(&popups, 1) => kill.kill(bye::USER),
        }
        assert_eq!(asking.await, SessionDecision::Deny);
        assert!(popups.shared().read(|m| m.popups.is_empty()));
    }

    /// A kill fired before the popup opened (an earlier session's) does not
    /// withdraw it: only a kill during it does.
    #[tokio::test]
    async fn an_earlier_kill_does_not_withdraw_a_new_popup() {
        let popups = popups();
        let kill = KillSwitch::new();
        kill.kill(bye::PANIC);
        let (_started_tx, started) = watch::channel(0);
        let consent = GuiConsent::new(Arc::clone(&popups), withdraw(&kill, started));
        let peer = pairing_peer();
        let asking = consent.pairing(&peer, "123 456");
        tokio::pin!(asking);
        tokio::select! {
            _ = &mut asking => panic!("withdrawn by a kill that came before it"),
            open = shown(&popups, 1) => {
                assert!(matches!(&open[0].kind, PopupKind::Pairing { sas, .. } if sas == "123 456"));
                assert!(popups.answer_pairing(open[0].id, PairDecision::Accept { label: None }));
            }
        }
        assert_eq!(asking.await, PairDecision::Accept { label: None });
    }

    /// The B2-5 residual: another session going live while a popup is open
    /// withdraws it, pairing and session popups alike.
    #[tokio::test]
    async fn a_session_start_withdraws_open_popups() {
        let popups = popups();
        let kill = KillSwitch::new();
        let (started_tx, started) = watch::channel(0u64);
        let consent = GuiConsent::new(Arc::clone(&popups), withdraw(&kill, started));
        let (peer, summary, pairing) = (peer(), summary(), pairing_peer());
        let session = consent.session(&peer, &summary);
        let pair = consent.pairing(&pairing, "654 321");
        tokio::pin!(session, pair);
        tokio::select! {
            _ = &mut session => panic!("answered early"),
            _ = &mut pair => panic!("answered early"),
            _ = shown(&popups, 2) => started_tx.send_modify(|n| *n += 1),
        }
        assert_eq!(session.await, SessionDecision::Deny);
        assert_eq!(pair.await, PairDecision::Reject);
        assert!(popups.shared().read(|m| m.popups.is_empty()));
    }

    /// A popup asked while a session is already live is refused without
    /// staying on screen.
    #[tokio::test]
    async fn a_popup_while_a_session_is_live_is_refused_at_once() {
        let popups = popups();
        let kill = KillSwitch::new();
        let (_started_tx, started) = watch::channel(0);
        let consent = GuiConsent::new(
            Arc::clone(&popups),
            Withdraw {
                live: Arc::new(|| true),
                ..withdraw(&kill, started)
            },
        );
        let (peer, summary) = (peer(), summary());
        assert_eq!(
            consent.session(&peer, &summary).await,
            SessionDecision::Deny
        );
        assert!(popups.shared().read(|m| m.popups.is_empty()));
    }

    /// The consent timeout denies: through the real handshake, a session popup
    /// nobody answers is refused as `POPUP_TIMEOUT` when the FSM's 60 s run
    /// out, and it leaves the screen.
    #[tokio::test(start_paused = true)]
    async fn the_consent_timeout_denies_and_takes_the_popup_down() {
        use tornect_core::{Config, Paths};
        use tornect_signal::HostSigner;
        use tornect_signal::fsm::HandshakeError;
        use tornect_signal::fsm::client::{
            ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
        };
        use tornect_signal::messages::reject;
        use tornect_signal::pairing::KnownHostStore;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let media = Arc::new(tornect_session::MediaHost::new(
            Arc::new(tornect_session::SystemBackend::new(
                tornect_session::Source::TestCard,
            )),
            Arc::new(tornect_session::NoObserver),
            tornect_session::MediaLimits::default(),
        ));
        let mut wiring = crate::host::wire(
            &paths,
            &Config::default(),
            Arc::clone(&identity),
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
            Arc::new(tornect_signal::pairing::AutoDeny),
            media,
            crate::host::ControlChannel::default(),
        )
        .unwrap();
        let popups = popups();
        let (_started_tx, started) = watch::channel(0);
        let live = Arc::clone(&wiring.live);
        wiring.deps.consent = Arc::new(GuiConsent::new(
            Arc::clone(&popups),
            Withdraw {
                kill: wiring.deps.kill.clone(),
                started,
                live: Arc::new(move || {
                    tornect_signal::fsm::host::SessionActivity::session_live(&*live)
                }),
            },
        ));
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move {
            crate::host::serve_signaling(host_end, &cfg, &deps, |_| {}).await
        });

        // The window's user: accepts the pairing, then leaves the session
        // popup unanswered.
        let answering = {
            let popups = Arc::clone(&popups);
            tokio::spawn(async move {
                let open = shown(&popups, 1).await;
                assert!(matches!(open[0].kind, PopupKind::Pairing { .. }));
                popups.answer_pairing(open[0].id, PairDecision::Accept { label: None });
                loop {
                    let open = popups.shared().read(|m| m.popups.clone());
                    if let Some(p) = open.first()
                        && matches!(p.kind, PopupKind::Session { .. })
                    {
                        return p.deadline;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        };
        let known = Arc::new(
            KnownHostStore::open(paths.state_dir.join("client-known-hosts.toml")).unwrap(),
        );
        let mut cdeps = ClientDeps::headless(known);
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let asked = tokio::time::Instant::now();
        let outcome = connect(client_end, &ccfg, &device, &cdeps, Intent::Session).await;
        let deadline = answering.await.unwrap();
        match outcome {
            Err(HandshakeError::SessionRejected { reject }) => {
                assert_eq!(reject.reason, reject::POPUP_TIMEOUT);
            }
            Ok(ClientOutcome::Session(_)) => panic!("a session nobody allowed"),
            other => panic!("expected the popup timeout, got {other:?}"),
        }
        assert!(
            asked.elapsed() >= timeouts::POPUP,
            "refused before the timeout"
        );
        // The countdown the window showed ran to the FSM's timeout.
        assert!(deadline > Instant::now() + timeouts::POPUP - Duration::from_secs(5));
        assert!(
            popups.shared().read(|m| m.popups.is_empty()),
            "the unanswered popup left the screen"
        );
        let _ = host.await;
    }

    /// The client's question: the answer is returned, silence refuses after
    /// the wait, and either way the question leaves the screen.
    #[tokio::test(start_paused = true)]
    async fn the_code_question_refuses_when_unanswered() {
        let popups = popups();
        let ui = GuiPairingUi::new(Arc::clone(&popups));
        let host = HostIdentity::from_seed(&[1; 32]).id();
        ui.show_sas(&host, "111 222").await;
        assert!(popups.shared().read(|m| matches!(
            &m.client,
            ClientStage::Pairing { sas } if sas == "111 222"
        )));

        let asking = ui.confirm(&host, "Desk", "111 222");
        tokio::pin!(asking);
        let id = loop {
            tokio::select! {
                _ = &mut asking => panic!("answered early"),
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            if let Some(c) = popups.shared().read(|m| m.confirm.clone()) {
                break c.id;
            }
        };
        assert!(popups.answer_confirm(id, true));
        assert!(asking.await);
        assert_eq!(ui.ended(), Some(CodeCheck::Matched));
        assert!(popups.shared().read(|m| m.confirm.is_none()));

        let started = tokio::time::Instant::now();
        assert!(!ui.confirm(&host, "Desk", "111 222").await);
        assert!(started.elapsed() >= CONFIRM_LIMIT);
        assert_eq!(ui.ended(), Some(CodeCheck::Unanswered));
        assert!(popups.shared().read(|m| m.confirm.is_none()));
    }

    /// The live console check of 2026-09-24: the code question ran out unseen
    /// after 50 s, the host's wait for the session, although the host had
    /// paired the device when its user accepted. A "the codes match" given
    /// after the host's wait is taken now (it pins the host), and said to be
    /// late; the question itself closes only at its own limit.
    #[tokio::test(start_paused = true)]
    async fn the_code_question_takes_a_late_answer() {
        let popups = popups();
        let ui = GuiPairingUi::new(Arc::clone(&popups));
        let host = HostIdentity::from_seed(&[1; 32]).id();
        let asking = ui.confirm(&host, "Desk", "111 222");
        tokio::pin!(asking);
        let id = loop {
            tokio::select! {
                _ = &mut asking => panic!("answered early"),
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            if let Some(c) = popups.shared().read(|m| m.confirm.clone()) {
                break c.id;
            }
        };
        let late = tokio::time::sleep(CONFIRM_TIMEOUT + Duration::from_secs(5));
        tokio::select! {
            refused = &mut asking => panic!("the question closed at the host's wait: {refused}"),
            () = late => {}
        }
        assert!(popups.answer_confirm(id, true));
        assert!(asking.await, "a late yes was not taken");
        assert_eq!(ui.ended(), Some(CodeCheck::MatchedLate));
        assert!(popups.shared().read(|m| m.confirm.is_none()));
    }
}
