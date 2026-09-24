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

use tokio::sync::{Mutex, mpsc};
use tornect_core::TornectId;
use tornect_signal::fsm::client::ClientPairingUi;
use tornect_signal::pairing::{
    BoxFuture, Consent, PairDecision, PairingPeer, SessionDecision, SessionRequestSummary,
    TrustedPeer,
};

/// How long the client waits for its user to confirm a code. The host gives the
/// client 60 s after `PAIR_ACCEPT` to send its `SESSION_REQUEST`, and the answer
/// still has to cross Tor.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(50);

/// Lines typed on stdin, answered one question at a time.
///
/// One thread reads stdin for the life of the process, because a blocking read
/// cannot be cancelled: a question that times out must not leave a read behind
/// that swallows the answer to the next one. The thread starts at the first
/// question, not before, so a host that only ever answers pings never touches
/// the terminal (a background job that reads it would be stopped by the shell).
/// Lines typed before a question is shown are discarded, so a stale answer
/// never counts for a new question.
pub struct Prompter {
    lines: Mutex<Option<mpsc::Receiver<String>>>,
    source: Source,
}

enum Source {
    Stdin,
    #[cfg(test)]
    Scripted,
}

impl Prompter {
    /// Stdin, or `None` when stdin is not a terminal.
    #[must_use]
    pub fn stdin() -> Option<Arc<Self>> {
        std::io::stdin().is_terminal().then(|| {
            Arc::new(Self {
                lines: Mutex::new(None),
                source: Source::Stdin,
            })
        })
    }

    /// Show `question` and wait for the next line typed after it; `None` once
    /// stdin is closed. Questions queue behind one another.
    pub async fn ask(&self, question: &str) -> Option<String> {
        let mut lines = self.lines.lock().await;
        if lines.is_none() {
            *lines = self.start();
        }
        let rx = lines.as_mut()?;
        while rx.try_recv().is_ok() {}
        eprintln!("{question}");
        rx.recv().await
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
        });
        (prompter, tx)
    }
}

/// The host's consent popups, asked on the terminal.
pub struct CliConsent {
    prompter: Arc<Prompter>,
}

impl CliConsent {
    /// Ask through `prompter`.
    #[must_use]
    pub fn new(prompter: Arc<Prompter>) -> Self {
        Self { prompter }
    }
}

impl Consent for CliConsent {
    fn pairing<'a>(&'a self, peer: &'a PairingPeer, sas: &'a str) -> BoxFuture<'a, PairDecision> {
        Box::pin(async move {
            match self.prompter.ask(&pairing_question(peer, sas)).await {
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
            match self.prompter.ask(&session_question(peer)).await {
                Some(answer) => parse_session(&answer),
                None => SessionDecision::Deny,
            }
        })
    }
}

// Every string printed here is either computed locally (the code, the
// fingerprint) or already sanitized (`normalize_label` drops control and
// invisible characters from the declared name and the pinned label), so a peer
// cannot write escape sequences to this terminal.
fn pairing_question(peer: &PairingPeer, sas: &str) -> String {
    let who = match &peer.pinned_label {
        Some(label) => format!(
            "a device ALREADY PAIRED as \"{label}\" asks to pair again (refusing does not unpair it)"
        ),
        None => format!("a device calling itself \"{}\" asks to pair", peer.name),
    };
    format!(
        "\nPAIRING REQUEST: {who}\n  device fingerprint: {}\n  code: {sas}   <- must match the code on that device\n\
         Pair? Type `yes`, or `yes <name>` to choose its label; anything else refuses (60 s):",
        peer.fingerprint
    )
}

fn session_question(peer: &TrustedPeer) -> String {
    format!(
        "\nSESSION REQUEST from \"{}\" (fingerprint {})\n\
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
    #[tokio::test]
    async fn stale_lines_never_answer_a_new_question() {
        let (prompter, tx) = Prompter::scripted();
        tx.send("yes".to_owned()).await.unwrap();
        let asking = {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move { prompter.ask("q?").await })
        };
        // Let the question drain the stale line and start waiting.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send("no".to_owned()).await.unwrap();
        assert_eq!(asking.await.unwrap().as_deref(), Some("no"));
    }

    /// Questions are asked one at a time, each answered by its own line.
    #[tokio::test]
    async fn questions_queue_and_closed_input_answers_none() {
        let (prompter, tx) = Prompter::scripted();
        let first = prompter.ask("first?");
        tokio::pin!(first);
        // The first question takes the lock; the line sent now answers it.
        tokio::select! {
            biased;
            _ = &mut first => panic!("answered before a line arrived"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        tx.send("one".to_owned()).await.unwrap();
        assert_eq!(first.await.as_deref(), Some("one"));
        drop(tx);
        assert_eq!(prompter.ask("second?").await, None);
    }

    /// The consent seam maps answers to decisions, and a closed terminal denies.
    #[tokio::test]
    async fn consent_denies_when_the_terminal_is_gone() {
        let (prompter, tx) = Prompter::scripted();
        let consent = CliConsent::new(prompter);
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
}
