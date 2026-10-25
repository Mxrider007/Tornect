//! Folder listings over a services stream, both ends (the services design
//! §3.4, §3.5, §5.2).
//!
//! **Pulled pages.** A `List{req, folder, from}` gets exactly one answer: a
//! `Listing` page or `ListFailed{req, reason}`. The viewer asks for the next
//! page (`from` = the page's `next`) until a page names none, and has at most
//! one `List` outstanding, so at most one page is in flight. Pages are cut by
//! encoded size (at most `page_budget`) and at
//! `tornect_proto::services::MAX_ENTRIES` entries.
//!
//! **The host.** A `List` from 0 reads its folder on one blocking listing
//! worker ([`read_folder`]: at most `max_entries` entries, a cancel flag
//! checked between entries, sorted), within `list_timeout` (`IO` past it);
//! the sorted entries of that one folder are kept for its later pages, which
//! are served from them, and a `List` for another folder replaces them. A
//! worker still stuck after its timeout makes every `List` that needs a
//! worker `BUSY` until it returns. A second `List` while one is outstanding
//! is `BUSY`; so is a first page asked for above [`LIST_RATE`] a second,
//! and a page the viewer asked for before it read the one before (the
//! writer's listing queue holds one page). The folder named must be one of
//! the stream's handles (`NOT_FOUND`), and [`Access::check`] runs on it
//! when it is read (`DENIED`, `NOT_FOUND`).
//!
//! **The viewer** asks for each next page itself and gives each page to its
//! user as it comes ([`ListingView`] with `from`), at most `max_entries`
//! entries of one folder; a page for a folder the user left meanwhile is
//! dropped, and the folder asked for last is listed instead. A `Listing` or
//! a `ListFailed` that answers no outstanding `List`, or whose `next` does
//! not follow its entries, ends the stream with `Close{PROTOCOL}`.
//!
//! **A lock** (§2.3): the host stops the listing it is reading and skips
//! every `List` until it is unlocked; the viewer gives up the `List` it has
//! outstanding (its user hears `LOCKED`), and drops an answer that still
//! comes for it.
//!
//! Nothing here logs a name or a path.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tornect_proto::services::{
    List, ListFailed, Listing, MAX_PAGE_ENTRIES_BYTES, SvcMsg, kind, reason,
};

use super::ServicesLimits;
use super::browse::{Access, Folder, Handles, ListingView, page, read_folder};
use super::transfer::{Abandoned, Untrusted};
use super::writer::Outbox;
use crate::flow::TokenBucket;

/// First pages of a listing the host reads per second on average; more get
/// `ListFailed{BUSY}` (a page that continues a listing is not counted).
pub const LIST_RATE: u32 = 4;

/// First pages the host reads at once.
pub(crate) const LIST_BURST: u32 = 4;

/// A test's hold on the host's listing worker, called on the worker's
/// thread as it starts.
#[cfg(test)]
pub(crate) type ListHook = Arc<dyn Fn() + Send + Sync>;

/// A listing worker's answer.
pub(crate) struct ListDone {
    seq: u64,
    result: Result<Folder, u16>,
}

/// The `List` whose folder a worker is reading.
struct Reading {
    req: u32,
    folder: u32,
    from: u32,
    seq: u64,
    cancel: Arc<AtomicBool>,
}

/// Clears its flag when the worker's thread ends, however it ends.
struct Alive(Arc<AtomicBool>);

impl Drop for Alive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The host's listings on one services stream, and the stream's handles.
pub(crate) struct HostListings {
    access: Arc<Access>,
    handles: Handles,
    outbox: Outbox,
    max_entries: usize,
    timeout: Duration,
    budget: usize,
    rate: TokenBucket,
    /// The folder being paged: its handle and its sorted entries.
    cache: Option<(u32, Folder)>,
    reading: Option<Reading>,
    /// A worker's thread is running (one that timed out included).
    alive: Arc<AtomicBool>,
    seq: u64,
    done: mpsc::UnboundedSender<ListDone>,
    #[cfg(test)]
    hook: Option<ListHook>,
}

impl HostListings {
    /// The listings of a stream whose files are those `access` lets through,
    /// within `limits` (`max_entries`, `list_timeout`, `page_budget`,
    /// `max_handles`); the workers' answers come on the receiver returned.
    pub(crate) fn new(
        access: Arc<Access>,
        outbox: Outbox,
        limits: &ServicesLimits,
    ) -> (Self, mpsc::UnboundedReceiver<ListDone>) {
        let (done, answers) = mpsc::unbounded_channel();
        (
            Self {
                access,
                handles: Handles::new(limits.max_handles),
                outbox,
                max_entries: limits.max_entries,
                timeout: limits.list_timeout,
                budget: limits.page_budget.clamp(1, MAX_PAGE_ENTRIES_BYTES),
                rate: TokenBucket::new(LIST_RATE, LIST_BURST, Instant::now()),
                cache: None,
                reading: None,
                alive: Arc::new(AtomicBool::new(false)),
                seq: 0,
                done,
                #[cfg(test)]
                hook: None,
            },
            answers,
        )
    }

    /// The same listings, `hook` called by each worker as it starts.
    #[cfg(test)]
    pub(crate) fn with_hook(mut self, hook: Option<ListHook>) -> Self {
        self.hook = hook;
        self
    }

    /// The path of handle `handle` (never the places'), for a download.
    pub(crate) fn path_of(&self, handle: u32) -> Option<PathBuf> {
        self.handles.get(handle).map(std::path::Path::to_path_buf)
    }

    /// The viewer's `List`; `paused` while a lock pauses browsing. `Err` with
    /// the `Close` reason.
    pub(crate) fn list(&mut self, list: List, paused: bool) -> Result<(), u16> {
        let List { req, folder, from } = list;
        if paused {
            return self.failed(req, reason::LOCKED);
        }
        if self.reading.is_some() {
            return self.failed(req, reason::BUSY);
        }
        if from > 0
            && self
                .cache
                .as_ref()
                .is_some_and(|(cached, _)| *cached == folder)
        {
            return self.page(req, from);
        }
        // A stuck worker's `BUSY` costs no token.
        if self.alive.load(Ordering::SeqCst) || !self.rate.take(Instant::now()) {
            return self.failed(req, reason::BUSY);
        }
        let path = match folder {
            0 => None,
            handle => match self.path_of(handle) {
                Some(path) => Some(path),
                None => return self.failed(req, reason::NOT_FOUND),
            },
        };
        // One folder's entries are held at a time.
        self.cache = None;
        self.seq += 1;
        let seq = self.seq;
        let cancel = Arc::new(AtomicBool::new(false));
        self.alive.store(true, Ordering::SeqCst);
        let alive = Alive(Arc::clone(&self.alive));
        let (access, max, stop) = (
            Arc::clone(&self.access),
            self.max_entries,
            Arc::clone(&cancel),
        );
        #[cfg(test)]
        let hook = self.hook.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _alive = alive;
            #[cfg(test)]
            if let Some(hook) = hook {
                hook();
            }
            read_folder(&access, path.as_deref(), max, &stop)
        });
        let (timeout, done, stop) = (self.timeout, self.done.clone(), Arc::clone(&cancel));
        tokio::spawn(async move {
            let result = match tokio::time::timeout(timeout, worker).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(reason::IO),
                Err(_) => {
                    // Abandoned: it stops at its next entry, and `alive`
                    // holds the next listings off until it returns.
                    stop.store(true, Ordering::SeqCst);
                    Err(reason::IO)
                }
            };
            let _ = done.send(ListDone { seq, result });
        });
        self.reading = Some(Reading {
            req,
            folder,
            from,
            seq,
            cancel,
        });
        Ok(())
    }

    /// A worker's answer: the `List`'s first page, or why not.
    pub(crate) fn done(&mut self, done: ListDone) -> Result<(), u16> {
        let Some(reading) = self.reading.take_if(|reading| reading.seq == done.seq) else {
            return Ok(());
        };
        match done.result {
            Ok(folder) => {
                self.cache = Some((reading.folder, folder));
                self.page(reading.req, reading.from)
            }
            Err(code) => self.failed(reading.req, code),
        }
    }

    /// Answer `req` with the page of the folder held from entry `from`.
    fn page(&mut self, req: u32, from: u32) -> Result<(), u16> {
        let Some((handle, folder)) = &self.cache else {
            return self.failed(req, reason::NOT_FOUND);
        };
        let handles = &mut self.handles;
        let (entries, next) = page(folder, from as usize, self.budget, handles);
        let parent = folder.path.as_ref().map(|_| {
            folder
                .parent
                .as_deref()
                .map_or(0, |parent| handles.issue(parent))
        });
        let listing = Listing {
            req,
            folder: *handle,
            title: folder.title.clone(),
            parent,
            entries,
            next,
            truncated: folder.truncated,
        };
        if self.outbox.try_list(SvcMsg::Listing(listing)) {
            Ok(())
        } else {
            // The page before is still queued: the viewer asked for this one
            // before it read that one.
            self.failed(req, reason::BUSY)
        }
    }

    fn failed(&self, req: u32, code: u16) -> Result<(), u16> {
        if self
            .outbox
            .ctrl(SvcMsg::ListFailed(ListFailed { req, reason: code }))
        {
            Ok(())
        } else {
            // The viewer stopped reading (§3.4).
            Err(reason::PROTOCOL)
        }
    }

    /// Browsing went (turned off, or the viewer's input was lost), a lock
    /// paused it, or the stream ends: a running worker stops at its next
    /// entry, and nothing more is answered.
    pub(crate) fn stop(&mut self) {
        if let Some(reading) = self.reading.take() {
            reading.cancel.store(true, Ordering::SeqCst);
        }
        self.cache = None;
    }
}

/// The `List` the viewer has outstanding.
#[derive(Debug, Clone, Copy)]
struct Asked {
    req: u32,
    folder: u32,
    from: u32,
}

/// The viewer's listings of the host's folders on one services stream.
pub(crate) struct ViewerListings {
    outbox: Outbox,
    req: u32,
    asked: Option<Asked>,
    /// The folder the user opened while a `List` was outstanding: listed
    /// once that one is answered.
    wanted: Option<u32>,
    max_entries: usize,
    /// The files of the folder shown, by handle: their names and sizes, for
    /// the rows of their downloads.
    files: HashMap<u32, (Untrusted, u64)>,
    /// `List`s given up at a lock whose answer may still come.
    abandoned: Abandoned,
}

/// What a host's answer to a `List` gives the viewer's user.
#[derive(Debug)]
pub(crate) enum Answer {
    /// A page.
    Page(ListingView),
    /// The folder could not be listed, with this reason.
    Failed(u16),
    /// Nothing: the answer was for a folder the user left meanwhile.
    Stale,
}

impl ViewerListings {
    /// The listings of a stream, at most `max_entries` entries of a folder.
    pub(crate) fn new(outbox: Outbox, max_entries: usize) -> Self {
        Self {
            outbox,
            req: 0,
            asked: None,
            wanted: None,
            max_entries: max_entries.max(1),
            files: HashMap::new(),
            abandoned: Abandoned::default(),
        }
    }

    /// List the host's folder `folder` (0: its places), from its first page;
    /// while a `List` is outstanding, once it is answered. `Err` with the
    /// `Close` reason.
    pub(crate) fn open(&mut self, folder: u32) -> Result<(), u16> {
        if self.asked.is_some() {
            self.wanted = Some(folder);
            return Ok(());
        }
        self.ask(folder, 0)
    }

    fn ask(&mut self, folder: u32, from: u32) -> Result<(), u16> {
        self.req = self.req.wrapping_add(1);
        let req = self.req;
        if !self.outbox.ctrl(SvcMsg::List(List { req, folder, from })) {
            // The host stopped reading (§3.4).
            return Err(reason::PROTOCOL);
        }
        self.asked = Some(Asked { req, folder, from });
        Ok(())
    }

    /// The `List` that `req` answers, now answered; `Err(PROTOCOL)` when none
    /// is outstanding under it.
    fn answered(&mut self, req: u32) -> Result<Asked, u16> {
        match self.asked {
            Some(asked) if asked.req == req => {
                self.asked = None;
                Ok(asked)
            }
            _ => Err(reason::PROTOCOL),
        }
    }

    /// The host's `Listing`. The next page is asked for at once, unless the
    /// folder holds more than this viewer lists (then the page says
    /// `truncated`).
    pub(crate) fn listing(&mut self, listing: &Listing) -> Result<Answer, u16> {
        if self.abandoned.answered(listing.req) {
            return Ok(Answer::Stale);
        }
        let asked = self.answered(listing.req)?;
        let count = u32::try_from(listing.entries.len()).unwrap_or(u32::MAX);
        let follows = asked.from.checked_add(count);
        if listing.folder != asked.folder || listing.next.is_some_and(|next| Some(next) != follows)
        {
            return Err(reason::PROTOCOL);
        }
        if let Some(folder) = self.wanted.take() {
            self.ask(folder, 0)?;
            return Ok(Answer::Stale);
        }
        if asked.from == 0 {
            self.files.clear();
        }
        for entry in listing.entries.iter().filter(|e| e.kind == kind::FILE) {
            self.files.insert(
                entry.handle,
                (
                    Untrusted::file_name(&entry.name),
                    entry.size.unwrap_or_default(),
                ),
            );
        }
        let mut view = ListingView::remote(listing, asked.from);
        if let Some(next) = listing.next {
            if next as usize >= self.max_entries {
                view.more = false;
                view.truncated = true;
            } else {
                self.ask(asked.folder, next)?;
            }
        }
        Ok(Answer::Page(view))
    }

    /// The host's `ListFailed`.
    pub(crate) fn failed(&mut self, failed: ListFailed) -> Result<Answer, u16> {
        if self.abandoned.answered(failed.req) {
            return Ok(Answer::Stale);
        }
        self.answered(failed.req)?;
        if let Some(folder) = self.wanted.take() {
            self.ask(folder, 0)?;
            return Ok(Answer::Stale);
        }
        Ok(Answer::Failed(failed.reason))
    }

    /// The name and size of file `handle` of the folder shown, if it is one.
    pub(crate) fn file(&self, handle: u32) -> Option<&(Untrusted, u64)> {
        self.files.get(&handle)
    }

    /// The host paused browsing (it is locked): the `List` outstanding is
    /// given up (the host may have skipped it; an answer that comes for it
    /// is dropped), and a folder opened meanwhile is forgotten; `true` when
    /// something was outstanding.
    pub(crate) fn pause(&mut self) -> bool {
        self.wanted = None;
        match self.asked.take() {
            Some(asked) => {
                self.abandoned.add(asked.req);
                true
            }
            None => false,
        }
    }

    /// The host turned browsing off: nothing is outstanding any more (its
    /// answers are skipped); `true` when something was.
    pub(crate) fn turned_off(&mut self) -> bool {
        self.wanted = None;
        self.files.clear();
        self.asked.take().is_some()
    }
}
