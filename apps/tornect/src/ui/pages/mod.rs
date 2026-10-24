//! The main window's pages (the redesign's §4): Home, the Address book,
//! Sessions and Settings show what works today, and never a control that
//! does nothing. The widget gallery is reached only from the preview. Trust surfaces are not pages: the open questions are drawn above
//! the page, the banner above everything (`view`).

mod address_book;
mod gallery;
mod home;
mod id_field;
mod sessions;
mod settings;
pub(super) mod viewer;

use std::time::Instant;

use egui::{RichText, Ui};
use tornect_core::address_book::Day;

pub use self::address_book::{BookForm, Tab};
pub(super) use self::sessions::rows as session_rows;
pub use self::settings::SettingsForm;
use super::model::Model;
use super::nav::Page;
use super::theme::{self, Face};
use super::view::{Action, Form};

/// Draw `page`, under the banner of devices that can connect without asking
/// while it is up (§B.8.6.2).
pub fn draw(
    ui: &mut Ui,
    page: Page,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    if let Some(banner) = &model.unattended_banner {
        unattended_banner(ui, banner, actions);
    }
    if page != Page::Home {
        form.left_home();
    }
    match page {
        Page::Home => home::home(ui, model, form, now, actions),
        Page::AddressBook => address_book::page(ui, model, form, model.screen_shared(now), actions),
        Page::Sessions => sessions::page(ui, model, form, model.screen_shared(now)),
        Page::Settings => settings::page(ui, model, form, model.screen_shared(now), actions),
        Page::Widgets => gallery::gallery(ui),
    }
}

/// The banner of §B.8.6.2, with its one control: acknowledging it asks for
/// re-authentication on the host.
fn unattended_banner(
    ui: &mut Ui,
    banner: &super::model::UnattendedBanner,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    super::widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.add(
            egui::Label::new(
                RichText::new(banner.line(Some(Day::today())))
                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                    .color(t.text_primary),
            )
            .wrap(),
        );
        ui.add(
            egui::Label::new(
                RichText::new(
                    "It stays until you acknowledge it, which asks for this computer's password.",
                )
                .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                .color(t.text_secondary),
            )
            .wrap(),
        );
        if ui.button("Acknowledge…").clicked() {
            actions.push(Action::AcknowledgeBanner);
        }
    });
    ui.add_space(12.0);
}

/// A day as the lists say it: "Today", "Yesterday", "3 days ago" within a
/// week, else "12 Sep 2026". Days are UTC days (history keeps no time).
#[must_use]
pub fn day_text(day: Day, today: Option<Day>) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match today.map(|today| today.days() - day.days()) {
        Some(0) => "Today".to_owned(),
        Some(1) => "Yesterday".to_owned(),
        Some(n @ 2..=6) => format!("{n} days ago"),
        _ => {
            let (y, m, d) = day.ymd();
            let month = MONTHS
                .get(m.saturating_sub(1) as usize)
                .copied()
                .unwrap_or("?");
            format!("{d} {month} {y}")
        }
    }
}

/// A day inside a sentence: "today", "yesterday", "3 days ago", or "on 12
/// Sep 2026".
#[must_use]
pub fn day_in_sentence(day: Day, today: Option<Day>) -> String {
    let text = day_text(day, today);
    match text.as_str() {
        "Today" | "Yesterday" => text.to_lowercase(),
        _ if text.ends_with(" ago") => text,
        _ => format!("on {text}"),
    }
}

/// What a page shows in place of the address book's names, IDs, days and
/// devices while this computer's screen may be in a picture that leaves it.
pub const HIDDEN_WHILE_SHARED: &str = "Hidden while this screen is shared";

/// The placeholder card of what is hidden while this computer is shared.
fn hidden_card(ui: &mut Ui, what: &str) {
    let t = theme::tokens(ui.ctx());
    super::widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(HIDDEN_WHILE_SHARED)
                .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                .color(t.text_primary),
        );
        ui.add(
            egui::Label::new(
                RichText::new(what)
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(t.text_secondary),
            )
            .wrap(),
        );
    });
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use egui::accesskit::{Node, Role};
    use tornect_core::unattended::ipc::ShownLink;
    use tornect_core::{TornectId, invite};
    use tornect_signal::pairing::SessionDecision;

    use super::super::model::{Check, Hosting, Popup, PopupKind, Setup, TorState};
    use super::super::nav;
    use super::super::theme::Tokens;
    use super::super::view::main_window;
    use super::address_book::Tab;
    use super::*;

    /// The main window at `size`, in `theme`, driven one pass at a time, as
    /// `view`'s own harness drives it; widgets are found in the
    /// accessibility tree.
    struct Window {
        ctx: egui::Context,
        model: Model,
        form: Form,
        size: egui::Vec2,
        start: Instant,
        /// How far the window's clock has moved past its five seconds.
        later: Duration,
        nodes: Vec<Node>,
    }

    impl Window {
        fn new(model: Model, page: Page, theme: egui::Theme, size: (f32, f32)) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            ctx.set_theme(theme);
            let mut form = Form::default();
            form.page = page;
            let mut window = Self {
                ctx,
                model,
                form,
                size: egui::vec2(size.0, size.1),
                start: Instant::now(),
                later: Duration::ZERO,
                nodes: Vec::new(),
            };
            // The fonts are active from the second pass; a third lays out
            // with them throughout.
            for _ in 0..3 {
                assert!(window.pass(Vec::new()).is_empty(), "nothing asked");
            }
            window
        }

        fn pass(&mut self, events: Vec<egui::Event>) -> Vec<Action> {
            let now = self.start + Duration::from_secs(5) + self.later;
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                time: Some(5.0),
                events,
                ..egui::RawInput::default()
            };
            let mut actions = Vec::new();
            let (model, form) = (&self.model, &mut self.form);
            let out = self.ctx.run_ui(raw, |ui| {
                main_window(ui, model, form, now, &mut actions);
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                self.nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            out.drop_without_applying_deltas();
            actions
        }

        fn node(&self, label: &str) -> &Node {
            self.nodes
                .iter()
                .find(|n| n.label() == Some(label))
                .unwrap_or_else(|| panic!("no \"{label}\" on screen"))
        }

        fn center(&self, label: &str) -> egui::Pos2 {
            let b = self.node(label).bounds().expect("bounds");
            egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
        }

        fn click(&mut self, at: egui::Pos2) -> Vec<Action> {
            let button = |pressed| egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut actions = self.pass(vec![egui::Event::PointerMoved(at), button(true)]);
            actions.extend(self.pass(vec![button(false)]));
            actions
        }

        fn key(&mut self, key: egui::Key) -> Vec<Action> {
            let event = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            self.pass(vec![event(true), event(false)])
        }

        /// The labels of everything that can be pressed or typed into.
        fn controls(&self) -> Vec<String> {
            self.nodes
                .iter()
                .filter(|n| {
                    matches!(
                        n.role(),
                        Role::Button | Role::TextInput | Role::CheckBox | Role::Link
                    )
                })
                .map(|n| n.label().unwrap_or("").to_owned())
                .collect()
        }
    }

    fn at_rest() -> Model {
        let mut model = Model {
            id: Some("abcdefgh ijklmnop qrstuvwx yz234567 abcdefgh ijklmnop qrstuvwd".to_owned()),
            tor: TorState::Ready {
                via: "obfs4 bridges",
            },
            hosting: Hosting::Published {
                reachable: true,
                state: "Running".to_owned(),
                problem: None,
            },
            ..Model::default()
        };
        model.note("something happened");
        model
    }

    const WIDE: (f32, f32) = (1200.0, 760.0);
    /// Tall enough for the details' lowest rows.
    const TALL: (f32, f32) = (1200.0, 1100.0);
    const NARROW: (f32, f32) = (560.0, 720.0);
    const THEMES: [egui::Theme; 2] = [egui::Theme::Dark, egui::Theme::Light];
    const PAGES: [Page; 5] = [
        Page::Home,
        Page::AddressBook,
        Page::Sessions,
        Page::Settings,
        Page::Widgets,
    ];

    /// Every page draws in both themes at the window's size and at the
    /// tests' narrow size, with its title, the theme's colours, and the four
    /// pages in the sidebar: named at full width, icons on the 64-point rail
    /// below 1000 points.
    #[test]
    fn every_page_draws_in_both_themes_at_both_widths() {
        for page in PAGES {
            for theme in THEMES {
                for size in [WIDE, NARROW] {
                    let window = Window::new(at_rest(), page, theme, size);
                    let case = format!("{page:?} {theme:?} {size:?}");
                    assert!(
                        window.nodes.iter().any(|n| n.value() == Some(page.title())),
                        "{case}: no title"
                    );
                    assert_eq!(
                        window.ctx.global_style().visuals.panel_fill,
                        Tokens::of(theme).bg_app,
                        "{case}"
                    );
                    for listed in Page::LISTED {
                        let b = window.node(listed.title()).bounds().expect("bounds");
                        let width = b.x1 - b.x0;
                        if size.0 < nav::RAIL_BELOW {
                            assert!(b.x1 <= 64.0 && width <= 40.5, "{case}: {listed:?} {b:?}");
                        } else {
                            assert!(width > 150.0, "{case}: {listed:?} {b:?}");
                        }
                    }
                }
            }
        }
    }

    /// A click on a page in the sidebar opens it and asks the backend
    /// nothing, on the rail as at full width.
    #[test]
    fn a_click_in_the_sidebar_opens_the_page() {
        for size in [WIDE, NARROW] {
            let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Light, size);
            for page in [
                Page::Sessions,
                Page::Settings,
                Page::AddressBook,
                Page::Home,
            ] {
                let at = window.center(page.title());
                assert!(window.click(at).is_empty());
                assert_eq!(window.form.page, page, "{size:?}");
            }
        }
    }

    /// At full width too (the sidebar with its words), the keyboard reaches
    /// a session question's Deny first, before the page and the sidebar.
    #[test]
    fn at_full_width_deny_is_still_the_first_key_stop() {
        let mut model = at_rest();
        model.popups = vec![Popup {
            id: 9,
            kind: PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: "ab:cd".to_owned(),
            },
            deadline: Instant::now() + Duration::from_secs(60),
        }];
        for page in PAGES {
            let mut window = Window::new(model.clone(), page, egui::Theme::Dark, WIDE);
            window.key(egui::Key::Tab);
            assert_eq!(
                window.key(egui::Key::Space),
                vec![Action::Session {
                    id: 9,
                    decision: SessionDecision::Deny,
                    pointer: false,
                }],
                "{page:?}"
            );
        }
    }

    /// Home's ID and connect cards share the taller one's height, and shrink
    /// back once their content does (a long hosting line gives way to a
    /// short one).
    #[test]
    fn homes_cards_shrink_back_to_their_content() {
        let row = egui::Id::new("home-row-height");
        let mut model = at_rest();
        model.hosting = Hosting::Published {
            reachable: false,
            state: "Bootstrapping".to_owned(),
            problem: Some("the descriptor could not be uploaded ".repeat(8)),
        };
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        let tall = window.ctx.data(|d| d.get_temp::<f32>(row)).expect("stored");
        window.model.hosting = Hosting::Waiting;
        for _ in 0..2 {
            assert!(window.pass(Vec::new()).is_empty());
        }
        let short = window.ctx.data(|d| d.get_temp::<f32>(row)).expect("stored");
        assert!(short < tall - 20.0, "{tall} then {short}");
        // And the row is drawn that tall, no taller: what follows it starts
        // one gap below the cards.
        let top = |w: &Window, text: &str| {
            w.nodes
                .iter()
                .find(|n| n.value() == Some(text))
                .and_then(Node::bounds)
                .unwrap_or_else(|| panic!("no \"{text}\""))
                .y0
        };
        let row_top = top(&window, "Connect to a computer") - 21.0;
        let below = top(&window, "Saved computers");
        let drawn = below - row_top;
        assert!(
            (drawn - f64::from(short)).abs() < 40.0,
            "the row is {drawn} tall, its cards need {short}"
        );
    }

    /// Enter in the connect field connects, as the button does.
    #[test]
    fn enter_in_the_connect_field_connects() {
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Light, WIDE);
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        let id = TornectId::from_public_key(&key);
        window.form.connect_to = id.to_string();
        window.pass(Vec::new());
        let field = window
            .nodes
            .iter()
            .find(|n| n.role() == Role::TextInput)
            .and_then(Node::bounds)
            .expect("the connect field");
        let at = egui::pos2(
            ((field.x0 + field.x1) / 2.0) as f32,
            ((field.y0 + field.y1) / 2.0) as f32,
        );
        assert!(window.click(at).is_empty(), "a click only focuses it");
        assert_eq!(window.key(egui::Key::Enter), vec![Action::Connect(id)]);
    }

    /// Home: Copy ID asks for the copy and says so; an ID typed into the
    /// connect field connects with Connect or Enter once Tor is ready.
    #[test]
    fn home_copies_the_id_and_connects() {
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        let copy = window.center("Copy ID");
        assert_eq!(window.click(copy), vec![Action::CopyId]);
        window.pass(Vec::new());
        assert!(window.nodes.iter().any(|n| n.label() == Some("Copied")));

        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let id = TornectId::from_public_key(&key);
        window.form.connect_to = id.display_groups();
        window.pass(Vec::new());
        let connect = window.center("Connect");
        assert!(!window.node("Connect").is_disabled());
        assert_eq!(window.click(connect), vec![Action::Connect(id)]);

        // Not before Tor is ready.
        let mut waiting = at_rest();
        waiting.tor = TorState::Starting;
        let mut window = Window::new(waiting, Page::Home, egui::Theme::Dark, WIDE);
        window.form.connect_to = id.to_string();
        window.pass(Vec::new());
        assert!(window.node("Connect").is_disabled());
        let connect = window.center("Connect");
        assert!(window.click(connect).is_empty());
    }

    /// Design `invite` §2.4: the ID card of a window opened for a link says
    /// it answers no request, and how to answer them.
    #[test]
    fn a_link_window_says_it_answers_no_request() {
        let mut model = at_rest();
        model.hosting = Hosting::Off(super::super::LINK_WINDOW_OFF.to_owned());
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "Incoming requests: off (opened from a link; open Tornect itself to answer requests)"
        ));
    }

    /// B02: a Tor that did not start says what to check in plain words (no
    /// command, no file) and when it tries again by itself, on Home and in
    /// Settings, Connection, each with a button that tries now; once Tor is
    /// up and publishing this ID failed, the countdown is the hosting
    /// line's; while nothing waits for a try there is no button.
    #[test]
    fn a_tor_failure_counts_down_to_its_next_try_and_offers_one_now() {
        use super::super::backend::{PUBLISH_FAILED, TOR_DOWN};
        let mut model = at_rest();
        model.tor = TorState::Failed(TOR_DOWN.to_owned());
        model.hosting = Hosting::Off("Tor is not reachable".to_owned());
        model.tor_retry = Some(Instant::now() + Duration::from_secs(120));
        let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "Tor: not reachable. Check that this computer is online."
        ));
        assert!(has_text(&window, "Trying again in 2 min."));
        assert!(!has_text(&window, "config.toml") && !has_text(&window, "tornect doctor"));
        let now = window.center(home::RETRY);
        assert_eq!(window.click(now), vec![Action::RetryTor]);

        let mut settings = Window::new(model.clone(), Page::Settings, egui::Theme::Light, WIDE);
        settings.form.settings.section = settings::Section::Connection;
        settings.pass(Vec::new());
        assert!(has_text(&settings, "Trying again in"));
        let now = settings.center(home::RETRY);
        assert_eq!(settings.click(now), vec![Action::RetryTor]);

        let mut published = model.clone();
        published.tor = TorState::Ready { via: "direct Tor" };
        published.hosting = Hosting::Off(PUBLISH_FAILED.to_owned());
        published.tor_retry = Some(Instant::now() + Duration::from_secs(40));
        let mut window = Window::new(published.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "Incoming requests: off (this ID could not be published); trying again in"
        ));
        assert!(!has_text(&window, "Trying again in"), "Tor is up");
        let now = window.center(home::RETRY);
        assert_eq!(window.click(now), vec![Action::RetryTor]);
        // Settings, Connection is about Tor, which is up: no Try again
        // under "Tor: connected", with nothing saying what it would retry.
        let mut settings = Window::new(published, Page::Settings, egui::Theme::Light, WIDE);
        settings.form.settings.section = settings::Section::Connection;
        settings.pass(Vec::new());
        assert!(has_text(&settings, "Tor: connected"));
        assert!(!settings.controls().iter().any(|c| c == home::RETRY));

        model.tor_retry = None;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "Tor: not reachable."));
        assert!(!window.controls().iter().any(|c| c == home::RETRY));
    }

    /// Review F-2: a question that arrives while the page is scrolled to its
    /// end is drawn in view, in its region above the page's scroll area: its
    /// Deny and its accepts are inside the window, and Deny is still the
    /// keyboard's first stop.
    #[test]
    fn a_question_arrives_in_view_on_a_scrolled_page() {
        let mut model = at_rest();
        model.setup = Some(Setup {
            token_file: "~/.local/share/tornect/portal-restore-token".into(),
            granted: false,
            busy: false,
            note: None,
        });
        for i in 0..Model::EVENTS_KEPT {
            model.note(format!("{i}: something happened that takes two lines to say. ").repeat(3));
        }
        for size in [WIDE, NARROW] {
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            let title = |w: &Window| {
                w.nodes
                    .iter()
                    .find(|n| n.value() == Some("Home"))
                    .and_then(Node::bounds)
                    .expect("the page's title")
                    .y0
            };
            let before = title(&window);
            // A long scroll over the page, to its end (a touchpad's: applied
            // at once, not smoothed over later passes).
            let over = egui::pos2(size.0 - 80.0, size.1 / 2.0);
            let wheel = |phase| egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -4000.0),
                phase,
                modifiers: egui::Modifiers::NONE,
            };
            window.pass(vec![
                egui::Event::PointerMoved(over),
                wheel(egui::TouchPhase::Start),
                wheel(egui::TouchPhase::Move),
            ]);
            window.pass(Vec::new());
            let scrolled = title(&window);
            assert!(
                scrolled < before - 50.0,
                "{size:?}: the page did not scroll ({before} → {scrolled})"
            );
            window.model.popups = vec![Popup {
                id: 9,
                kind: PopupKind::Session {
                    label: "Laptop".to_owned(),
                    fingerprint: "ab:cd".to_owned(),
                },
                deadline: Instant::now() + Duration::from_secs(60),
            }];
            window.pass(Vec::new());
            window.pass(Vec::new());
            for label in ["Deny", "View only", "Allow control"] {
                let b = window.node(label).bounds().expect("bounds");
                assert!(
                    b.y0 >= 0.0 && b.y1 <= f64::from(size.1) && b.x1 <= f64::from(size.0),
                    "{size:?}: {label} at {b:?}, outside the window"
                );
            }
            window.key(egui::Key::Tab);
            assert_eq!(
                window.key(egui::Key::Space),
                vec![Action::Session {
                    id: 9,
                    decision: SessionDecision::Deny,
                    pointer: false,
                }],
                "{size:?}"
            );
        }
    }

    /// The preview's made-up address book (what the pictures show), or an
    /// empty one (a first run), on a window at rest.
    fn with_book(empty: bool) -> Model {
        let mut model = at_rest();
        model.device_name = "Linux PC".to_owned();
        model.book = super::super::preview::model(false, empty).book;
        model
    }

    /// The first computer of the made-up book: "Office PC", paired, seen today.
    fn office(model: &Model) -> TornectId {
        let computer = &model.book.computers[0];
        assert_eq!(computer.title(), "Office PC");
        computer.id
    }

    fn has_text(window: &Window, text: &str) -> bool {
        window
            .nodes
            .iter()
            .any(|n| n.value().is_some_and(|v| v.contains(text)))
    }

    /// Home and the address book draw empty and populated, in both themes,
    /// at both sizes, every tab of the address book included, and ask for
    /// nothing on their own.
    #[test]
    fn home_and_the_address_book_draw_empty_and_populated() {
        for empty in [true, false] {
            for theme in THEMES {
                for size in [WIDE, NARROW] {
                    let case = format!("empty {empty} {theme:?} {size:?}");
                    let home = Window::new(with_book(empty), Page::Home, theme, size);
                    assert!(has_text(&home, "Saved computers"), "{case}");
                    assert_eq!(has_text(&home, "No saved computers yet"), empty, "{case}");
                    assert!(has_text(&home, "Others see this computer as"), "{case}");
                    let mut book = Window::new(with_book(empty), Page::AddressBook, theme, size);
                    assert!(has_text(&book, "Address book"), "{case}");
                    assert_eq!(has_text(&book, "No saved computers yet"), empty, "{case}");
                    assert_eq!(
                        book.nodes
                            .iter()
                            .any(|n| n.label() == Some("Check if reachable")),
                        !empty,
                        "{case}"
                    );
                    for tab in [Tab::Recent, Tab::Devices, Tab::Computers] {
                        book.form.book.tab = tab;
                        for _ in 0..2 {
                            assert!(book.pass(Vec::new()).is_empty(), "{case} {tab:?}");
                        }
                    }
                }
            }
        }
    }

    /// "Check if reachable" asks for one ping per click and nothing more:
    /// while the answer is awaited the button is disabled, a click on it asks
    /// for nothing, and passes without a click never ask (no polling, no
    /// presence).
    #[test]
    fn the_check_button_sends_exactly_one_ping() {
        let model = with_book(false);
        let id = office(&model);
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, WIDE);
        for _ in 0..20 {
            assert!(
                window.pass(Vec::new()).is_empty(),
                "nothing is asked without a click"
            );
        }
        let check = window.center("Check if reachable");
        assert_eq!(window.click(check), vec![Action::Ping(id)]);
        // What the tokio side answers at once: the check is running.
        window.model.book.set_check(id, Check::Asking);
        window.pass(Vec::new());
        assert!(window.node("Checking…").is_disabled());
        let checking = window.center("Checking…");
        assert!(
            window.click(checking).is_empty(),
            "no second ping while one runs"
        );
        window
            .model
            .book
            .set_check(id, Check::Reachable { millis: 6200 });
        for _ in 0..20 {
            assert!(
                window.pass(Vec::new()).is_empty(),
                "an answer asks nothing again"
            );
        }
        assert!(has_text(&window, "It answered over Tor (6.2 s)"));
    }

    /// Forget asks first: the first click only shows the question, "Keep it"
    /// takes it back, and only "Forget" forgets.
    #[test]
    fn forget_asks_first() {
        let model = with_book(false);
        let id = office(&model);
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Light, WIDE);
        let forget = window.center("Forget this computer");
        assert!(window.click(forget).is_empty());
        assert_eq!(window.form.book.forgetting, Some(id));
        window.pass(Vec::new());
        assert!(has_text(&window, "Forget \"Office PC\"?"));
        let keep = window.center("Keep it");
        assert!(window.click(keep).is_empty());
        assert_eq!(window.form.book.forgetting, None);
        window.pass(Vec::new());
        let forget = window.center("Forget this computer");
        assert!(window.click(forget).is_empty());
        window.pass(Vec::new());
        let sure = window.center("Forget");
        assert_eq!(window.click(sure), vec![Action::ForgetHost(id)]);
    }

    /// Add computer takes an ID only once it is one, not this computer's
    /// own, and saves it with the name typed. What is wrong is said with the
    /// shared field's specific words (design `invite` §2.3).
    #[test]
    fn add_checks_the_id_before_saving() {
        let mut model = with_book(false);
        let mine = ed25519_dalek::SigningKey::from_bytes(&[6; 32]).verifying_key();
        let own = TornectId::from_public_key(&mine).display_groups();
        model.id = Some(own.clone());
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, NARROW);
        let add = window.center("Add computer");
        assert!(window.click(add).is_empty());
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key();
        let valid = TornectId::from_public_key(&key);
        for (typed, says) in [
            ("not an id".to_owned(), Some("7 of 56 characters.")),
            (own.clone(), Some("That is this computer's own ID")),
            (valid.display_groups(), None),
        ] {
            window.form.book.adding = Some((typed.clone(), "Desk".to_owned()));
            window.pass(Vec::new());
            window.pass(Vec::new());
            match says {
                Some(text) => {
                    assert!(has_text(&window, text), "{typed}");
                    assert!(window.node("Save").is_disabled(), "{typed}");
                    let save = window.center("Save");
                    assert!(window.click(save).is_empty(), "{typed}");
                }
                None => {
                    assert!(!window.node("Save").is_disabled());
                    let save = window.center("Save");
                    assert_eq!(
                        window.click(save),
                        vec![Action::SaveEntry(valid, "Desk".to_owned())]
                    );
                    assert!(window.form.book.adding.is_none());
                }
            }
        }
    }

    /// B26: the connect field refuses this computer's own ID, as Add
    /// computer does: it says so, Connect stays disabled, Enter asks for
    /// nothing, and no look-alike warning or "Connect anyway" is offered for
    /// it (it is not a different address). Another valid ID still connects.
    #[test]
    fn the_connect_field_refuses_this_computers_own_id() {
        let mut model = with_book(false);
        let mine = ed25519_dalek::SigningKey::from_bytes(&[6; 32]).verifying_key();
        let own = TornectId::from_public_key(&mine);
        model.id = Some(own.display_groups());
        model.connect_warning = Some(super::super::model::ConnectWarning {
            id: own,
            name: "Linux PC".to_owned(),
        });
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        for typed in [own.display_groups(), own.to_string()] {
            window.form.connect_to = typed.clone();
            window.pass(Vec::new());
            window.pass(Vec::new());
            assert!(has_text(&window, id_field::OWN_ID), "{typed}");
            assert!(!has_text(&window, "Looks like"), "{typed}");
            assert!(
                !window.controls().iter().any(|c| c == "Connect anyway"),
                "{typed}"
            );
            assert!(window.node("Connect").is_disabled(), "{typed}");
            let connect = window.center("Connect");
            assert!(window.click(connect).is_empty(), "{typed}");
            let field = window
                .nodes
                .iter()
                .find(|n| n.role() == Role::TextInput)
                .and_then(Node::bounds)
                .expect("the connect field");
            let at = egui::pos2(
                ((field.x0 + field.x1) / 2.0) as f32,
                ((field.y0 + field.y1) / 2.0) as f32,
            );
            assert!(window.click(at).is_empty(), "{typed}");
            assert!(window.key(egui::Key::Enter).is_empty(), "{typed}");
        }
        let other = TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        );
        window.form.connect_to = other.display_groups();
        window.pass(Vec::new());
        assert!(!has_text(&window, id_field::OWN_ID));
        let connect = window.center("Connect");
        assert_eq!(window.click(connect), vec![Action::Connect(other)]);
    }

    /// An ID from the key of seed `seed`.
    fn key_id(seed: u8) -> TornectId {
        TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    /// The right shape and checksum, but 32 bytes that decode to no curve
    /// point.
    fn not_a_key() -> TornectId {
        (0..=u8::MAX)
            .map(|i| TornectId::from_bytes([i; 32]))
            .find(|id| id.verifying_key().is_err())
            .expect("some repeated byte is no curve point")
    }

    /// The middle of the text field labelled `label`, or of the first text
    /// field.
    fn field_at(window: &Window, label: Option<&str>) -> egui::Pos2 {
        let b = window
            .nodes
            .iter()
            .filter(|n| n.role() == Role::TextInput)
            .find(|n| label.is_none() || n.label() == label)
            .and_then(Node::bounds)
            .expect("the field");
        egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
    }

    /// Click into the field at `at` and paste `text` there, as a user does.
    fn paste(window: &mut Window, at: egui::Pos2, text: &str) -> Vec<Action> {
        let mut actions = window.click(at);
        actions.extend(window.pass(vec![egui::Event::Paste(text.to_owned())]));
        actions.extend(window.pass(Vec::new()));
        actions
    }

    /// Design `invite` §2.2–§2.3: a whole invitation (its line breaks, as
    /// egui's single-line paste turns them into spaces) or a link pasted into
    /// the connect field becomes the ID's groups, which is what Connect then
    /// dials; the same in Add a computer, whose Save then saves that ID. The
    /// paste itself asks for nothing.
    #[test]
    fn a_pasted_invitation_becomes_its_id() {
        let id = key_id(7);
        for text in [invite::invitation(&id), invite::link(&id)] {
            let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
            let at = field_at(&window, None);
            assert!(paste(&mut window, at, &text).is_empty(), "{text}");
            assert_eq!(window.form.connect_to, id.display_groups(), "{text}");
            assert!(!window.node("Connect").is_disabled(), "{text}");
            let connect = window.center("Connect");
            assert_eq!(window.click(connect), vec![Action::Connect(id)], "{text}");
        }

        let mut book = Window::new(with_book(false), Page::AddressBook, egui::Theme::Dark, WIDE);
        let add = book.center("Add computer");
        assert!(book.click(add).is_empty());
        book.form.book.adding = Some((String::new(), "Desk".to_owned()));
        book.pass(Vec::new());
        let at = field_at(&book, Some("Tornect ID"));
        assert!(paste(&mut book, at, &invite::invitation(&id)).is_empty());
        let typed = book
            .form
            .book
            .adding
            .as_ref()
            .map(|(typed, _)| typed.clone());
        assert_eq!(typed, Some(id.display_groups()));
        let save = book.center("Save");
        assert_eq!(
            book.click(save),
            vec![Action::SaveEntry(id, "Desk".to_owned())]
        );
    }

    /// A pasted ID with a zero-width space a chat inserted is rewritten to
    /// the groups (so the field shows what will be dialled); one pasted
    /// cleanly stays as it was pasted.
    #[test]
    fn a_pasted_id_with_a_zero_width_space_is_rewritten() {
        let id = key_id(7);
        let bare = id.to_string();
        let (head, tail) = bare.split_at(20);
        for (text, shown) in [
            (format!("{head}\u{200B}{tail}"), id.display_groups()),
            (bare.clone(), bare.clone()),
        ] {
            let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Light, WIDE);
            let at = field_at(&window, None);
            assert!(paste(&mut window, at, &text).is_empty());
            assert_eq!(window.form.connect_to, shown);
            let connect = window.center("Connect");
            assert_eq!(window.click(connect), vec![Action::Connect(id)]);
        }
    }

    /// Design `invite` §2.2–§2.3, §3: Home and the address book say what is
    /// wrong with an ID with the same specific words, and neither takes it:
    /// a short ID, a digit base32 never has, a link with more than the ID,
    /// two IDs, an ID that is no key (new on Home) and this computer's own.
    #[test]
    fn id_problems_on_home_and_in_the_book() {
        let mut model = with_book(false);
        let own = key_id(6);
        model.id = Some(own.display_groups());
        let (a, b) = (key_id(7), key_id(8));
        let zero = format!("{}0", &a.to_string()[..55]);
        let rows = [
            ("abcdefgh".to_owned(), "8 of 56 characters.".to_owned()),
            (
                zero,
                "IDs never contain 0, 1, 8 or 9 (perhaps the letter o, i, l, b or g).".to_owned(),
            ),
            (
                format!("{}?x=1", invite::link(&a)),
                "That link holds more than a Tornect ID; Tornect takes only tornect://<ID>."
                    .to_owned(),
            ),
            (
                format!("{} {}", invite::link(&a), invite::link(&b)),
                "That text holds more than one Tornect ID: paste only the one you want.".to_owned(),
            ),
            (
                not_a_key().display_groups(),
                "That ID has the right shape but is no computer's key: check for a typo."
                    .to_owned(),
            ),
            (own.display_groups(), id_field::OWN_ID.to_owned()),
        ];
        let mut home = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        let mut book = Window::new(model, Page::AddressBook, egui::Theme::Dark, NARROW);
        let add = book.center("Add computer");
        assert!(book.click(add).is_empty());
        for (typed, says) in &rows {
            home.form.connect_to = typed.clone();
            book.form.book.adding = Some((typed.clone(), "Desk".to_owned()));
            for window in [&mut home, &mut book] {
                window.pass(Vec::new());
                window.pass(Vec::new());
                assert!(has_text(window, says), "{typed}: {says}");
            }
            assert!(home.node("Connect").is_disabled(), "{typed}");
            let connect = home.center("Connect");
            assert!(home.click(connect).is_empty(), "{typed}");
            assert!(book.node("Save").is_disabled(), "{typed}");
            let save = book.center("Save");
            assert!(book.click(save).is_empty(), "{typed}");
            assert_eq!(home.form.connect_to, *typed, "a refusal is never rewritten");
        }
        // The empty field says nothing at all.
        home.form.connect_to.clear();
        home.pass(Vec::new());
        assert!(!has_text(&home, "No Tornect ID was given"));
    }

    /// The main window as `on_show` sees it, not minimised, recording what
    /// is asked of it: the raise of a second launch or a link.
    #[derive(Default)]
    struct Raise(std::cell::RefCell<Vec<&'static str>>);

    impl super::super::app::Attention for Raise {
        fn is_minimized(&self) -> Option<bool> {
            Some(false)
        }

        fn set_minimized(&self, _minimized: bool) {
            self.0.borrow_mut().push("restore");
        }

        fn request_user_attention(&self, kind: Option<winit::window::UserAttentionType>) {
            assert_eq!(kind, Some(winit::window::UserAttentionType::Critical));
            self.0.borrow_mut().push("attention");
        }
    }

    /// Design `invite` §2.2, §2.4, L-1: a link's fill puts the ID in the
    /// connect field, says so, and opens Home (from any page; the address
    /// book's Add field is never filled), and nothing more: no pass asks
    /// for anything; within a second of the row's first draw Connect is
    /// disabled, and neither its click nor Enter in the field dials; a
    /// second after, a click dials the filled ID.
    #[test]
    fn a_link_fill_never_connects() {
        let id = key_id(7);
        let mut window = Window::new(at_rest(), Page::AddressBook, egui::Theme::Dark, WIDE);
        window.form.book.adding = Some((String::new(), String::new()));
        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(id), own);
        assert_eq!(window.form.page, Page::Home);
        assert_eq!(
            window.form.book.adding,
            Some((String::new(), String::new())),
            "links never fill the address book"
        );
        for _ in 0..3 {
            assert!(window.pass(Vec::new()).is_empty());
        }
        assert_eq!(window.form.connect_to, id.display_groups());
        assert!(has_text(&window, home::LINK_FILLED));
        assert!(window.node("Connect").is_disabled());
        let connect = window.center("Connect");
        assert!(window.click(connect).is_empty());
        let at = field_at(&window, None);
        assert!(
            window.click(at).is_empty(),
            "a click only focuses the field"
        );
        assert!(
            window.key(egui::Key::Enter).is_empty(),
            "Enter dials nothing"
        );
        window.later += Duration::from_millis(900);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(window.node("Connect").is_disabled());
        assert!(window.click(connect).is_empty());
        window.later += Duration::from_millis(100);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Connect").is_disabled());
        assert_eq!(window.click(connect), vec![Action::Connect(id)]);
        assert!(
            has_text(&window, home::LINK_FILLED),
            "the field still has it"
        );
    }

    /// L-4 (MUST): a fill takes the keyboard focus from the connect field,
    /// so that keys typed for another program, or for the user's own ID,
    /// never reach it. With the field focused (being typed into) when a
    /// link comes, the next pass leaves nothing focused; once Connect has
    /// armed, Enter dials nothing and typed text changes nothing.
    #[test]
    fn a_link_fill_takes_the_focus_from_the_field() {
        let id = key_id(7);
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        let at = field_at(&window, None);
        assert!(window.click(at).is_empty());
        let field = window.ctx.memory(|m| m.focused());
        assert!(field.is_some(), "the field has the focus");
        assert!(
            window
                .pass(vec![egui::Event::Text("abc".to_owned())])
                .is_empty()
        );
        assert_eq!(window.form.connect_to, "abc", "typed into the field");
        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(id), own);
        assert_eq!(window.ctx.memory(|m| m.focused()), field, "until a pass");
        assert!(window.pass(Vec::new()).is_empty());
        assert_eq!(
            window.ctx.memory(|m| m.focused()),
            None,
            "the fill took the focus"
        );
        window.later += Duration::from_secs(1);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Connect").is_disabled(), "armed");
        assert!(
            window.key(egui::Key::Enter).is_empty(),
            "Enter dials nothing"
        );
        assert!(
            window
                .pass(vec![egui::Event::Text("x".to_owned())])
                .is_empty()
        );
        assert!(window.pass(Vec::new()).is_empty());
        assert_eq!(window.form.connect_to, id.display_groups());
        assert_eq!(window.ctx.memory(|m| m.focused()), None);
    }

    /// The arming second starts at the first pass that draws the Connect
    /// row, not at the fill: a window first drawn five seconds after the
    /// link came still waits its second.
    #[test]
    fn a_link_fill_arms_when_seen() {
        let id = key_id(7);
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Light, WIDE);
        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(id), own);
        window.later += Duration::from_secs(5);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(window.node("Connect").is_disabled());
        window.later += Duration::from_millis(900);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(window.node("Connect").is_disabled(), "at +0.9 s");
        window.later += Duration::from_millis(100);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Connect").is_disabled(), "at +1 s");
    }

    /// L-4: an armed fill disarms for another second whenever the window
    /// comes back into view (`window_came_back`, which the event loop runs
    /// for `Focused(true)`, `Occluded(false)` and the `Show` raise), and
    /// whenever another link arrives, a refused one included: the fill
    /// stays, still said so beside the refusal (§2.2), its Connect waits
    /// again.
    #[test]
    fn a_link_fill_arms_again_after_a_return() {
        let id = key_id(7);
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(id), own);
        window.pass(Vec::new());
        window.later += Duration::from_secs(1);
        window.pass(Vec::new());
        assert!(!window.node("Connect").is_disabled(), "armed");
        let connect = window.center("Connect");

        window.form.window_came_back();
        assert!(window.pass(Vec::new()).is_empty());
        assert!(window.node("Connect").is_disabled(), "back in view");
        assert!(window.click(connect).is_empty());
        window.later += Duration::from_secs(1);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Connect").is_disabled());

        window.form.link_arrived(ShownLink::Refused, own);
        assert!(window.pass(Vec::new()).is_empty());
        assert_eq!(window.form.connect_to, id.display_groups());
        assert!(has_text(&window, home::LINK_REFUSED));
        assert!(
            has_text(&window, home::LINK_FILLED),
            "the field still holds the fill"
        );
        assert!(window.node("Connect").is_disabled(), "another link came");
        let connect = window.center("Connect");
        assert!(window.click(connect).is_empty());
        window.later += Duration::from_secs(1);
        assert!(window.pass(Vec::new()).is_empty());
        assert_eq!(window.click(connect), vec![Action::Connect(id)]);
    }

    /// §2.2, L-1, L-4: a link that fills nothing (refused, no key, or this
    /// computer's own ID) after a fill still in the field keeps the fill's
    /// note, above its own: the field holds an ID a link put there, and it
    /// says so for as long as Connect would dial it. An edit that leaves the
    /// field yielding that ID takes only the refusal's note away.
    #[test]
    fn a_later_refused_link_keeps_the_fill_said() {
        let (own, id) = (key_id(6), key_id(7));
        let mut model = at_rest();
        model.id = Some(own.display_groups());
        for (later, says) in [
            (ShownLink::Refused, home::LINK_REFUSED),
            (ShownLink::Fill(not_a_key()), home::LINK_REFUSED),
            (ShownLink::Fill(own), home::LINK_OWN),
        ] {
            let case = format!("{later:?} {says}");
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
            window.form.link_arrived(ShownLink::Fill(id), Some(own));
            window.pass(Vec::new());
            window.form.link_arrived(later, Some(own));
            for _ in 0..3 {
                assert!(window.pass(Vec::new()).is_empty(), "{case}");
            }
            assert_eq!(window.form.connect_to, id.display_groups(), "{case}");
            let top = |window: &Window, text: &str| {
                window
                    .nodes
                    .iter()
                    .find(|n| n.value().is_some_and(|v| v.contains(text)))
                    .and_then(Node::bounds)
                    .map(|b| b.y0)
            };
            let (filled, refused) = (top(&window, home::LINK_FILLED), top(&window, says));
            assert!(filled.is_some() && refused.is_some(), "{case}");
            assert!(filled < refused, "the fill's note first: {case}");
            // An edit that keeps the ID (a hyphen is no character of it).
            let at = field_at(&window, None);
            assert!(window.click(at).is_empty(), "{case}");
            window.pass(vec![egui::Event::Text("-".to_owned())]);
            window.pass(Vec::new());
            assert_ne!(window.form.connect_to, id.display_groups(), "{case}");
            assert!(!has_text(&window, says), "{case}");
            assert!(has_text(&window, home::LINK_FILLED), "{case}");
            window.later += Duration::from_secs(1);
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            let connect = window.center("Connect");
            assert_eq!(window.click(connect), vec![Action::Connect(id)], "{case}");
        }
    }

    /// L-4: with a pairing and a session question open, a link's raise and
    /// fill answer, dismiss and re-order no question and ask for nothing;
    /// the raise arms the open card again and only asks for attention,
    /// never the focus (the window is not minimised, so nothing is
    /// restored either).
    #[test]
    fn a_link_fill_reaches_no_sheet() {
        let mut model = at_rest();
        model.popups = vec![session_question(1, "Laptop"), pairing_question(2)];
        let before = format!("{:?}", model.popups);
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        window.later += Duration::from_secs(2);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Allow control").is_disabled(), "armed");
        let allow = window.center("Allow control");

        let raise = Raise::default();
        super::super::app::on_show(&raise, &mut window.form);
        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(key_id(7)), own);
        let mut asked = Vec::new();
        for _ in 0..3 {
            asked.extend(window.pass(Vec::new()));
        }
        assert!(asked.is_empty(), "{asked:?}");
        assert_eq!(format!("{:?}", window.model.popups), before);
        assert!(has_text(&window, "1 more waiting"));
        assert!(window.node("Allow control").is_disabled(), "armed again");
        assert!(window.click(allow).is_empty());
        assert_eq!(raise.0.into_inner(), vec!["attention"]);
        assert_eq!(window.form.connect_to, key_id(7).display_groups());
    }

    /// A refused link, a fill whose bytes are no key (what IPC can carry)
    /// and a fill of this computer's own ID fill nothing: the field keeps
    /// what it held, Home says why, and nothing is asked. The note goes
    /// when the field is edited, or when another link comes.
    #[test]
    fn a_bad_or_own_link_fills_nothing_and_says_why() {
        let own = key_id(6);
        let mut model = at_rest();
        model.id = Some(own.display_groups());
        for (link, says) in [
            (ShownLink::Refused, home::LINK_REFUSED),
            (ShownLink::Fill(not_a_key()), home::LINK_REFUSED),
            (ShownLink::Fill(own), home::LINK_OWN),
        ] {
            let case = format!("{link:?} {says}");
            let mut window = Window::new(model.clone(), Page::Sessions, egui::Theme::Dark, WIDE);
            window.form.connect_to = "abc".to_owned();
            window.form.link_arrived(link, Some(own));
            assert_eq!(window.form.page, Page::Home, "{case}");
            for _ in 0..3 {
                assert!(window.pass(Vec::new()).is_empty(), "{case}");
            }
            assert_eq!(window.form.connect_to, "abc", "{case}");
            assert!(has_text(&window, says), "{case}");
            assert!(!has_text(&window, home::LINK_FILLED), "{case}");
            for label in [home::LINK_REFUSED, home::LINK_OWN] {
                assert_eq!(has_text(&window, label), label == says, "{case}");
            }
            // Typing in the field takes the note away.
            let at = field_at(&window, None);
            assert!(window.click(at).is_empty(), "{case}");
            assert!(has_text(&window, says), "a click is no edit: {case}");
            window.pass(vec![egui::Event::Text("d".to_owned())]);
            window.pass(Vec::new());
            assert_eq!(window.form.connect_to, "abcd", "{case}");
            assert!(!has_text(&window, says), "{case}");
            // Another link replaces it.
            window.form.link_arrived(link, Some(own));
            window
                .form
                .link_arrived(ShownLink::Fill(key_id(7)), Some(own));
            window.pass(Vec::new());
            assert!(has_text(&window, home::LINK_FILLED), "{case}");
            assert!(!has_text(&window, says), "{case}");
        }
    }

    /// L-1 (review): while the field holds a link's fill, Connect answers
    /// only a click of the pointer. Connect focused from the keyboard before
    /// the link (Space then dials what the user typed), then filled by a
    /// link: once armed, Space and Enter dial nothing, and a click dials the
    /// fill. Reached by Tab after the fill, Connect is skipped, so Space and
    /// Enter there dial nothing either.
    #[test]
    fn a_link_fill_is_never_dialled_from_the_keyboard() {
        let (typed, filled) = (key_id(7), key_id(8));
        let dials = |actions: &[Action]| {
            actions
                .iter()
                .any(|a| matches!(a, Action::Connect(_) | Action::ConnectAnyway(_)))
        };
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        window.form.connect_to = typed.display_groups();
        window.pass(Vec::new());
        let at = field_at(&window, None);
        assert!(window.click(at).is_empty());
        assert!(window.key(egui::Key::Tab).is_empty());
        let focused = window.ctx.memory(|m| m.focused());
        assert!(focused.is_some(), "Tab reached Connect");
        assert_eq!(
            window.key(egui::Key::Space),
            vec![Action::Connect(typed)],
            "the keyboard presses Connect without a link"
        );
        assert_eq!(window.ctx.memory(|m| m.focused()), focused);

        let own = window.model.own_id();
        window.form.link_arrived(ShownLink::Fill(filled), own);
        assert!(window.pass(Vec::new()).is_empty());
        window.later += Duration::from_secs(1);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!window.node("Connect").is_disabled(), "armed");
        assert_eq!(
            window.ctx.memory(|m| m.focused()),
            None,
            "Connect gave up the focus"
        );
        for key in [egui::Key::Space, egui::Key::Enter] {
            assert!(window.key(key).is_empty(), "{key:?}");
        }

        let at = field_at(&window, None);
        assert!(window.click(at).is_empty());
        let mut pressed = window.key(egui::Key::Tab);
        assert_ne!(
            window.ctx.memory(|m| m.focused()),
            focused,
            "Tab skips Connect while the fill is there"
        );
        for key in [egui::Key::Space, egui::Key::Enter] {
            pressed.extend(window.key(key));
        }
        assert!(!dials(&pressed), "{pressed:?}");

        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        window.form.link_arrived(ShownLink::Fill(filled), own);
        window.pass(Vec::new());
        window.later += Duration::from_secs(1);
        window.pass(Vec::new());
        let connect = window.center("Connect");
        assert_eq!(window.click(connect), vec![Action::Connect(filled)]);
    }

    /// L-1, L-4 (review): a link that brings the window to Home arms Home's
    /// rows that dial, whatever it said: each saved computer's actions and
    /// the Connect row with what the user typed earlier wait until they have
    /// been in view, still, for a second, and again after every return of
    /// the window, so a click aimed at the page the user was on never lands
    /// on them. A later return to Home by the user's own choice is not
    /// armed.
    #[test]
    fn a_link_arms_homes_saved_computers_and_connect() {
        /// The first saved computer's Knock (the top left one), and whether
        /// every Knock on Home is disabled.
        fn knock(window: &Window) -> (egui::Pos2, bool) {
            let knocks: Vec<&Node> = window
                .nodes
                .iter()
                .filter(|n| n.label() == Some("Knock"))
                .collect();
            let first = knocks
                .iter()
                .filter_map(|n| n.bounds())
                .min_by(|a, b| (a.y0, a.x0).partial_cmp(&(b.y0, b.x0)).unwrap())
                .expect("a Knock on Home");
            let at = egui::pos2(
                ((first.x0 + first.x1) / 2.0) as f32,
                ((first.y0 + first.y1) / 2.0) as f32,
            );
            (at, knocks.iter().all(|n| n.is_disabled()))
        }
        let model = with_book(false);
        let office = office(&model);
        let typed = key_id(7);
        // Tall enough for the saved computers' cards to be in view.
        let mut probe = Window::new(model.clone(), Page::Home, egui::Theme::Dark, TALL);
        let (at, disabled) = knock(&probe);
        assert!(!disabled);
        assert_eq!(
            probe.click(at),
            vec![Action::Connect(office)],
            "without a link, Knock answers at once"
        );

        for link in [ShownLink::Refused, ShownLink::Fill(key_id(8))] {
            let case = format!("{link:?}");
            let mut window = Window::new(model.clone(), Page::AddressBook, egui::Theme::Dark, TALL);
            if link == ShownLink::Refused {
                window.form.connect_to = typed.display_groups();
            }
            let own = window.model.own_id();
            window.form.link_arrived(link, own);
            assert_eq!(window.form.page, Page::Home, "{case}");
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            let (at, disabled) = knock(&window);
            let connect = window.center("Connect");
            assert!(disabled, "{case}");
            assert!(
                window.node("Connect without asking").is_disabled(),
                "{case}"
            );
            assert!(window.node("Connect").is_disabled(), "{case}");
            for at in [at, connect] {
                assert!(window.click(at).is_empty(), "{case}");
            }
            window.later += Duration::from_millis(900);
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            assert!(window.click(at).is_empty(), "{case}: at +0.9 s");
            window.later += Duration::from_millis(100);
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            assert!(!knock(&window).1, "{case}");
            assert_eq!(window.click(at), vec![Action::Connect(office)], "{case}");
            if link == ShownLink::Refused {
                assert_eq!(
                    window.click(connect),
                    vec![Action::Connect(typed)],
                    "{case}"
                );
            }

            window.form.window_came_back();
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            assert!(knock(&window).1, "{case}: back in view");
            assert!(window.click(at).is_empty(), "{case}");
            window.later += Duration::from_secs(1);
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            assert!(!knock(&window).1, "{case}");

            // The user picks another page, then Home again.
            window.form.page = Page::Sessions;
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            window.form.page = Page::Home;
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            window.form.window_came_back();
            assert!(window.pass(Vec::new()).is_empty(), "{case}");
            assert!(!knock(&window).1, "{case}: not armed");
            assert_eq!(window.click(at), vec![Action::Connect(office)], "{case}");
        }
    }

    /// Design `invite` §2.1: Copy invitation asks for the invitation of
    /// this computer's ID to be copied (`Action::Copy`, no action of its
    /// own) and says "Copied" for two seconds; Copy ID keeps its words.
    /// The three buttons fit the ID card at both widths. Without an ID it
    /// is disabled.
    #[test]
    fn copy_invitation_copies_it() {
        let own = key_id(6);
        for size in [WIDE, NARROW] {
            let mut model = at_rest();
            model.id = Some(own.display_groups());
            let mut window = Window::new(model, Page::Home, egui::Theme::Dark, size);
            for label in ["Copy ID", "Copy invitation", "Show QR code"] {
                let b = window.node(label).bounds().expect("bounds");
                assert!(
                    b.x0 >= 0.0 && b.x1 <= f64::from(size.0),
                    "{size:?}: {label} at {b:?}"
                );
            }
            assert!(!window.node("Copy invitation").is_disabled());
            let copy = window.center("Copy invitation");
            assert_eq!(
                window.click(copy),
                vec![Action::Copy(invite::invitation(&own))],
                "{size:?}"
            );
            window.pass(Vec::new());
            assert!(window.nodes.iter().any(|n| n.label() == Some("Copied")));
            assert!(window.nodes.iter().any(|n| n.label() == Some("Copy ID")));
            assert!(
                !window
                    .nodes
                    .iter()
                    .any(|n| n.label() == Some("Copy invitation"))
            );
            window.later += Duration::from_secs(2);
            window.pass(Vec::new());
            assert!(
                window
                    .nodes
                    .iter()
                    .any(|n| n.label() == Some("Copy invitation"))
            );
        }
        let mut model = at_rest();
        model.id = None;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(window.node("Copy invitation").is_disabled());
    }

    /// Rename starts from the saved name and saves what was typed.
    #[test]
    fn rename_saves_the_typed_name() {
        let model = with_book(false);
        let id = office(&model);
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, WIDE);
        let rename = window.center("Rename");
        assert!(window.click(rename).is_empty());
        assert_eq!(
            window.form.book.renaming,
            Some((id, "Office PC".to_owned()))
        );
        window.form.book.renaming = Some((id, "  Desk 2 ".to_owned()));
        window.pass(Vec::new());
        let save = window.center("Save");
        assert_eq!(
            window.click(save),
            vec![Action::RenameHost(id, "Desk 2".to_owned())]
        );
    }

    /// The Recent tab: the switch asks to turn history off (and on), Clear
    /// asks to clear; with history off the tab says so.
    #[test]
    fn the_history_switch_and_clear() {
        let mut window = Window::new(with_book(false), Page::AddressBook, egui::Theme::Dark, WIDE);
        window.form.book.tab = Tab::Recent;
        window.pass(Vec::new());
        assert!(has_text(&window, "You connected to \"Office PC\""));
        let switch = window.center("Keep a list of recent connections");
        assert_eq!(window.click(switch), vec![Action::SetHistory(false)]);
        let clear = window.center("Clear history");
        assert_eq!(window.click(clear), vec![Action::ClearHistory]);
        window.model.book.history = false;
        window.model.book.recent.clear();
        window.pass(Vec::new());
        assert!(has_text(&window, "History is off"));
        let switch = window.center("Keep a list of recent connections");
        assert_eq!(window.click(switch), vec![Action::SetHistory(true)]);
    }

    /// Home: the saved computers connect in one click once Tor is ready,
    /// "Open address book" opens it, and "Show QR code" shows the ID's QR
    /// code.
    #[test]
    fn home_connects_to_a_saved_computer_and_shows_the_qr_code() {
        let model = with_book(false);
        office(&model);
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "Office PC"));
        let show = window.center("Show QR code");
        assert!(window.click(show).is_empty());
        assert!(window.form.qr);
        window.pass(Vec::new());
        assert!(window.nodes.iter().any(|n| n.label() == Some("QR code")));
        // The saved cards' Knock (§B.8.10: Knock comes first until a
        // connect without asking worked there); the connect card's own
        // button stays "Connect".
        let connects: Vec<egui::Pos2> = window
            .nodes
            .iter()
            .filter(|n| n.label() == Some("Knock"))
            .filter_map(Node::bounds)
            .map(|b| egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32))
            .collect();
        assert_eq!(connects.len(), 3, "the three saved ones");
        assert_eq!(
            window
                .nodes
                .iter()
                .filter(|n| n.label() == Some("Connect"))
                .count(),
            1,
            "the connect card's"
        );
        let lowest = connects
            .iter()
            .copied()
            .filter(|p| p.y < WIDE.1)
            .max_by(|a, b| a.y.total_cmp(&b.y))
            .expect("a saved card's Connect in view");
        let asked = window.click(lowest);
        assert!(
            matches!(asked.as_slice(), [Action::Connect(_)]),
            "{asked:?}"
        );
        let open = window.center("Open address book");
        assert!(window.click(open).is_empty());
        assert_eq!(window.form.page, Page::AddressBook);
    }

    /// The highest node labelled `label` (the prompt sits above the page).
    fn topmost<'a>(window: &'a Window, label: &str) -> &'a Node {
        window
            .nodes
            .iter()
            .filter(|n| n.label() == Some(label))
            .min_by(|a, b| {
                let y = |n: &Node| n.bounds().map_or(f64::MAX, |b| b.y0);
                y(a).total_cmp(&y(b))
            })
            .unwrap_or_else(|| panic!("no \"{label}\" on screen"))
    }

    /// The labelled controls' centres, top first.
    fn centres(window: &Window, label: &str) -> Vec<egui::Pos2> {
        let mut at: Vec<egui::Pos2> = window
            .nodes
            .iter()
            .filter(|n| n.label() == Some(label))
            .filter_map(Node::bounds)
            .map(|b| egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32))
            .collect();
        at.sort_by(|a, b| a.y.total_cmp(&b.y));
        at
    }

    /// §B.8.10: a saved computer's card offers Connect (without asking, the
    /// prompt first) as its first action once an unattended session worked
    /// there, Knock otherwise; its admin actions each ask first, naming it,
    /// and only then open the prompt; an unread setup change holds Connect.
    #[test]
    fn the_host_card_offers_connect_after_a_first_success_and_knock_otherwise() {
        use crate::ua_client::AdminAction;
        let mut model = with_book(false);
        let id = office(&model);
        model.book.computers[0].unattended.worked_before = true;
        let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        // The connect card's Connect and Office PC's; Knock for the others
        // and as Office PC's second action.
        assert_eq!(centres(&window, "Connect").len(), 2);
        assert_eq!(centres(&window, "Knock").len(), 3);
        let office_connect = *centres(&window, "Connect").last().unwrap();
        assert_eq!(window.click(office_connect), vec![Action::AskPassword(id)]);

        let mut window = Window::new(model.clone(), Page::AddressBook, egui::Theme::Light, TALL);
        let revoke = window.center("Revoke this device");
        assert!(window.click(revoke).is_empty(), "nothing is sent by itself");
        assert_eq!(
            window.form.ua.confirming,
            Some((id, AdminAction::RevokeThisDevice))
        );
        window.pass(Vec::new());
        assert!(has_text(&window, "Revoke this device at \"Office PC\"?"));
        let go = window.center("Continue: the password");
        assert_eq!(
            window.click(go),
            vec![Action::AskAdmin(id, AdminAction::RevokeThisDevice)]
        );
        // Turn unattended off is offered only after a control session there.
        assert!(
            !window
                .nodes
                .iter()
                .any(|n| n.label() == Some("Turn unattended off there"))
        );
        let mut control = model.clone();
        control.book.computers[0].unattended.control = true;
        let mut window = Window::new(control, Page::AddressBook, egui::Theme::Light, TALL);
        assert!(
            window
                .nodes
                .iter()
                .any(|n| n.label() == Some("Turn unattended off there"))
        );
        // Unlock names the other device by its ID, confirmed in words that
        // name the computer, then the prompt.
        let unlock = window.center("Unlock another device there");
        assert!(window.click(unlock).is_empty());
        window.pass(Vec::new());
        assert!(has_text(
            &window,
            "Unlock your other device at \"Office PC\"?"
        ));
        assert!(
            window.node("Continue: the password").is_disabled(),
            "no device ID yet"
        );
        let other = tornect_core::DeviceIdentity::from_seed(&[7; 32]).id();
        window.form.ua.unlocking = Some((id, other.to_string()));
        window.pass(Vec::new());
        let go = window.center("Continue: the password");
        assert_eq!(
            window.click(go),
            vec![Action::AskUnlock(id, *other.public_key_bytes())]
        );

        // Without a success there: Knock first, and a paired computer may
        // still connect without asking.
        let fresh = with_book(false);
        let mut window = Window::new(fresh, Page::AddressBook, egui::Theme::Dark, TALL);
        let knock = window.center("Knock");
        assert_eq!(window.click(knock), vec![Action::Connect(id)]);
        let ask = window.center("Connect without asking");
        assert_eq!(window.click(ask), vec![Action::AskPassword(id)]);
        assert!(
            !window
                .nodes
                .iter()
                .any(|n| n.label() == Some("Revoke this device"))
        );

        // An unread setup change holds Connect until confirmed.
        let mut held = model;
        held.setup_changed.insert(id);
        let mut window = Window::new(held, Page::AddressBook, egui::Theme::Dark, TALL);
        assert!(window.node("Connect").is_disabled());
        assert!(has_text(&window, "unattended setup was re-created"));
        let read = window.center("I read this");
        assert_eq!(window.click(read), vec![Action::ConfirmSetupChanged(id)]);
    }

    fn prompt(id: TornectId) -> super::super::model::Prompt {
        use tornect_core::unattended::credentials::RememberOffer;
        super::super::model::Prompt {
            id,
            host: "Office PC".to_owned(),
            keychain: Some("a test keychain"),
            kept: None,
            remember: (RememberOffer::Offered, RememberOffer::NotForAdministrator),
            remembered: false,
            vanished: false,
            stale: false,
            may_admin: false,
            retry_at: None,
            admin: None,
            target: None,
        }
    }

    /// §B.8.10, §B.8.9.1, decision M1-67: the prompt is masked with a reveal
    /// toggle and "View only this time"; "Remember on this device" is off,
    /// with its risk copy and the sentence that the host's answer decides,
    /// and absent without a keychain and where the host's last answer
    /// reached administrator access, left the key out or was refused, or the
    /// level is asked for (the sentence says why); what the computer said
    /// about waiting shows before submitting.
    #[test]
    fn the_prompt_offers_remember_only_where_it_may() {
        use tornect_core::unattended::credentials::{
            NO_KEYCHAIN, RememberOffer, reach_not_remembered,
        };
        let mut model = with_book(false);
        let id = office(&model);
        model.prompt = Some(prompt(id));
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        let controls = window.controls();
        for want in [
            "Password",
            "Show",
            "View only this time",
            "Remember on this device",
        ] {
            assert!(controls.iter().any(|c| c == want), "{want}: {controls:?}");
        }
        assert!(!controls.iter().any(|c| c == "Ask for administrator access"));
        assert!(has_text(&window, "any program running as you can read it"));
        assert!(has_text(
            &window,
            "If \"Office PC\" lets your access use administrator access through Tornect, \
             the password is not remembered."
        ));
        assert!(has_text(&window, "Connect to \"Office PC\" without asking"));
        assert!(!window.form.ua.remember, "off by default");

        let mut none = model.clone();
        none.prompt.as_mut().unwrap().keychain = None;
        none.prompt.as_mut().unwrap().remember =
            (RememberOffer::NoKeychain, RememberOffer::NoKeychain);
        let window = Window::new(none, Page::Home, egui::Theme::Dark, WIDE);
        assert!(
            !window
                .controls()
                .iter()
                .any(|c| c == "Remember on this device")
        );
        assert!(has_text(&window, NO_KEYCHAIN));

        let mut admin = model.clone();
        admin.prompt.as_mut().unwrap().may_admin = true;
        let mut window = Window::new(admin, Page::Home, egui::Theme::Dark, WIDE);
        let controls = window.controls();
        assert!(controls.iter().any(|c| c == "Ask for administrator access"));
        assert!(!controls.iter().any(|c| c == "Remember on this device"));
        let reach = reach_not_remembered("\"Office PC\"");
        assert_eq!(
            reach,
            "A password that can reach administrator access on \"Office PC\", or that \
             \"Office PC\" did not rule out, is never remembered."
        );
        assert!(has_text(&window, &reach));
        // View only asks for no level: the choice goes.
        window.form.ua.administrator = true;
        window.form.ua.view_only = true;
        window.pass(Vec::new());
        assert!(
            !window
                .controls()
                .iter()
                .any(|c| c == "Ask for administrator access")
        );
        assert!(!window.form.ua.administrator);

        let mut reached = model.clone();
        reached.prompt.as_mut().unwrap().remember = (
            RememberOffer::NotForAdministrator,
            RememberOffer::NotForAdministrator,
        );
        let window = Window::new(reached, Page::Home, egui::Theme::Dark, WIDE);
        let controls = window.controls();
        assert!(!controls.iter().any(|c| c == "Remember on this device"));
        assert!(!controls.iter().any(|c| c == "Ask for administrator access"));
        assert!(has_text(&window, &reach));

        let mut waiting = model;
        waiting.prompt.as_mut().unwrap().retry_at = Some(Instant::now() + Duration::from_secs(600));
        let window = Window::new(waiting, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "asked this device to wait"));
    }

    /// F4-2: the risk copy names the Linux keychain for the account and says
    /// how long it keeps the password; a keychain that keeps it until it is
    /// deleted adds nothing.
    #[test]
    fn the_risk_copy_says_how_long_the_keychain_keeps_it() {
        use tornect_core::unattended::credentials::KEYUTILS_KEPT;
        let mut model = with_book(false);
        let id = office(&model);
        let mut linux = prompt(id);
        linux.keychain = Some("the kernel keyring of your user account");
        linux.kept = Some(KEYUTILS_KEPT);
        model.prompt = Some(linux);
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "any program running as you can read it from the kernel keyring of your user \
             account. It stays on this account until a restart, or for a few days after you \
             sign out."
        ));
        model.prompt = Some(prompt(id));
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "can read it from a test keychain."));
        assert!(!has_text(&window, "It stays on this account"));
    }

    /// I-9: when the password remembered for a computer was gone from the
    /// keychain, the prompt comes back asking for it and says why.
    #[test]
    fn the_prompt_asks_again_for_a_password_that_vanished() {
        let mut model = with_book(false);
        let id = office(&model);
        let mut again = prompt(id);
        again.vanished = true;
        model.prompt = Some(again);
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "The password remembered here is no longer in a test keychain: type it."
        ));
        assert!(window.controls().iter().any(|c| c == "Password"));
    }

    /// F4-4: the Unlock card says what it does, and once the typed device ID
    /// parses it asks once for that device's words and shows them, to compare
    /// with that device's own Home.
    #[test]
    fn the_unlock_card_shows_the_typed_devices_words() {
        let mut model = with_book(false);
        let id = office(&model);
        model.book.computers[0].unattended.worked_before = true;
        model.book.computers[0].unattended.control = true;
        let other = tornect_core::DeviceIdentity::from_seed(&[7; 32]).id();
        let key = *other.public_key_bytes();
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, TALL);
        window.form.ua.unlocking = Some((id, other.to_string()));
        assert_eq!(window.pass(Vec::new()), vec![Action::DeviceWords(key)]);
        assert!(window.pass(Vec::new()).is_empty(), "asked once");
        assert!(has_text(&window, "Working out its device words…"));
        assert!(has_text(
            &window,
            "and a suspension set from another of your devices is lifted."
        ));
        let words = tornect_core::words::Words::from_cached("economy bench equip pencil").unwrap();
        window.model.unlock_words = Some((key, words));
        window.pass(Vec::new());
        assert!(has_text(&window, &words.shown()));
        assert!(has_text(&window, address_book::UNLOCK_COMPARE));
        window.model.unlock_words = Some(([1; 32], words));
        window.pass(Vec::new());
        assert!(!has_text(&window, &words.shown()), "another key's words");
    }

    /// §B.8.10: the prompt is never shown while this screen is shared: no
    /// field and no name, only that it waits.
    #[test]
    fn the_prompt_waits_while_this_screen_is_shared() {
        let mut model = with_book(false);
        let id = office(&model);
        model.prompt = Some(prompt(id));
        model.hosted_elsewhere = true;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "The password prompt waits"));
        assert!(!window.controls().iter().any(|c| c == "Password"));
        assert!(!has_text(&window, "Office PC"));
    }

    /// §B.8.10: the prompt's Connect answers a click of the pointer only:
    /// Enter and Space never send a password, typed or remembered.
    #[test]
    fn the_prompt_sends_on_a_click_only() {
        let mut model = with_book(false);
        let id = office(&model);
        model.prompt = Some(prompt(id));
        let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(
            topmost(&window, "Connect").is_disabled(),
            "nothing typed yet"
        );
        window.form.ua.password = zeroize::Zeroizing::new("quiet verdant otter".to_owned());
        window.pass(Vec::new());
        let field = window.center("Password");
        assert!(window.click(field).is_empty());
        for key in [
            egui::Key::Enter,
            egui::Key::Space,
            egui::Key::Tab,
            egui::Key::Enter,
        ] {
            assert!(window.key(key).is_empty(), "{key:?} sent nothing");
        }
        let connect = centres(&window, "Connect")[0];
        assert_eq!(
            window.click(connect),
            vec![Action::SubmitPrompt { pointer: true }]
        );
        // egui keeps no undo copy of the password; the field's state goes
        // with the prompt.
        let field_id = egui::Id::new("unattended-password");
        let state = egui::text_edit::TextEditState::load(&window.ctx, field_id)
            .expect("the field's state while the prompt is open");
        let undoer = state.undoer();
        assert!(!undoer.is_in_flux(), "no copy in flux");
        assert!(
            format!("{undoer:?}").contains("undo count: 0"),
            "{undoer:?}"
        );
        window.model.prompt = None;
        window.pass(Vec::new());
        assert!(egui::text_edit::TextEditState::load(&window.ctx, field_id).is_none());
        // A remembered password: Connect is live without typing, and still
        // answers the pointer only.
        model.prompt.as_mut().unwrap().remembered = true;
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "The password remembered in a test keychain is used."
        ));
        assert!(!window.controls().iter().any(|c| c == "Password"));
        assert!(!topmost(&window, "Connect").is_disabled());
        for key in [egui::Key::Enter, egui::Key::Space] {
            assert!(window.key(key).is_empty(), "{key:?} sent nothing");
        }
    }

    /// §B.8.10: the unattended stepper's own steps (the password, then the
    /// computer's checks, generic, no countdown; no direct path in this
    /// version), the badge from the signed accept, the failed attempts, and
    /// the withheld level, naming the computer only while not shared.
    #[test]
    fn the_unattended_stepper_and_badge() {
        use super::super::model::{ClientStage, Dial, StreamInfo, UaLive, Viewing};
        let mut model = with_book(false);
        let id = office(&model);
        model.dial = Dial {
            id: Some(id),
            since: Some(Instant::now()),
            paired_now: false,
            failed: None,
            unattended: true,
            went_live: false,
        };
        model.client = ClientStage::Checking;
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        for said in [
            "Checking the password",
            "Someone at the computer can still block this, or must allow it",
            "No direct path in this version: relayed through Tor",
        ] {
            assert!(has_text(&window, said), "{said}");
        }
        model.client = ClientStage::Live(Viewing {
            host: "Office PC".to_owned(),
            control: true,
            administrator: false,
            unattended: true,
            since: Instant::now(),
            pictures: 0,
            size: (0, 0),
            stream: StreamInfo::default(),
        });
        model.ua_live = Some(UaLive {
            withheld: true,
            fail_summary: Some("3 failed attempts since your last login".to_owned()),
        });
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "Unattended · Control"));
        assert!(has_text(&window, "3 failed attempts since your last login"));
        assert!(has_text(
            &window,
            "Administrator access unavailable at \"Office PC\""
        ));
        model.hosted_elsewhere = true;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "Administrator access unavailable at the computer"
        ));
        assert!(!has_text(&window, "Office PC"));
    }

    /// Days read as people say them: today, yesterday, within a week, else a
    /// date.
    #[test]
    fn days_read_as_people_say_them() {
        let today: Day = "2026-09-27".parse().unwrap();
        let ago = |n: i64| Day::from_days(today.days() - n);
        assert_eq!(day_text(ago(0), Some(today)), "Today");
        assert_eq!(day_text(ago(1), Some(today)), "Yesterday");
        assert_eq!(day_text(ago(6), Some(today)), "6 days ago");
        assert_eq!(day_text(ago(7), Some(today)), "20 Sep 2026");
        assert_eq!(day_text(ago(0), None), "27 Sep 2026");
        assert_eq!(day_in_sentence(ago(1), Some(today)), "yesterday");
        assert_eq!(day_in_sentence(ago(30), Some(today)), "on 28 Aug 2026");
    }

    /// A window at rest with one host sheet of `sheet`'s kind (the preview's
    /// invented words).
    fn with_sheet(sheet: super::super::preview::Sheet) -> Model {
        let mut model = at_rest();
        super::super::preview::sheet(&mut model, sheet);
        model
    }

    /// §B.6.1 on the sheets, in both themes, at both sizes: an unpinned key
    /// is named by its device words, "not yet trusted · compare the code",
    /// in their labelled slot; a pinned key by its saved name, without that
    /// line; no hex fingerprint on any sheet (W-B7); the answers as before.
    #[test]
    fn the_sheets_show_words_or_the_saved_name_and_no_fingerprint() {
        use super::super::preview::Sheet;
        for theme in THEMES {
            for size in [WIDE, NARROW] {
                let case = format!("{theme:?} {size:?}");
                let new = Window::new(with_sheet(Sheet::New), Page::Settings, theme, size);
                assert!(
                    has_text(
                        &new,
                        "device words: absurd · citizen · dinner · harvest · not yet trusted · \
                         compare the code"
                    ),
                    "{case}"
                );
                assert!(has_text(&new, "calling itself \"Laptop\""), "{case}");
                assert!(has_text(&new, "482 917"), "{case}: the code");
                assert!(new.controls().iter().any(|c| c == "The codes match: pair"));
                assert!(new.controls().iter().any(|c| c == "Refuse"));
                let pinned = Window::new(with_sheet(Sheet::Pinned), Page::Settings, theme, size);
                assert!(has_text(&pinned, "ALREADY PAIRED as \"Laptop\""), "{case}");
                assert!(!has_text(&pinned, "not yet trusted"), "{case}");
                assert!(
                    !has_text(&pinned, "orbit"),
                    "{case}: no words beside a name"
                );
                let session = Window::new(with_sheet(Sheet::Session), Page::Settings, theme, size);
                assert!(
                    has_text(&session, "\"Laptop\" wants to see this screen."),
                    "{case}"
                );
                assert!(session.controls().iter().any(|c| c == "Deny"));
                for window in [&new, &pinned, &session] {
                    assert!(!has_text(window, "fingerprint"), "{case}");
                }
            }
        }
    }

    /// W-B3 in the window: when the alarm fired, the sheet says so in red,
    /// hides this computer's own code and shows no accept button; keys alone
    /// never pair; the six digits typed into its field, then Enter, ask the
    /// host to check them (the check itself: `recognize::tests`).
    #[test]
    fn a_fired_alarm_asks_for_the_typed_code_not_a_click() {
        use super::super::preview::Sheet;
        use tornect_signal::pairing::PairDecision;
        for theme in THEMES {
            let mut window = Window::new(with_sheet(Sheet::Alarm), Page::Settings, theme, WIDE);
            assert!(has_text(
                &window,
                "Looks like your saved device \"Office PC\", but it is a different device"
            ));
            assert!(!has_text(&window, "482 917"), "its own code is hidden");
            assert!(
                !window
                    .controls()
                    .iter()
                    .any(|c| c == "The codes match: pair")
            );
            for key in [
                egui::Key::Tab,
                egui::Key::Tab,
                egui::Key::Enter,
                egui::Key::Space,
            ] {
                let asked = window.key(key);
                assert!(
                    !asked.iter().any(|a| matches!(
                        a,
                        Action::Pair {
                            decision: PairDecision::Accept { .. },
                            ..
                        } | Action::PairCode { .. }
                    )),
                    "{asked:?}"
                );
            }
            // A fresh window for the typing (the keys above moved the focus).
            let mut window = Window::new(with_sheet(Sheet::Alarm), Page::Settings, theme, WIDE);
            window.later += Duration::from_secs(2);
            window.pass(Vec::new());
            let field = window
                .nodes
                .iter()
                .filter(|n| n.role() == Role::TextInput)
                .filter_map(Node::bounds)
                // Below the name field.
                .max_by(|a, b| a.y0.total_cmp(&b.y0))
                .expect("the code field");
            let at = egui::pos2(
                ((field.x0 + field.x1) / 2.0) as f32,
                ((field.y0 + field.y1) / 2.0) as f32,
            );
            // What typing puts in the field (as the other page tests do), a
            // click to focus it, then Enter.
            window.form.codes.insert(7, "482 917".to_owned());
            window.pass(Vec::new());
            assert!(window.click(at).is_empty(), "a click only focuses it");
            let asked = window.key(egui::Key::Enter);
            assert_eq!(
                asked,
                vec![Action::PairCode {
                    id: 7,
                    code: "482 917".to_owned(),
                    label: Some("Office PC".to_owned()),
                }],
                "{theme:?}"
            );
        }
    }

    /// Home's ID card leads with the words a host's sheet shows when this
    /// computer connects, the address's own under it, the help line; none
    /// of them while this computer is shared (R-W2), in the address book
    /// neither.
    #[test]
    fn the_id_card_shows_both_word_sets_except_while_shared() {
        for theme in THEMES {
            let mut model = with_book(false);
            model.mine = super::super::preview::model(false, false).mine;
            let window = Window::new(model.clone(), Page::Home, theme, WIDE);
            assert!(has_text(
                &window,
                "When you connect to another computer, it shows: orient · walk · nice · rally"
            ));
            assert!(has_text(
                &window,
                "this address: treat · fame · transfer · pride"
            ));
            assert!(has_text(
                &window,
                "Device words help you recognise a device."
            ));
            assert!(has_text(&window, "not a secret or a password"));
            let mut shared = model;
            shared.sharing = vec![super::super::model::Sharing {
                session_id: "00".to_owned(),
                label: "Laptop".to_owned(),
                control: false,
                unattended: false,
                since: Instant::now(),
                capture: None,
            }];
            for page in [Page::Home, Page::AddressBook] {
                let window = Window::new(shared.clone(), page, theme, WIDE);
                for words in ["orient · walk", "treat · fame", "arctic · crisp"] {
                    assert!(!has_text(&window, words), "{page:?}: {words}");
                }
                assert!(has_text(
                    &window,
                    "Device words are hidden while this computer is shared."
                ));
            }
            let book = Window::new(with_book(false), Page::AddressBook, theme, WIDE);
            assert!(
                has_text(&book, "arctic · crisp · lamp · orbit"),
                "the selected computer's words"
            );
            assert!(!has_text(&book, "Host key"));
        }
    }

    /// The connect field's warning (§B.6.1 item 4): an ID that looks like a
    /// saved one is named in red, and Connect becomes "Connect anyway", a
    /// second, deliberate click; Enter in the field does not take it.
    #[test]
    fn a_look_alike_id_takes_a_second_click() {
        let id: TornectId = TornectId::from_bytes([0x66; 32]);
        let mut model = with_book(false);
        model.connect_warning = Some(super::super::model::ConnectWarning {
            id,
            name: "Office PC".to_owned(),
        });
        let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        window.form.connect_to = id.onion_address();
        window.pass(Vec::new());
        assert!(has_text(
            &window,
            "Looks like your saved \"Office PC\", but it is a different address."
        ));
        let anyway = window.center("Connect anyway");
        assert_eq!(window.click(anyway), vec![Action::ConnectAnyway(id)]);
    }

    /// The bounds of the last widget labelled `label`: on the request sheet,
    /// the newest card's.
    fn last_bounds(window: &Window, label: &str) -> egui::accesskit::Rect {
        window
            .nodes
            .iter()
            .filter(|n| n.label() == Some(label))
            .filter_map(Node::bounds)
            .next_back()
            .unwrap_or_else(|| panic!("no \"{label}\" on screen"))
    }

    fn session_question(id: u64, label: &str) -> Popup {
        Popup {
            id,
            kind: PopupKind::Session {
                label: label.to_owned(),
                fingerprint: "ab:cd".to_owned(),
            },
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    fn pairing_question(id: u64) -> Popup {
        Popup {
            id,
            kind: PopupKind::Pairing {
                name: "Phone".to_owned(),
                fingerprint: "ef:01".to_owned(),
                sas: "123 456".to_owned(),
                pinned: None,
            },
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    /// The request sheet with two and three open questions, at both sizes:
    /// the one card shown (the oldest: one question at a time) has its Deny
    /// and accepts inside the sheet's room, under the waiting line; and when
    /// the room shrinks, they are brought back into view.
    #[test]
    fn the_newest_questions_answers_stay_in_view() {
        for size in [WIDE, NARROW] {
            for questions in [
                vec![session_question(1, "Laptop"), pairing_question(2)],
                vec![
                    session_question(1, "Laptop"),
                    pairing_question(2),
                    session_question(3, "Tablet"),
                ],
            ] {
                let open = questions.len();
                let mut model = at_rest();
                model.popups = questions;
                let mut window = Window::new(model, Page::Home, egui::Theme::Dark, size);
                assert!(has_text(&window, &format!("{} more waiting", open - 1)));
                for height in [size.1, size.1 - 220.0] {
                    window.size.y = height;
                    for _ in 0..3 {
                        assert!(window.pass(Vec::new()).is_empty());
                    }
                    for label in ["Deny", "View only", "Allow control"] {
                        let b = last_bounds(&window, label);
                        assert!(
                            b.y0 >= 0.0
                                && b.y1 <= f64::from(height) - 16.0
                                && b.x0 >= 0.0
                                && b.x1 <= f64::from(size.0),
                            "{size:?} {open} questions, {height} high: {label} at {b:?}"
                        );
                    }
                }
            }
        }
    }

    /// The banner stays above the request sheet's scrim, and live: its Stop
    /// answers a click while a question is open and is the keyboard's first
    /// stop, the question's Deny the next; the sidebar and the page under
    /// the scrim take no click.
    #[test]
    fn the_banner_stays_above_the_request_sheet() {
        let mut model = at_rest();
        model.sharing = vec![super::super::model::Sharing {
            session_id: "00".to_owned(),
            label: "Laptop".to_owned(),
            control: true,
            unattended: false,
            since: Instant::now(),
            capture: None,
        }];
        model.popups = vec![session_question(9, "Tablet")];
        for size in [WIDE, NARROW] {
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            let settings = window.center(Page::Settings.title());
            assert!(window.click(settings).is_empty(), "{size:?}");
            assert_eq!(window.form.page, Page::Home, "the sidebar under the scrim");
            let stop = window.center("Stop sharing");
            assert_eq!(window.click(stop), vec![Action::StopSharing], "{size:?}");
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            window.key(egui::Key::Tab);
            assert_eq!(
                window.key(egui::Key::Space),
                vec![Action::StopSharing],
                "{size:?}: the banner's Stop first"
            );
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            window.key(egui::Key::Tab);
            window.key(egui::Key::Tab);
            assert_eq!(
                window.key(egui::Key::Space),
                vec![Action::Session {
                    id: 9,
                    decision: SessionDecision::Deny,
                    pointer: false,
                }],
                "{size:?}: then the sheet's Deny"
            );
        }
    }

    /// The code field of a sheet whose alarm fired never takes the focus by
    /// itself: a sheet that appears while the connect field has it leaves it
    /// there, and typing goes on into that field.
    #[test]
    fn a_code_field_never_takes_the_focus() {
        use super::super::preview::Sheet;
        let mut window = Window::new(at_rest(), Page::Home, egui::Theme::Dark, WIDE);
        let field = window
            .nodes
            .iter()
            .find(|n| n.role() == Role::TextInput)
            .and_then(Node::bounds)
            .expect("the connect field");
        let at = egui::pos2(
            ((field.x0 + field.x1) / 2.0) as f32,
            ((field.y0 + field.y1) / 2.0) as f32,
        );
        assert!(window.click(at).is_empty());
        window.pass(vec![egui::Event::Text("ab".to_owned())]);
        assert_eq!(window.form.connect_to, "ab");
        let alarmed = with_sheet(Sheet::Alarm);
        window.model.popups = alarmed.popups;
        window.model.recognition = alarmed.recognition;
        window.later += Duration::from_secs(2);
        for _ in 0..2 {
            assert!(window.pass(Vec::new()).is_empty());
        }
        assert!(has_text(&window, "Looks like your saved device"));
        window.pass(vec![egui::Event::Text("5".to_owned())]);
        assert_eq!(window.form.connect_to, "ab5");
        assert!(window.form.codes.values().all(String::is_empty));
    }

    /// P-M2 and R-3a: while this computer's screen may be in a picture that
    /// leaves it — a session live, one just allowed (before the accept goes
    /// out), or another Tornect process holding the host lock — Home and
    /// every tab of the address book (Devices included) show no saved name,
    /// no ID prefix, no day, no recent or device line and nothing of what
    /// happened, and say that they are hidden; the connect field's look-alike
    /// warning names no saved computer (FW-L1).
    #[test]
    fn sharing_hides_the_book() {
        let base = with_book(false);
        let names: Vec<String> = base
            .book
            .computers
            .iter()
            .map(|c| c.title())
            .chain(base.book.devices.iter().map(|d| d.label.clone()))
            .collect();
        assert!(names.len() >= 6, "{names:?}");
        let prefixes: Vec<String> = base.book.computers.iter().map(|c| c.id.short()).collect();
        let look_alike = TornectId::from_bytes([0x66; 32]);
        let viewer = super::super::model::Sharing {
            session_id: "00".to_owned(),
            label: "Viewer".to_owned(),
            control: false,
            unattended: false,
            since: Instant::now(),
            capture: None,
        };
        type Set = Box<dyn Fn(&mut Model)>;
        let states: [(&str, Set); 3] = [
            ("live", Box::new(move |m| m.sharing = vec![viewer.clone()])),
            ("allowed", Box::new(|m| m.accepted = Some(Instant::now()))),
            ("elsewhere", Box::new(|m| m.hosted_elsewhere = true)),
        ];
        // Unshared, the same pages show what the test looks for.
        let open = Window::new(base.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&open, "Office PC") && has_text(&open, "Last connected"));
        for (case, set) in &states {
            let mut model = base.clone();
            set(&mut model);
            model.connect_warning = Some(super::super::model::ConnectWarning {
                id: look_alike,
                name: "Office PC".to_owned(),
            });
            for theme in THEMES {
                for (page, tab) in [
                    (Page::Home, Tab::Computers),
                    (Page::AddressBook, Tab::Computers),
                    (Page::AddressBook, Tab::Recent),
                    (Page::AddressBook, Tab::Devices),
                ] {
                    let mut window = Window::new(model.clone(), page, theme, WIDE);
                    window.form.book.tab = tab;
                    window.form.connect_to = look_alike.onion_address();
                    window.pass(Vec::new());
                    window.pass(Vec::new());
                    let at = format!("{case} {theme:?} {page:?} {tab:?}");
                    for name in &names {
                        assert!(!has_text(&window, name), "{at}: {name}");
                    }
                    for prefix in &prefixes {
                        assert!(!has_text(&window, prefix), "{at}: {prefix}");
                    }
                    for day in [
                        "Today",
                        "Yesterday",
                        "days ago",
                        "Last connected",
                        "last request",
                        "something happened",
                    ] {
                        assert!(!has_text(&window, day), "{at}: {day}");
                    }
                    assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{at}");
                    if page == Page::Home {
                        assert!(
                            has_text(
                                &window,
                                "Looks like a saved computer, but it is a different address."
                            ),
                            "{at}"
                        );
                    }
                }
            }
        }
    }

    /// R-3b: a session sheet names the device by its pinned label and hints
    /// at nothing else: not that a computer of the same name is saved in this
    /// computer's address book.
    #[test]
    fn a_sheet_never_hints_at_the_book() {
        let mut model = with_book(false);
        model.popups = vec![session_question(9, "Office PC")];
        for size in [WIDE, NARROW] {
            let window = Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
            assert!(has_text(
                &window,
                "\"Office PC\" wants to connect to this computer"
            ));
            for hint in [
                "saved",
                "address book",
                "Address book",
                "Last connected",
                "book",
            ] {
                let found: Vec<&str> = window
                    .nodes
                    .iter()
                    .filter_map(|n| n.value())
                    .filter(|v| v.contains(hint))
                    .collect();
                assert!(found.is_empty(), "{size:?}: {hint} in {found:?}");
            }
        }
    }

    /// The connect stepper: the four steps and the one the connection is on,
    /// the code on step 2 while pairing, the level from the signed accept once
    /// live, and every error of the taxonomy in plain words, with Try again
    /// (the same ID) and Back; the dialed ID is never shown while this
    /// screen is shared, nor a host's name.
    #[test]
    fn the_connect_stepper_says_where_it_is_and_why_it_stopped() {
        use super::super::model::{ClientStage, Dial, Failure, StreamInfo, Viewing};
        let id = TornectId::from_bytes([0x42; 32]);
        let dial = |failed| Dial {
            id: Some(id),
            since: Some(Instant::now()),
            paired_now: true,
            failed,
            unattended: false,
            went_live: false,
        };
        let steps = [
            "Reaching the computer over Tor",
            "Pairing: compare the code",
            "Waiting for approval",
            "Opening the picture",
        ];
        for stage in [
            ClientStage::Reaching {
                id: id.display_groups(),
            },
            ClientStage::Pairing {
                sas: "305 116".to_owned(),
            },
            ClientStage::Asking,
        ] {
            let mut model = at_rest();
            model.client = stage.clone();
            model.dial = dial(None);
            let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
            assert!(has_text(&window, "Connecting to a computer"), "{stage:?}");
            for step in steps {
                assert!(has_text(&window, step), "{stage:?}: {step}");
            }
            assert!(has_text(&window, &id.display_groups()), "{stage:?}");
            assert!(window.node("Cancel").bounds().is_some());
            if matches!(stage, ClientStage::Pairing { .. }) {
                assert!(has_text(&window, "305 116"));
            }
        }
        let mut live = at_rest();
        live.client = ClientStage::Live(Viewing {
            host: "Desk".to_owned(),
            control: true,
            administrator: true,
            unattended: false,
            since: Instant::now(),
            pictures: 1,
            size: (1280, 720),
            stream: StreamInfo::default(),
        });
        live.dial = dial(None);
        let window = Window::new(live.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(
            &window,
            "Connected to \"Desk\" (Control · administrator): the picture is in its own window."
        ));
        for (failure, step) in [
            (Failure::Unreachable, 1),
            (Failure::CodesDiffer, 2),
            (Failure::Denied, 3),
            (Failure::TimedOut, 3),
            (Failure::VersionMismatch, 1),
        ] {
            let mut model = at_rest();
            model.client = ClientStage::Ended("the stage's own words".to_owned());
            model.dial = dial(Some((failure, step)));
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
            assert!(has_text(&window, failure.title()), "{failure:?}");
            assert!(has_text(&window, failure.advice()), "{failure:?}");
            assert!(has_text(&window, "the stage's own words"), "{failure:?}");
            let again = window.center("Try again");
            assert_eq!(
                window.click(again),
                vec![Action::Connect(id)],
                "{failure:?}"
            );
            let back = window.center("Back");
            assert_eq!(
                window.click(back),
                vec![Action::DismissConnect],
                "{failure:?}"
            );
            // Shared: neither the ID nor the stage's words (they may name
            // the host).
            model.sharing = vec![super::super::model::Sharing {
                session_id: "00".to_owned(),
                label: "Viewer".to_owned(),
                control: false,
                unattended: false,
                since: Instant::now(),
                capture: None,
            }];
            let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
            assert!(!has_text(&window, &id.display_groups()), "{failure:?}");
            assert!(!has_text(&window, "the stage's own words"), "{failure:?}");
            assert!(has_text(&window, failure.title()), "{failure:?}");
        }
        live.sharing = vec![super::super::model::Sharing {
            session_id: "00".to_owned(),
            label: "Viewer".to_owned(),
            control: false,
            unattended: false,
            since: Instant::now(),
            capture: None,
        }];
        let window = Window::new(live, Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, "Desk"));
        assert!(has_text(&window, "(Control · administrator)"));
    }

    /// B25: a dial cancelled before its session, or one that ended early
    /// with nothing classified, never reads as a session that ran: no "The
    /// session ended" and no step ticked past where it stopped; a cancel
    /// says "Cancelled". Only a dial that went live and ended reads "The
    /// session ended" with every step done.
    #[test]
    fn a_cancelled_dial_is_not_a_session_that_ended() {
        use super::super::model::{ClientStage, Dial, Failure};
        let id = TornectId::from_bytes([0x42; 32]);
        let dial = |failed, went_live| Dial {
            id: Some(id),
            since: Some(Instant::now()),
            paired_now: true,
            failed,
            unattended: false,
            went_live,
        };
        let ticked = |window: &Window| -> Vec<u8> {
            (1..=4)
                .filter(|n| has_text(window, &format!("✓ {n}")))
                .collect()
        };
        for (failed, words, done) in [
            (Some((Failure::Cancelled, 1)), "Cancelled.", vec![]),
            (
                Some((Failure::Cancelled, 3)),
                "Cancelled before the session started.",
                vec![1, 2],
            ),
            (None, "Cancelled.", vec![]),
        ] {
            let mut model = at_rest();
            model.client = ClientStage::Ended(words.to_owned());
            model.dial = dial(failed, false);
            let mut window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
            assert!(!has_text(&window, "The session ended"), "{failed:?}");
            assert!(has_text(&window, "Not connected"), "{failed:?}");
            assert_eq!(ticked(&window), done, "{failed:?}");
            if failed.is_some() {
                assert!(has_text(&window, Failure::Cancelled.title()));
                assert!(has_text(&window, Failure::Cancelled.advice()));
            }
            let again = window.center("Try again");
            assert_eq!(window.click(again), vec![Action::Connect(id)]);
        }
        let mut ended = at_rest();
        ended.client = ClientStage::Ended("Session with \"Desk\" ended (by you).".to_owned());
        ended.dial = dial(None, true);
        let window = Window::new(ended, Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, "The session ended"));
        assert_eq!(ticked(&window), vec![1, 2, 3, 4]);
    }

    /// The first run says once that no recent list is kept unless history
    /// is switched on, that pairings are always kept, and that the session
    /// log records connection attempts in both directions (the operator's
    /// rulings of 2026-09-29, F4-M1); not on a later run, and not once
    /// history is on.
    #[test]
    fn the_first_run_says_history_is_off() {
        let notice = home::HISTORY_NOTICE;
        assert_eq!(
            notice,
            "Tornect keeps no list of your recent connections unless you switch history on \
             (Address book, Recent). Pairings are always kept. The session log on this computer \
             always records connection attempts in both directions: requests to this computer, \
             and your unattended connections to others. It is never sent anywhere."
        );
        let mut model = with_book(false);
        model.book.history = false;
        model.history_notice = true;
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, notice));
        model.history_notice = false;
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, notice), "a later run");
        model.history_notice = true;
        model.book.history = true;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, notice), "history is on");
    }

    /// F4-M1: the Recent tab with history off and Forget's confirmation say
    /// that the session log is kept either way, and Forget says what it
    /// removes (the remembered password too) and what stays.
    #[test]
    fn the_history_texts_name_the_session_log() {
        let mut model = with_book(false);
        model.book.history = false;
        let id = office(&model);
        let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, WIDE);
        window.form.book.tab = Tab::Recent;
        window.pass(Vec::new());
        assert_eq!(
            address_book::HISTORY_OFF,
            "Off: no list of recent connections is kept. Switched on, it keeps the day of each \
             connection (never the time) and each computer's last-connected day, only on this \
             computer; anything kept before stays until you clear it. The switch does not cover \
             the session log: it always records requests to this computer, and your unattended \
             connections to others, with their time, on this computer only."
        );
        assert!(has_text(&window, address_book::HISTORY_OFF));
        window.form.book.tab = Tab::Computers;
        window.form.book.forgetting = Some(id);
        window.pass(Vec::new());
        let question = address_book::forget_question("Office PC");
        assert_eq!(
            question,
            "Forget \"Office PC\"? Its pairing, name, recent connections and remembered password \
             go; the next connection compares a code again."
        );
        assert!(has_text(&window, &question));
        assert_eq!(
            address_book::FORGET_KEEPS,
            "Its lines in the session log stay: the session log always records requests to this \
             computer, and your unattended connections to others."
        );
        assert!(has_text(&window, address_book::FORGET_KEEPS));
    }

    /// Every preview sheet and stage draws in both themes at both sizes
    /// without asking for anything; on every host sheet the first answer the
    /// keyboard reaches is a refusal (Deny or Refuse) that answers at once,
    /// and no run of Tabs followed by Space or Enter ever gives an accept
    /// (M1-50).
    #[test]
    fn every_sheet_draws_and_keys_only_refuse() {
        use super::super::preview::Sheet;
        use tornect_signal::pairing::PairDecision;
        let sheets = [
            Sheet::New,
            Sheet::Pinned,
            Sheet::Alarm,
            Sheet::Session,
            Sheet::SessionLinux,
            Sheet::SessionAdmin,
            Sheet::AdminConfirm,
            Sheet::SessionWindows,
            Sheet::SessionFour,
            Sheet::AdminNotGiven,
            Sheet::SessionNoPrompt,
            Sheet::TwoOpen,
            Sheet::StageReaching,
            Sheet::StagePairing,
            Sheet::StageAsking,
            Sheet::StageLive,
            Sheet::StageUnreachable,
            Sheet::StageDenied,
            Sheet::StageCodesDiffer,
            Sheet::UaCard,
            Sheet::UaPrompt,
            Sheet::UaRefused,
            Sheet::UaLive,
        ];
        let accepts = |actions: &[Action]| {
            actions.iter().any(|a| {
                matches!(
                    a,
                    Action::Session {
                        decision: SessionDecision::AllowOnce
                            | SessionDecision::AllowOnceViewOnly
                            | SessionDecision::AllowOnceAdmin,
                        ..
                    } | Action::Pair {
                        decision: PairDecision::Accept { .. },
                        ..
                    } | Action::PairCode { .. }
                        | Action::Confirm { matched: true, .. }
                        | Action::AdminConfirm { .. }
                        | Action::AdminPrompt { .. }
                        | Action::SubmitPrompt { .. }
                )
            })
        };
        for sheet in sheets {
            for theme in THEMES {
                for size in [WIDE, NARROW] {
                    let model = with_sheet(sheet);
                    let hosts = !model.popups.is_empty();
                    let mut window = Window::new(model.clone(), Page::Home, theme, size);
                    let case = format!("{sheet:?} {theme:?} {size:?}");
                    if hosts {
                        // The first answer the keyboard reaches is a refusal
                        // (a pairing sheet's name field comes before it).
                        let mut refused = Vec::new();
                        for tabs in 1..=3 {
                            let mut fresh = Window::new(model.clone(), Page::Home, theme, size);
                            for _ in 0..tabs {
                                fresh.key(egui::Key::Tab);
                            }
                            refused = fresh.key(egui::Key::Space);
                            if !refused.is_empty() {
                                break;
                            }
                        }
                        window.pass(Vec::new());
                        assert!(
                            matches!(
                                refused.as_slice(),
                                [Action::Session {
                                    decision: SessionDecision::Deny,
                                    pointer: false,
                                    ..
                                }] | [Action::Pair {
                                    decision: PairDecision::Reject,
                                    pointer: false,
                                    ..
                                }]
                            ),
                            "{case}: {refused:?}"
                        );
                    }
                    for confirm in [egui::Key::Space, egui::Key::Enter] {
                        for tabs in 1..=8 {
                            let mut window = Window::new(model.clone(), Page::Home, theme, size);
                            let mut asked = Vec::new();
                            for _ in 0..tabs {
                                asked.extend(window.key(egui::Key::Tab));
                            }
                            asked.extend(window.key(confirm));
                            assert!(
                                !accepts(&asked),
                                "{case}: {tabs} Tabs, {confirm:?}: {asked:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// §B.8.6.2, TM-28: the banner counts the devices that can connect without
    /// asking and names the last change and who made it, above every page,
    /// until that change is acknowledged (a newer change shows it again); its
    /// one control asks for the acknowledgement; with nobody able to connect
    /// without asking there is none.
    #[test]
    fn the_banner_counts_grants_until_acknowledged() {
        use super::super::model::UnattendedBanner;
        let today = Day::today();
        let (y, m, d) = today.ymd();
        let at = format!("{y:04}-{m:02}-{d:02}T09:30:00Z");
        let banner = UnattendedBanner::of(2, Some((at.clone(), "cli")), None).expect("shown");
        assert_eq!(
            banner.line(Some(today)),
            "2 devices can connect without asking — last change today by cli"
        );
        assert_eq!(
            UnattendedBanner::of(1, None, None)
                .unwrap()
                .line(Some(today)),
            "1 device can connect without asking"
        );
        assert_eq!(
            UnattendedBanner::of(0, Some((at.clone(), "ui")), None),
            None
        );
        assert_eq!(
            UnattendedBanner::of(2, Some((at.clone(), "cli")), Some(&at)),
            None
        );
        let later = format!("{y:04}-{m:02}-{d:02}T10:00:00Z");
        assert!(UnattendedBanner::of(3, Some((later, "import")), Some(&at)).is_some());

        for page in PAGES {
            let mut model = at_rest();
            model.unattended_banner = Some(banner.clone());
            let mut window = Window::new(model, page, egui::Theme::Dark, WIDE);
            assert!(
                window.nodes.iter().any(|n| n.value()
                    == Some("2 devices can connect without asking — last change today by cli")),
                "{page:?}: no banner"
            );
            let ack = window.center("Acknowledge…");
            assert_eq!(
                window.click(ack),
                vec![Action::AcknowledgeBanner],
                "{page:?}"
            );
            let none = Window::new(at_rest(), page, egui::Theme::Dark, WIDE);
            assert!(
                !none.nodes.iter().any(|n| n.label() == Some("Acknowledge…")),
                "{page:?}"
            );
        }
    }

    /// The controls the sidebar and the banner offer over `model` (the
    /// Sessions page draws only "Open log folder", and that only when not shared).
    fn chrome_controls(model: &Model, size: (f32, f32)) -> Vec<String> {
        Window::new(model.clone(), Page::Sessions, egui::Theme::Dark, size).controls()
    }

    /// The settings page lists the sections built so far, in the redesign's
    /// order, opens on General, and asks for nothing when it or a section is
    /// opened; General's controls each send one change of the settings file,
    /// never an operation of §B.8.6.2.
    #[test]
    fn the_settings_page_lists_its_sections() {
        use super::super::model::SettingsChange;
        use tornect_core::config::Theme;
        let titles: Vec<&str> = settings::Section::LISTED
            .iter()
            .map(|s| s.title())
            .collect();
        assert_eq!(
            titles,
            [
                "General",
                "Connection",
                "Security",
                "Display and quality",
                "Privacy",
                "About"
            ]
        );
        for size in [WIDE, NARROW] {
            let mut window = Window::new(at_rest(), Page::Settings, egui::Theme::Dark, size);
            assert_eq!(window.form.settings.section, settings::Section::General);
            for section in settings::Section::LISTED {
                let title = &section.label(size == NARROW);
                assert!(
                    window.controls().iter().any(|c| c == title),
                    "{size:?}: {title}"
                );
                let right = window.node(title).bounds().expect("bounds").x1;
                assert!(
                    right <= f64::from(size.0),
                    "{size:?}: {title} ends at {right}"
                );
                let at = window.center(title);
                assert!(window.click(at).is_empty(), "{size:?}: {title}");
                assert_eq!(window.form.settings.section, section, "{size:?}");
            }
            let at = window.center("General");
            assert!(window.click(at).is_empty(), "{size:?}");
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            for text in [
                "Name others see",
                settings::general::NAME_NOTE,
                settings::general::NEXT_START,
                "Theme",
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            for (_, choice) in settings::general::THEMES {
                assert!(
                    window.controls().iter().any(|c| c == choice),
                    "{size:?}: {choice}"
                );
            }
            let light = window.center("Light");
            assert_eq!(
                window.click(light),
                vec![Action::SaveSettings(SettingsChange::Theme(Theme::Light))],
                "{size:?}"
            );
            let change = window.center("Change");
            assert!(window.click(change).is_empty(), "{size:?}");
            // What typing puts in the field (as the other page tests do).
            window.form.settings.name = Some("Desk by the window".to_owned());
            window.pass(Vec::new());
            let save = window.center("Save");
            assert_eq!(
                window.click(save),
                vec![Action::SaveSettings(SettingsChange::DeviceName(
                    "Desk by the window".to_owned()
                ))],
                "{size:?}"
            );
            assert_eq!(
                window.form.settings.name, None,
                "{size:?}: the field closes"
            );
        }
    }

    /// Settings, General: the name others see is the saved one, shown and put
    /// into the field exactly as saved; on a fresh configuration that is the
    /// neutral default ("Linux PC", "Windows PC"), never this computer's
    /// network name. The host name here is invented and planted where the
    /// window keeps the name in use, not read: no settings file asks for a
    /// host name, so a computer named like the default cannot make this pass
    /// or fail.
    #[test]
    fn the_name_field_starts_neutral_and_never_shows_the_host_name() {
        use super::super::model::Settings;
        let neutral = if cfg!(windows) {
            "Windows PC"
        } else if cfg!(target_os = "linux") {
            "Linux PC"
        } else {
            return;
        };
        let planted_host = "quillmere-desk-4821";
        let stored = "Brightwater studio 7731";
        let fresh = Settings::of(&tornect_core::Config::default());
        let chosen = Settings {
            device_name: stored.to_owned(),
            ..Settings::default()
        };
        for (saved, expected) in [(fresh, neutral), (chosen, stored)] {
            let mut model = at_rest();
            model.device_name = planted_host.to_owned();
            model.settings = saved;
            for size in [WIDE, NARROW] {
                let mut window =
                    Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
                let case = format!("{expected} {size:?}");
                assert!(
                    has_text(&window, &format!("\u{201c}{expected}\u{201d}")),
                    "{case}"
                );
                let change = window.center("Change");
                assert!(window.click(change).is_empty(), "{case}");
                assert_eq!(
                    window.form.settings.name.as_deref(),
                    Some(expected),
                    "{case}"
                );
                // The field is drawn from the next pass on.
                assert!(window.pass(Vec::new()).is_empty(), "{case}");
                let fields: Vec<&str> = window
                    .nodes
                    .iter()
                    .filter(|n| n.role() == Role::TextInput)
                    .filter_map(Node::value)
                    .collect();
                assert_eq!(fields, [expected], "{case}");
                assert!(
                    !window.nodes.iter().any(|n| {
                        [n.value(), n.label(), n.placeholder()]
                            .into_iter()
                            .flatten()
                            .any(|v| v.contains(planted_host))
                    }),
                    "{case}"
                );
            }
        }
        for source in [
            include_str!("settings/mod.rs"),
            include_str!("settings/general.rs"),
        ] {
            assert!(!source.contains("host_name"));
        }
    }

    /// No other settings section, the grant wizard, the Sessions page or
    /// Home reads this computer's network name: none of their sources names
    /// it (built behaviour, pinned).
    #[test]
    fn no_other_page_reads_the_host_name() {
        for (file, source) in [
            ("settings/about.rs", include_str!("settings/about.rs")),
            (
                "settings/connection.rs",
                include_str!("settings/connection.rs"),
            ),
            ("settings/display.rs", include_str!("settings/display.rs")),
            ("settings/privacy.rs", include_str!("settings/privacy.rs")),
            ("settings/security.rs", include_str!("settings/security.rs")),
            ("settings/wizard.rs", include_str!("settings/wizard.rs")),
            ("sessions.rs", include_str!("sessions.rs")),
            ("home.rs", include_str!("home.rs")),
        ] {
            assert!(!source.contains("host_name"), "{file}");
        }
    }

    /// While this screen may be in a picture that leaves it (a session
    /// live, another Tornect process hosting), no section of the settings
    /// page offers a control that writes, a name half typed included: the
    /// hidden card stands in their place, and what is left to press is the
    /// section list, the sidebar, the banner and "Copy report" (which copies
    /// the diagnostics report as shown, naming nobody, and writes nothing);
    /// what the sections say stays, and About, which writes nothing, shows
    /// no hidden card.
    #[test]
    fn no_settings_write_while_shared() {
        let mut sharing = at_rest();
        sharing.sharing = vec![super::super::model::Sharing {
            session_id: "00".to_owned(),
            label: "Laptop".to_owned(),
            control: true,
            unattended: false,
            since: Instant::now(),
            capture: None,
        }];
        sharing.manager = Some(manager_on());
        let mut elsewhere = at_rest();
        elsewhere.hosted_elsewhere = true;
        elsewhere.manager = Some(manager_on());
        for (why, model) in [("sharing", sharing), ("elsewhere", elsewhere)] {
            for section in settings::Section::LISTED {
                for size in [WIDE, NARROW] {
                    let chrome = chrome_controls(&model, size);
                    let mut window =
                        Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
                    window.form.settings.section = section;
                    window.form.settings.name = Some("Desk".to_owned());
                    window.pass(Vec::new());
                    let case = format!("{why} {section:?} {size:?}");
                    // About has no control that writes, so nothing to hide.
                    if section != settings::Section::About {
                        assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{case}");
                        assert!(has_text(&window, settings::WRITES_HIDDEN), "{case}");
                    }
                    let narrow = size == NARROW;
                    let labels: Vec<&str> = settings::Section::LISTED
                        .iter()
                        .map(|s| s.label(narrow))
                        .collect();
                    for control in window.controls() {
                        assert!(
                            labels.contains(&control.as_str())
                                || chrome.contains(&control)
                                || control == "Copy report"
                                || (section == settings::Section::Security
                                    && [
                                        "Turn off",
                                        "For 12 hours",
                                        "Until I turn it back on",
                                        "Revoke all…"
                                    ]
                                    .contains(&control.as_str())),
                            "{case}: \"{control}\" writes while shared"
                        );
                    }
                    assert!(
                        !window.nodes.iter().any(|n| n.role() == Role::TextInput),
                        "{case}"
                    );
                }
            }
        }
    }

    /// Unattended access as a window host read it: on, two devices (one
    /// active, one locked), the panic key bound and one row not read yet.
    fn manager_on() -> super::super::model::Manager {
        use super::super::model::{GrantRow, Manager};
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::readiness::Probe;
        Manager {
            on: true,
            paused_until: None,
            without_asking: 1,
            grants: vec![
                GrantRow {
                    device: tornect_core::DeviceId::from_bytes([1; 32]),
                    label: "Office laptop".to_owned(),
                    words: tornect_core::words::Words::from_cached("abandon ability able about"),
                    created_by: Some(Actor::Ui),
                    last_used: None,
                    state: "active".to_owned(),
                    failures: 0,
                },
                GrantRow {
                    device: tornect_core::DeviceId::from_bytes([2; 32]),
                    label: "Tablet".to_owned(),
                    words: None,
                    created_by: Some(Actor::Cli),
                    last_used: Some(1_000_000_000),
                    state: "locked:120".to_owned(),
                    failures: 3,
                },
            ],
            readiness: vec![("panic_key", Probe::Ok), ("capture", Probe::Unknown)],
            not_ready: true,
            keep_awake: false,
            prevent_idle_lock: false,
            notify: false,
            sign_in: Some(false),
            installed: Some(false),
        }
    }

    /// The Security section, opened from the section list.
    fn security_section(model: Model, size: (f32, f32)) -> Window {
        let mut window = Window::new(model, Page::Settings, egui::Theme::Dark, size);
        let at = window.center("Security");
        assert!(window.click(at).is_empty(), "opening it asks nothing");
        assert_eq!(window.form.settings.section, settings::Section::Security);
        assert!(
            window.pass(Vec::new()).is_empty(),
            "drawing it asks nothing"
        );
        window
    }

    /// Settings, Security (§B.8.7.3): the header says whether unattended
    /// access is on, off or paused; each device's row shows its pinned label,
    /// its device words, who gave it access, when it last connected, its
    /// state and its failed attempts since the last unlock; the readiness
    /// rows show by their titles, the panic key bound or not, then the
    /// static advisory. What can be pressed is the section's deny-direction
    /// operations.
    #[test]
    fn the_manager_rows_show_the_planned_fields() {
        use settings::security;
        let mut model = at_rest();
        model.manager = Some(manager_on());
        for size in [WIDE, NARROW] {
            let window = security_section(model.clone(), size);
            for text in [
                "Unattended access",
                "On",
                "Office laptop",
                "Active",
                "device words: abandon · ability · able · about",
                "Given in this window · never connected · 0 failed attempts since the last \
                 unlock",
                "Tablet",
                "Locked for 2 min",
                "Given on the command line · last connected on 9 Sep 2001 · 3 failed attempts \
                 since the last unlock",
                "Readiness",
                "Panic key: bound",
                "Screen capture permission: unknown",
                security::ADVISORY,
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            let chrome = chrome_controls(&model, size);
            let narrow = size == NARROW;
            for control in window.controls() {
                assert!(
                    chrome.contains(&control)
                        || settings::Section::LISTED
                            .iter()
                            .any(|s| s.label(narrow) == control)
                        || security_controls().contains(&control.as_str()),
                    "{size:?}: \"{control}\""
                );
            }
        }
        let today = Day::from_ymd(2026, 10, 9).unwrap();
        let mut paused = manager_on();
        paused.paused_until = Some(today.days() as u64 * 86_400 + 8 * 3_600);
        assert_eq!(security::header(&paused, today).1, "Paused until 08:00 UTC");
        paused.paused_until = Some((today.days() as u64 + 1) * 86_400 + 8 * 3_600);
        assert_eq!(
            security::header(&paused, today).1,
            "Paused until 08:00 UTC on 10 Oct 2026"
        );
        paused.paused_until = Some(u64::MAX);
        assert_eq!(
            security::header(&paused, today).1,
            security::PAUSED_UNTIL_ON
        );
        paused.on = false;
        assert_eq!(security::header(&paused, today).1, "Off");
        for (label, said) in [
            ("disabled:ui", "Disabled in this window"),
            ("suspended:local_block", "Suspended: blocked here"),
            ("hard_locked", "Hard-locked"),
            ("not_yet_active", "Not yet active"),
            ("expired", "Expired"),
        ] {
            assert_eq!(security::state_text(label).1, said);
        }
        assert_eq!(
            security::readiness_line(
                "os_password",
                &tornect_core::unattended::readiness::Probe::Fail("empty".to_owned())
            )
            .1,
            "Account password not empty: re-authentication cannot protect settings on this \
             account"
        );
    }

    /// Home's badge "N devices can connect without asking" (§B.8.7.3) is
    /// unattended access as the guard says it, not the banner: it stays
    /// when the banner is acknowledged and goes when no device can connect
    /// without asking.
    #[test]
    fn the_badge_stays_after_the_banner_is_acknowledged() {
        use super::super::model::UnattendedBanner;
        let badge =
            |window: &Window, text: &str| window.nodes.iter().any(|n| n.value() == Some(text));
        let mut model = at_rest();
        let mut manager = manager_on();
        manager.without_asking = 2;
        manager.not_ready = false;
        model.manager = Some(manager);
        let at = format!("{}T09:30:00Z", {
            let (y, m, d) = Day::today().ymd();
            format!("{y:04}-{m:02}-{d:02}")
        });
        model.unattended_banner = UnattendedBanner::of(2, Some((at, "cli")), None);
        for size in [WIDE, NARROW] {
            let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            assert!(
                badge(&window, "2 devices can connect without asking"),
                "{size:?}: with the banner"
            );
        }
        model.unattended_banner = None;
        for size in [WIDE, NARROW] {
            let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            assert!(
                badge(&window, "2 devices can connect without asking"),
                "{size:?}: acknowledged"
            );
        }
        if let Some(manager) = &mut model.manager {
            manager.without_asking = 1;
        }
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(badge(&window, "1 device can connect without asking"));
        if let Some(manager) = &mut model.manager {
            manager.without_asking = 0;
        }
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, "can connect without asking"));
    }

    /// While this screen may be in a picture that leaves it, Home draws no
    /// badge of how many devices can connect without asking.
    #[test]
    fn the_badge_is_not_drawn_while_shared() {
        let mut model = at_rest();
        let mut manager = manager_on();
        manager.not_ready = false;
        model.manager = Some(manager);
        model.sharing = vec![super::super::model::Sharing {
            session_id: "00".to_owned(),
            label: "Laptop".to_owned(),
            control: true,
            unattended: false,
            since: Instant::now(),
            capture: None,
        }];
        let mut elsewhere = model.clone();
        elsewhere.sharing.clear();
        elsewhere.hosted_elsewhere = true;
        for model in [model, elsewhere] {
            for size in [WIDE, NARROW] {
                let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
                assert!(!has_text(&window, "can connect without asking"), "{size:?}");
            }
        }
    }

    /// Home's not-ready badge (§B.8.7.1 ⑥) shows while a readiness row is
    /// not green and unattended access is on, and goes once every row is
    /// (or unattended access is off).
    #[test]
    fn a_not_ready_row_raises_the_badge_until_ready() {
        let mut model = at_rest();
        model.manager = Some(manager_on());
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(has_text(&window, home::NOT_READY));
        let mut ready = manager_on();
        ready.not_ready = false;
        model.manager = Some(ready);
        let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, home::NOT_READY));
        let mut off = manager_on();
        off.on = false;
        model.manager = Some(off);
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, home::NOT_READY));
    }

    /// While this screen may be in a picture that leaves it, Settings,
    /// Security shows no device: the hidden card stands in their place,
    /// whether unattended access is on and what the readiness rows say stay.
    #[test]
    fn the_security_section_while_shared_shows_the_hidden_card() {
        let mut model = at_rest();
        model.manager = Some(manager_on());
        model.hosted_elsewhere = true;
        for size in [WIDE, NARROW] {
            let window = security_section(model.clone(), size);
            assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{size:?}");
            for gone in ["Office laptop", "Tablet", "device words", "failed attempt"] {
                assert!(!has_text(&window, gone), "{size:?}: {gone}");
            }
            for kept in ["On", "Panic key: bound"] {
                assert!(has_text(&window, kept), "{size:?}: {kept}");
            }
        }
    }

    /// While this screen may be in a picture that leaves it, each readiness
    /// row says its title and its state word only: a probe's message (it may
    /// name a path, and so the account) shows only when nothing is shared.
    #[test]
    fn the_readiness_rows_while_shared_say_their_state_only() {
        use tornect_core::unattended::readiness::Probe;
        let warned = "reading /home/someone/x: denied";
        let failed = "no file at /home/someone/y";
        let mut manager = manager_on();
        manager.readiness = vec![
            ("panic_key", Probe::Ok),
            ("keystore", Probe::Warn(warned.to_owned())),
            ("autostart", Probe::Fail(failed.to_owned())),
            ("capture", Probe::Unknown),
        ];
        let mut model = at_rest();
        model.manager = Some(manager);
        let mut shared = model.clone();
        shared.hosted_elsewhere = true;
        for size in [WIDE, NARROW] {
            let window = security_section(shared.clone(), size);
            for gone in ["/home/", warned, failed] {
                assert!(!has_text(&window, gone), "{size:?}: {gone}");
            }
            for state in [
                "Panic key: bound",
                "Keystore persistent and unlockable at start: warning",
                "Start at sign-in: FAIL",
                "Screen capture permission: unknown",
            ] {
                assert!(has_text(&window, state), "{size:?}: {state}");
            }
            let window = security_section(model.clone(), size);
            for said in [
                format!("Keystore persistent and unlockable at start: warning: {warned}"),
                format!("Start at sign-in: FAIL: {failed}"),
            ] {
                assert!(has_text(&window, &said), "{size:?}: {said}");
            }
        }
    }

    /// A window without the guard (no host role here, a store that did not
    /// open, another Tornect holding it) says so on Settings, Security, and
    /// shows nothing else of unattended access and no control.
    #[test]
    fn without_a_guard_the_security_section_offers_no_control() {
        use settings::security;
        for size in [WIDE, NARROW] {
            let window = security_section(at_rest(), size);
            assert!(has_text(&window, security::NO_GUARD), "{size:?}");
            assert!(!has_text(&window, "Readiness"), "{size:?}");
            let chrome = chrome_controls(&at_rest(), size);
            let narrow = size == NARROW;
            for control in window.controls() {
                assert!(
                    chrome.contains(&control)
                        || settings::Section::LISTED
                            .iter()
                            .any(|s| s.label(narrow) == control),
                    "{size:?}: \"{control}\""
                );
            }
        }
    }

    /// Every control of Settings, Security over [`manager_on`]: Turn off,
    /// the pause's ends, Revoke all, each row's operations (the locked
    /// device's Unlock among them) and the host settings' switches.
    fn security_controls() -> Vec<&'static str> {
        let mut controls = vec![
            settings::security::TURN_OFF,
            settings::security::REVOKE_ALL,
            settings::security::ROTATE,
            "Unlock",
        ];
        controls.extend(settings::security::PAUSE_ENDS.map(|(_, label)| label));
        controls.extend(settings::security::ROW_OPS.map(|(label, _)| label));
        controls.extend(settings::security::SETTINGS.map(|(label, _)| label));
        controls
    }

    /// [`manager_on`] with its first device only.
    fn one_device() -> super::super::model::Manager {
        let mut manager = manager_on();
        manager.grants.truncate(1);
        manager
    }

    /// "Give administrator access…" is offered on a control row only: the
    /// administrator level is a level of control.
    #[test]
    fn a_view_only_row_offers_no_raise() {
        use super::super::model::GrantLevel;
        use tornect_core::session_log::SessionMode;
        use tornect_core::unattended::grant::Preset;
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let mut model = at_rest();
        model.manager = Some(manager_on());
        model.wizard.account = Some(tornect_core::levels::AccountFacts::Windows(
            tornect_core::levels::WindowsFacts {
                installed: true,
                administrator: true,
                ..Default::default()
            },
        ));
        model.wizard.levels = vec![(
            device,
            GrantLevel {
                holds: false,
                marked: false,
                preset: Preset::MyMachines,
            },
        )];
        for (mode, offered) in [(SessionMode::ViewOnly, 0), (SessionMode::Control, 1)] {
            model.wizard.modes = vec![(device, mode)];
            let window = security_section(model.clone(), WIDE);
            let raises = window
                .controls()
                .iter()
                .filter(|c| *c == settings::wizard::RAISE)
                .count();
            assert_eq!(raises, offered, "{mode:?}");
        }
    }

    /// A click on a control of Settings, Security sends one operation for
    /// the window host's guard and nothing else; the section does not change
    /// on the click (it shows what the guard's answer is read back as):
    /// Turn off, each end of the pause, Revoke all after its question, and
    /// each operation of a device's row, naming that device.
    #[test]
    fn a_manager_click_sends_one_command_and_writes_nothing() {
        use super::super::model::{ManagerOp, PauseEnd};
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let mut model = at_rest();
        model.manager = Some(one_device());
        for size in [WIDE, NARROW] {
            let mut window = security_section(model.clone(), size);
            let mut clicks = vec![
                ("Turn off", ManagerOp::Off),
                ("For 12 hours", ManagerOp::Pause(PauseEnd::TwelveHours)),
                (
                    "Until I turn it back on",
                    ManagerOp::Pause(PauseEnd::UntilOn),
                ),
                ("Suspend", ManagerOp::Suspend(device)),
                ("Disable", ManagerOp::Disable(device)),
                ("Revoke unattended", ManagerOp::Revoke(device)),
                ("Remove device", ManagerOp::Remove(device)),
            ];
            for (label, op) in clicks.drain(..) {
                let at = window.center(label);
                assert_eq!(
                    window.click(at),
                    vec![Action::Manager(op)],
                    "{size:?}: {label}"
                );
                assert!(window.pass(Vec::new()).is_empty(), "{size:?}: {label}");
                assert!(has_text(&window, "Office laptop"), "{size:?}: {label}");
                assert!(has_text(&window, "On"), "{size:?}: {label}");
            }
            let at = window.center("Revoke all…");
            assert!(window.click(at).is_empty(), "{size:?}: the question first");
            // The question is drawn from the next pass on.
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            assert!(
                has_text(&window, "Remove unattended access for 1 device?"),
                "{size:?}"
            );
            let at = window.center("Remove");
            assert_eq!(
                window.click(at),
                vec![Action::Manager(ManagerOp::RevokeAll)],
                "{size:?}"
            );
        }
        assert_eq!(
            settings::security::revoke_all_question(2),
            "Remove unattended access for all 2 devices?"
        );
    }

    /// The pause offers the two ruled ends, 12 hours and until access is
    /// turned back on, and no end at 08:00 (OPEN until a zone source exists, as
    /// the operator ruled: this version keeps no time zone of the computer).
    #[test]
    fn pause_offers_the_two_settled_ends() {
        use super::super::model::{ManagerOp, PauseEnd};
        let mut model = at_rest();
        model.manager = Some(one_device());
        for size in [WIDE, NARROW] {
            let mut window = security_section(model.clone(), size);
            let controls = window.controls();
            assert!(controls.iter().any(|c| c == "For 12 hours"), "{size:?}");
            assert!(
                controls.iter().any(|c| c == "Until I turn it back on"),
                "{size:?}"
            );
            assert!(!controls.iter().any(|c| c.contains("08:00")), "{size:?}");
            for (label, end) in [
                ("For 12 hours", PauseEnd::TwelveHours),
                ("Until I turn it back on", PauseEnd::UntilOn),
            ] {
                let at = window.center(label);
                assert_eq!(
                    window.click(at),
                    vec![Action::Manager(ManagerOp::Pause(end))],
                    "{size:?}"
                );
            }
        }
    }

    /// While a pause runs, the section offers no end of a pause (one ending
    /// sooner would turn access back on, which only master on may do); Turn
    /// off stays. Off, it offers neither.
    #[test]
    fn a_running_pause_offers_no_shorter_end() {
        for until in [
            u64::MAX,
            Day::today().days() as u64 * 86_400 + 86_400 + 3_600,
        ] {
            let mut manager = one_device();
            manager.paused_until = Some(until);
            let mut model = at_rest();
            model.manager = Some(manager);
            for size in [WIDE, NARROW] {
                let window = security_section(model.clone(), size);
                let controls = window.controls();
                assert!(has_text(&window, "Paused until"), "{size:?}");
                for (_, end) in settings::security::PAUSE_ENDS {
                    assert!(!controls.iter().any(|c| c == end), "{size:?}: {end}");
                }
                assert!(controls.iter().any(|c| c == "Turn off"), "{size:?}");
            }
        }
        let mut off = one_device();
        off.on = false;
        let mut model = at_rest();
        model.manager = Some(off);
        let window = security_section(model, WIDE);
        let controls = window.controls();
        assert!(
            !controls
                .iter()
                .any(|c| c == "Turn off" || c == "For 12 hours")
        );
    }

    /// The desktop's screen-sharing grant on Settings, Security uses the
    /// first-run step's own commands: Grant again sends the grant, Revoke
    /// forgets it; while this screen is shared neither is offered and the
    /// state stays.
    #[test]
    fn the_sharing_grant_controls_use_the_existing_commands() {
        let mut model = at_rest();
        model.manager = Some(one_device());
        model.setup = Some(Setup {
            token_file: std::path::PathBuf::from("restore-token"),
            granted: true,
            busy: false,
            note: None,
        });
        // The block is the section's last: windows tall enough to reach it.
        for size in [TALL, (NARROW.0, 1600.0)] {
            let mut window = security_section(model.clone(), size);
            assert!(has_text(&window, "Granted and remembered"), "{size:?}");
            assert!(!has_text(&window, "restore-token"), "{size:?}: no path");
            let at = window.center("Grant again");
            assert_eq!(window.click(at), vec![Action::Grant], "{size:?}");
            let at = window.center("Revoke");
            assert_eq!(window.click(at), vec![Action::Revoke], "{size:?}");
            assert!(has_text(&window, settings::security::STOP_LINE), "{size:?}");
        }
        let mut shared = model;
        shared.hosted_elsewhere = true;
        let window = security_section(shared, TALL);
        assert!(has_text(&window, "Granted and remembered"));
        let controls = window.controls();
        assert!(!controls.iter().any(|c| c == "Grant again" || c == "Revoke"));
    }

    /// While this screen may be in a picture that leaves it, Turn off, the
    /// pause's ends and Revoke all stay offered (§B.8.6.2: deny-direction
    /// operations always), naming no device and no number: Revoke all asks
    /// "Remove unattended access for every device?".
    #[test]
    fn master_off_and_pause_stay_offered_while_shared() {
        use super::super::model::ManagerOp;
        let mut model = at_rest();
        model.manager = Some(manager_on());
        model.hosted_elsewhere = true;
        for size in [WIDE, NARROW] {
            let mut window = security_section(model.clone(), size);
            let controls = window.controls();
            for offered in [
                "Turn off",
                "For 12 hours",
                "Until I turn it back on",
                "Revoke all…",
            ] {
                assert!(controls.iter().any(|c| c == offered), "{size:?}: {offered}");
            }
            for (label, _) in settings::security::ROW_OPS {
                assert!(!controls.iter().any(|c| c == label), "{size:?}: {label}");
            }
            let at = window.center("Revoke all…");
            assert!(window.click(at).is_empty(), "{size:?}");
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            assert!(
                has_text(&window, settings::security::REVOKE_ALL_SHARED),
                "{size:?}"
            );
            for gone in ["Office laptop", "Tablet", "2 devices", "all 2"] {
                assert!(!has_text(&window, gone), "{size:?}: {gone}");
            }
            assert!(
                !window.nodes.iter().any(|n| n
                    .value()
                    .is_some_and(|v| v.starts_with("Remove unattended access")
                        && v.chars().any(|c| c.is_ascii_digit()))),
                "{size:?}: a number"
            );
            let at = window.center("Remove");
            assert_eq!(
                window.click(at),
                vec![Action::Manager(ManagerOp::RevokeAll)],
                "{size:?}"
            );
        }
    }

    /// One pass of `window` with `events`, as `Window::pass` runs it, and
    /// what the window asked to copy in it (`pass` keeps none).
    fn copied_in(window: &mut Window, events: Vec<egui::Event>) -> Vec<String> {
        let now = window.start + Duration::from_secs(5) + window.later;
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, window.size)),
            time: Some(5.0),
            events,
            ..egui::RawInput::default()
        };
        let mut actions = Vec::new();
        let (model, form) = (&window.model, &mut window.form);
        let out = window.ctx.run_ui(raw, |ui| {
            main_window(ui, model, form, now, &mut actions);
        });
        if let Some(update) = &out.platform_output.accesskit_update {
            window.nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
        }
        let copied = out
            .platform_output
            .commands
            .iter()
            .filter_map(|command| match command {
                egui::OutputCommand::CopyText(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        out.drop_without_applying_deltas();
        copied
    }

    /// §B.8.7.4: the stop code is drawn on one card, once, as text, with
    /// what it does and that it is shown only now; not while this screen is
    /// shared and not under a sheet (it is kept, and drawn again after);
    /// "I have written it down" sends the delivery and nothing else.
    #[test]
    fn the_stop_card_is_one_card_until_written_down() {
        use super::super::backend::Secret;
        use super::super::model::ManagerOp;
        use settings::security;
        let code = "0a1b-2c3d-4e5f-6a7b-8c9d-0e1f-2a3b-4c5d";
        let mut model = at_rest();
        model.manager = Some(one_device());
        model.stop_card = Some(Secret(zeroize::Zeroizing::new(code.to_owned())));
        for size in [WIDE, NARROW] {
            let mut window = security_section(model.clone(), size);
            let shown = window
                .nodes
                .iter()
                .filter(|n| n.value().is_some_and(|v| v.contains("0a1b-2c3d")))
                .count();
            assert_eq!(shown, 1, "{size:?}: one card");
            for text in [
                security::STOP_HEADING,
                security::STOP_DOES,
                security::WRITE_IT_DOWN,
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            // Nothing copies the code: a drag across it, then Copy, Cmd+C
            // and Ctrl+C.
            let b = window
                .nodes
                .iter()
                .find(|n| n.value() == Some(code))
                .and_then(Node::bounds)
                .expect("the code's place");
            let (from, to) = (
                egui::pos2(b.x0 as f32 + 1.0, ((b.y0 + b.y1) / 2.0) as f32),
                egui::pos2(b.x1 as f32 - 1.0, ((b.y0 + b.y1) / 2.0) as f32),
            );
            let button = |pos, pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut copied = copied_in(
                &mut window,
                vec![egui::Event::PointerMoved(from), button(from, true)],
            );
            copied.extend(copied_in(&mut window, vec![egui::Event::PointerMoved(to)]));
            copied.extend(copied_in(&mut window, vec![button(to, false)]));
            copied.extend(copied_in(&mut window, vec![egui::Event::Copy]));
            for modifiers in [egui::Modifiers::COMMAND, egui::Modifiers::CTRL] {
                let key = |pressed| egui::Event::Key {
                    key: egui::Key::C,
                    physical_key: None,
                    pressed,
                    repeat: false,
                    modifiers,
                };
                copied.extend(copied_in(&mut window, vec![key(true), key(false)]));
                copied.extend(copied_in(&mut window, Vec::new()));
            }
            assert!(copied.is_empty(), "{size:?}: {copied:?}");
            let at = window.center(security::WRITTEN_DOWN);
            assert_eq!(
                window.click(at),
                vec![Action::Manager(ManagerOp::StopCodeWrittenDown(0))],
                "{size:?}"
            );
        }
        let mut shared = model.clone();
        shared.hosted_elsewhere = true;
        let window = security_section(shared, WIDE);
        assert!(!has_text(&window, "0a1b-2c3d"), "not while shared");
        assert!(!has_text(&window, security::STOP_HEADING));
        let mut asking = model;
        asking.popups = vec![Popup {
            id: 5,
            kind: PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: "ab:cd".to_owned(),
            },
            deadline: Instant::now() + Duration::from_secs(60),
        }];
        let mut window = Window::new(asking, Page::Settings, egui::Theme::Dark, WIDE);
        window.form.settings.section = settings::Section::Security;
        window.pass(Vec::new());
        assert!(!has_text(&window, "0a1b-2c3d"), "not under a sheet");
    }

    /// Settings, Security with no device to offer the wizard: "Pair a device
    /// first" while no device is paired, and that every paired device already
    /// has unattended access when each has.
    #[test]
    fn the_security_page_says_why_no_device_is_offered() {
        use settings::wizard;
        let mut model = at_rest();
        model.manager = Some(one_device());
        model.wizard.offer = Some(false);
        for (all_granted, shown, absent) in [
            (false, wizard::NO_DEVICE, wizard::ALL_GRANTED),
            (true, wizard::ALL_GRANTED, wizard::NO_DEVICE),
        ] {
            model.wizard.all_granted = all_granted;
            for size in [WIDE, NARROW] {
                let window = security_section(model.clone(), size);
                assert!(has_text(&window, shown), "{all_granted} {size:?}");
                assert!(!has_text(&window, absent), "{all_granted} {size:?}");
            }
        }
    }

    /// Settings, General's "Start Tornect when I sign in" (§B.1.1): turning
    /// it on first says what it means, as approved, with Cancel first; only
    /// its "Turn on" sends the operation (the switch moves on the guard's
    /// answer, not on the click); turning it off sends the removal at once.
    #[test]
    fn the_sign_in_switch_shows_the_tor_text_before_it_acts() {
        use super::super::model::ManagerOp;
        use settings::general;
        let text = format!(
            "{} {}",
            crate::unattended::TOR_AT_SIGN_IN,
            general::WHILE_IT_RUNS
        );
        assert_eq!(
            text,
            "Starting at sign-in means a Tor connection at every sign-in: your local network and \
             your internet provider can see that this computer uses Tor. While Tornect runs, \
             devices you gave unattended access can connect, new devices can ask to pair, and \
             anyone with this computer's Tornect ID can see that it is online."
        );
        let mut model = at_rest();
        model.manager = Some(one_device());
        for size in [TALL, (NARROW.0, 1600.0)] {
            let mut window = Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
            assert!(!has_text(&window, &text), "{size:?}");
            let at = window.center(general::SIGN_IN);
            assert!(
                window.click(at).is_empty(),
                "{size:?}: the click asks nothing yet"
            );
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            assert!(has_text(&window, &text), "{size:?}: the text first");
            let cancel = window.node("Cancel").bounds().expect("bounds");
            let turn_on = window.node(general::TURN_ON).bounds().expect("bounds");
            assert!(cancel.x0 < turn_on.x0, "{size:?}: Cancel first");
            let at = window.center("Cancel");
            assert!(window.click(at).is_empty(), "{size:?}");
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            assert!(!has_text(&window, &text), "{size:?}: cancelled");
            let at = window.center(general::SIGN_IN);
            assert!(window.click(at).is_empty(), "{size:?}");
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            let at = window.center(general::TURN_ON);
            assert_eq!(
                window.click(at),
                vec![Action::Manager(ManagerOp::SignIn(true))],
                "{size:?}"
            );
        }
        let mut on = one_device();
        on.sign_in = Some(true);
        model.manager = Some(on);
        let mut window = Window::new(model.clone(), Page::Settings, egui::Theme::Dark, TALL);
        let at = window.center(general::SIGN_IN);
        assert_eq!(
            window.click(at),
            vec![Action::Manager(ManagerOp::SignIn(false))]
        );
        model.manager = None;
        let window = Window::new(model, Page::Settings, egui::Theme::Dark, TALL);
        assert!(
            has_text(&window, settings::security::NO_GUARD),
            "no guard: said"
        );
        assert!(!window.controls().iter().any(|c| c == general::SIGN_IN));
    }

    /// Settings, General says whether Tornect is installed, by the install's
    /// probe, with the command that installs or removes it and that Tornect
    /// must be closed first (§B.1.1).
    #[test]
    fn the_install_state_and_its_command_are_shown() {
        use settings::general;
        for (installed, state, command) in [
            (Some(true), "Installed.", "tornect uninstall"),
            (Some(false), "Not installed.", "tornect install"),
            (None, "could not be read", "tornect install"),
        ] {
            let mut manager = one_device();
            manager.installed = installed;
            let mut model = at_rest();
            model.manager = Some(manager);
            for size in [TALL, (NARROW.0, 1600.0)] {
                let window = Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
                for text in [state, command, general::CLOSE_FIRST] {
                    assert!(has_text(&window, text), "{installed:?} {size:?}: {text}");
                }
            }
        }
    }

    /// Rotate ID's dialog (§B.8.12) names the devices whose unattended
    /// access it removes and asks for the typed word ROTATE, Cancel first;
    /// only with the word does Rotate ID send the operation (no password: it
    /// removes access). Not offered while this screen is shared.
    #[test]
    fn the_rotate_dialog_names_the_grants_and_needs_the_word() {
        use super::super::model::ManagerOp;
        use settings::security;
        let question = security::rotate_question(&["Office laptop", "Tablet"]);
        assert_eq!(
            question,
            "This makes a new Tornect ID. Every pairing stops working, and unattended access is \
             removed for: Office laptop, Tablet. Type ROTATE to go on. Tornect closes when it is \
             done; start it again to use the new ID."
        );
        let mut model = at_rest();
        model.manager = Some(manager_on());
        // The dialog is the section's last: windows tall enough to reach it.
        for size in [(WIDE.0, 2400.0), (NARROW.0, 3200.0)] {
            let mut window = security_section(model.clone(), size);
            let at = window.center(security::ROTATE);
            assert!(window.click(at).is_empty(), "{size:?}: the dialog first");
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            assert!(has_text(&window, &question), "{size:?}");
            let cancel = window.node("Cancel").bounds().expect("bounds");
            let rotate = window.node("Rotate ID").bounds().expect("bounds");
            assert!(cancel.x0 < rotate.x0, "{size:?}: Cancel first");
            for typed in ["", "rotate", "ROTATE ID"] {
                window.form.settings.rotate = Some(typed.to_owned());
                assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
                let at = window.center("Rotate ID");
                assert!(window.click(at).is_empty(), "{size:?}: {typed:?}");
            }
            window.form.settings.rotate = Some("ROTATE".to_owned());
            assert!(window.pass(Vec::new()).is_empty(), "{size:?}");
            let at = window.center("Rotate ID");
            assert_eq!(
                window.click(at),
                vec![Action::Manager(ManagerOp::RotateId)],
                "{size:?}"
            );
            assert!(window.form.settings.rotate.is_none(), "{size:?}: closed");
        }
        let mut shared = model;
        shared.hosted_elsewhere = true;
        let window = security_section(shared, (WIDE.0, 2400.0));
        assert!(!window.controls().iter().any(|c| c == security::ROTATE));
    }

    /// One password dialog at a time, Rotate ID's included: while another
    /// operation waits at its dialog (a section's operation, or the
    /// wizard's), neither Rotate ID's button nor its dialog sends anything.
    #[test]
    fn rotate_id_sends_nothing_while_another_operation_asks() {
        use settings::security;
        let mut model = at_rest();
        model.manager = Some(manager_on());
        let mut busy = model.clone();
        busy.manager_busy = true;
        let mut running = model;
        running.wizard.running = Some(1);
        for (what, model) in [("a section's operation", busy), ("the wizard", running)] {
            let mut window = security_section(model, (WIDE.0, 2400.0));
            let at = window.center(security::ROTATE);
            assert!(window.click(at).is_empty(), "{what}");
            assert!(window.form.settings.rotate.is_none(), "{what}: no dialog");
            window.form.settings.rotate = Some("ROTATE".to_owned());
            assert!(window.pass(Vec::new()).is_empty(), "{what}");
            let at = window.center("Rotate ID");
            assert!(window.click(at).is_empty(), "{what}: nothing sent");
        }
    }

    /// A Rotate ID that did not finish (§B.8.12): the main window shows one
    /// card with the operator's sentence for what was left and one Close
    /// button, and nothing else (no page, no navigation, no path); Close
    /// asks the window to close.
    #[test]
    fn a_rotation_that_did_not_finish_shows_one_card() {
        use super::super::model::RotateFailed;
        use settings::security;
        assert_eq!(
            security::ROTATE_DID_NOT_FINISH,
            "Rotate ID did not finish: unattended access was removed, but this computer keeps \
             its old ID. Start Tornect again and use Rotate ID again."
        );
        assert_eq!(
            security::ROTATE_DID_NOT_RUN,
            "Rotate ID did not run: nothing was changed. Start Tornect again and use Rotate ID \
             again."
        );
        for (failed, text) in [
            (RotateFailed::AccessRemoved, security::ROTATE_DID_NOT_FINISH),
            (RotateFailed::NothingChanged, security::ROTATE_DID_NOT_RUN),
        ] {
            let mut model = at_rest();
            model.rotating = true;
            model.rotate_failed = Some(failed);
            for size in [WIDE, NARROW] {
                let mut window =
                    Window::new(model.clone(), Page::Settings, egui::Theme::Dark, size);
                // The sentence, and no other text: every text node carries
                // it or, wrapped at the narrow width, one of its lines.
                assert!(has_text(&window, text), "{failed:?} {size:?}");
                for shown in window.nodes.iter().filter_map(Node::value) {
                    assert!(text.contains(shown), "{failed:?} {size:?}: {shown}");
                }
                assert_eq!(window.controls(), ["Close"], "{failed:?} {size:?}");
                let at = window.center("Close");
                assert_eq!(
                    window.click(at),
                    vec![Action::CloseWindow],
                    "{failed:?} {size:?}"
                );
            }
        }
    }

    /// The Privacy section, opened from the section list.
    fn privacy(model: Model, size: (f32, f32)) -> Window {
        let mut window = Window::new(model, Page::Settings, egui::Theme::Dark, size);
        let at = window.center("Privacy");
        assert!(window.click(at).is_empty(), "opening it asks nothing");
        assert_eq!(window.form.settings.section, settings::Section::Privacy);
        assert!(
            window.pass(Vec::new()).is_empty(),
            "drawing it asks nothing"
        );
        window
    }

    /// Settings, Privacy names the name in use, as Home does; a saved rename
    /// shows under it as the name from the next start; before the start
    /// fills the name in use in, the saved one stands.
    #[test]
    fn the_privacy_page_names_the_name_in_use() {
        let mut model = with_book(false);
        model.settings.device_name = "Desk by the window".to_owned();
        for size in [WIDE, NARROW] {
            let window = privacy(model.clone(), size);
            assert!(
                has_text(&window, "The name \u{201c}Linux PC\u{201d}"),
                "{size:?}"
            );
            assert!(
                has_text(
                    &window,
                    "\u{201c}Desk by the window\u{201d} from the next start."
                ),
                "{size:?}"
            );
            assert!(has_text(&window, settings::privacy::ID_LINE), "{size:?}");
        }
        model.settings.device_name = "Linux PC".to_owned();
        let window = privacy(model.clone(), WIDE);
        assert!(has_text(&window, "The name \u{201c}Linux PC\u{201d}"));
        assert!(!has_text(&window, "from the next start"), "equal names");
        model.device_name.clear();
        model.settings.device_name = "Desk by the window".to_owned();
        let window = privacy(model, WIDE);
        assert!(has_text(
            &window,
            "The name \u{201c}Desk by the window\u{201d}"
        ));
        assert!(
            !has_text(&window, "from the next start"),
            "before the start"
        );
    }

    /// Settings, Privacy: the plan's sentences word for word (Part C row
    /// 10's line; §B.6's name for the session log and what it records), the
    /// screenshots line and the rest of what the page says, all on the page
    /// at both sizes; places named in words, no path.
    #[test]
    fn the_privacy_page_says_the_planned_lines() {
        use settings::privacy;
        assert_eq!(
            privacy::UNATTENDED_KEPT,
            "For each computer you connect to unattended, this device keeps whether a password is \
             remembered and whether your access there is control or reaches administrator \
             access; Forget removes it."
        );
        assert_eq!(
            privacy::LOG_KEPT,
            "The session log is the log of your unattended connections, always kept, never sent."
        );
        assert_eq!(
            privacy::LOG_RECORDS,
            "Connection attempts to this computer, and the unattended connections and admin \
             commands of this device, are always recorded in the session log; the history switch \
             governs only the address book's recent list."
        );
        assert_eq!(
            privacy::SCREENSHOTS,
            "Screenshots are saved in Pictures/Tornect, named by the date and time."
        );
        assert_eq!(
            privacy::NETWORK_LINE,
            "Your IP address stays hidden from the computers you connect to and those that connect \
             here: every session is relayed through Tor. Tornect has no accounts, no telemetry and \
             no update checks, and it checks whether a saved computer is reachable only when you \
             click \"Check if reachable\"."
        );
        for size in [WIDE, NARROW] {
            let window = privacy(with_book(false), size);
            for text in [
                privacy::UNATTENDED_KEPT,
                privacy::LOG_KEPT,
                privacy::LOG_RECORDS,
                privacy::SCREENSHOTS,
                privacy::NETWORK_LINE,
                settings::general::NAME_NOTE,
                "The name \u{201c}Linux PC\u{201d}",
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            for (what, how_long) in privacy::STORED {
                assert!(has_text(&window, what), "{size:?}: {what}");
                assert!(has_text(&window, how_long), "{size:?}: {how_long}");
            }
            for value in window.nodes.iter().filter_map(Node::value) {
                for path in ['~', '\\'] {
                    assert!(!value.contains(path), "{size:?}: {value}");
                }
                assert!(
                    !value.contains(".toml") && !value.contains(".log"),
                    "{size:?}: {value}"
                );
            }
        }
    }

    /// The Privacy page's history switch is the Recent tab's setting, not a
    /// second one: both show the one state, and a click on either sends the
    /// same action; Clear history on either clears the one history.
    #[test]
    fn the_privacy_switch_is_the_recent_switch() {
        use egui::accesskit::Toggled;
        const KEEP: &str = "Keep a list of recent connections";
        for on in [true, false] {
            let mut model = with_book(false);
            model.book.history = on;
            let mut recent = Window::new(model.clone(), Page::AddressBook, egui::Theme::Dark, WIDE);
            recent.form.book.tab = Tab::Recent;
            recent.pass(Vec::new());
            let mut mirror = privacy(model, WIDE);
            let shown = if on { Toggled::True } else { Toggled::False };
            assert_eq!(recent.node(KEEP).toggled(), Some(shown), "{on}");
            assert_eq!(mirror.node(KEEP).toggled(), Some(shown), "{on}");
            for window in [&mut recent, &mut mirror] {
                let at = window.center(KEEP);
                assert_eq!(window.click(at), vec![Action::SetHistory(!on)], "{on}");
                let at = window.center("Clear history");
                assert_eq!(window.click(at), vec![Action::ClearHistory], "{on}");
            }
        }
    }

    /// With history off the Privacy page writes no history: the click that
    /// turns it off, applied as the window's tokio side applies it, leaves
    /// off the one switch that both writers of `last_seen` read (their own
    /// tests: `history`), so a connection made then is not recorded; the
    /// page then shows the switch off and asks for nothing by itself.
    #[test]
    fn the_privacy_page_writes_no_history_while_off() {
        use egui::accesskit::Toggled;
        use tornect_core::address_book::Store;
        const KEEP: &str = "Keep a list of recent connections";
        let tmp = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(tmp.path().join("home"));
        let store = Store::new(&paths);
        store.set_history(true).unwrap();
        assert!(store.keeps_history());
        let mut model = with_book(false);
        model.book.history = true;
        let mut window = privacy(model, WIDE);
        let at = window.center(KEEP);
        let asked = window.click(at);
        assert_eq!(asked, vec![Action::SetHistory(false)]);
        for action in asked {
            if let Action::SetHistory(on) = action {
                super::super::book::apply(&paths, &super::super::book::Change::History(on));
            }
        }
        assert!(!store.keeps_history());
        let id = TornectId::from_bytes([0x42; 32]);
        assert!(
            !store
                .record_visit(id, [7; 32], "Office PC", Day::today())
                .unwrap()
        );
        assert!(!store.recent_path().exists(), "no recent list written");
        window.model.book.history = false;
        for _ in 0..2 {
            assert!(window.pass(Vec::new()).is_empty());
        }
        assert_eq!(window.node(KEEP).toggled(), Some(Toggled::False));
    }

    /// While this screen is shared, the Privacy page's history switch and
    /// Clear give way to the hidden card, as the Recent tab's do (the whole
    /// address book is hidden then: the mirror is no wider); what the page
    /// says stays.
    #[test]
    fn the_privacy_history_controls_while_shared_are_hidden() {
        use settings::privacy;
        const KEEP: &str = "Keep a list of recent connections";
        let mut model = with_book(false);
        model.hosted_elsewhere = true;
        for size in [WIDE, NARROW] {
            let window = privacy(model.clone(), size);
            assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{size:?}");
            assert!(
                !window.nodes.iter().any(|n| n.label() == Some(KEEP)),
                "{size:?}"
            );
            assert!(
                !window.controls().iter().any(|c| c == "Clear history"),
                "{size:?}"
            );
            for text in [
                privacy::LOG_RECORDS,
                privacy::LOG_KEPT,
                privacy::UNATTENDED_KEPT,
                privacy::SCREENSHOTS,
                privacy::NETWORK_LINE,
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            let mut book = Window::new(model.clone(), Page::AddressBook, egui::Theme::Dark, size);
            book.form.book.tab = Tab::Recent;
            book.pass(Vec::new());
            assert!(
                !book.nodes.iter().any(|n| n.label() == Some(KEEP)),
                "{size:?}: the Recent tab's own switch is hidden too"
            );
        }
    }

    /// Settings, About: the version, the protocol, the licence, where the
    /// third-party licences are, that nothing checks for updates, and the
    /// diagnostics report as the window gathered it; the page's one control
    /// copies the report as shown, and nothing on it reaches the network
    /// (no check, no connection, no download).
    #[test]
    fn the_about_page_offers_no_network_action() {
        use settings::about;
        assert_eq!(
            about::LICENCES,
            "The licences of the code Tornect includes from others are in \
             THIRD_PARTY_LICENSES.txt, beside the program in each release."
        );
        assert_eq!(
            about::NO_UPDATES,
            "Tornect never checks for updates by itself."
        );
        assert_eq!(about::REVIEW, "Review it before you share it.");
        let report = "Tornect 0.1.0, protocol 1\nSystem: linux x86_64";
        for size in [WIDE, NARROW] {
            let titles: Vec<&str> = settings::Section::LISTED
                .iter()
                .map(|s| s.label(size == NARROW))
                .collect();
            let mut model = at_rest();
            model.diagnostics = report.to_owned();
            let chrome = chrome_controls(&model, size);
            let mut window = Window::new(model, Page::Settings, egui::Theme::Dark, size);
            let at = window.center("About");
            assert!(
                window.click(at).is_empty(),
                "{size:?}: opening it asks nothing"
            );
            assert!(
                window.pass(Vec::new()).is_empty(),
                "{size:?}: drawing it asks nothing"
            );
            for text in [
                format!("Version {}", tornect_core::VERSION),
                format!("Protocol {}", tornect_core::PROTOCOL_VERSION),
                "GPL-3.0-or-later".to_owned(),
                about::LICENCES.to_owned(),
                about::NO_UPDATES.to_owned(),
                about::REVIEW.to_owned(),
                report.to_owned(),
            ] {
                assert!(has_text(&window, &text), "{size:?}: {text}");
            }
            let own: Vec<String> = window
                .controls()
                .into_iter()
                .filter(|c| !chrome.contains(c) && !titles.contains(&c.as_str()))
                .collect();
            assert_eq!(own, ["Copy report"], "{size:?}");
            let at = window.center("Copy report");
            assert_eq!(
                window.click(at),
                vec![Action::Copy(report.to_owned())],
                "{size:?}"
            );
        }
    }

    /// Settings, Display and quality: each choice sends the stored viewer
    /// defaults with that one change (the picture's sizes in the toolbar's
    /// own words), from what the settings hold; while this screen is shared
    /// the controls give way to the hidden card and the fixed lines stay.
    #[test]
    fn the_display_section_sends_the_viewer_defaults() {
        use super::super::model::SettingsChange;
        use settings::display;
        use tornect_core::config::{Picture, ToolbarHides, Viewer};
        let stored = Viewer::default();
        let mut window = Window::new(at_rest(), Page::Settings, egui::Theme::Dark, WIDE);
        let at = window.center("Display and quality");
        assert!(window.click(at).is_empty());
        assert!(window.pass(Vec::new()).is_empty());
        for text in [display::HOST_RATE, display::QUALITY_LATER] {
            assert!(has_text(&window, text), "{text}");
        }
        let save = |viewer| vec![Action::SaveSettings(SettingsChange::Viewer(viewer))];
        let at = window.center("1:1");
        assert_eq!(
            window.click(at),
            save(Viewer {
                picture: Picture::OneToOne,
                ..stored
            })
        );
        let at = window.center(display::FULLSCREEN);
        assert_eq!(
            window.click(at),
            save(Viewer {
                fullscreen_at_open: true,
                ..stored
            })
        );
        let at = window.center("Never");
        assert_eq!(
            window.click(at),
            save(Viewer {
                toolbar_hides: ToolbarHides::Never,
                ..stored
            })
        );
        let at = window.center(display::BADGE);
        assert_eq!(
            window.click(at),
            save(Viewer {
                show_badge: false,
                ..stored
            })
        );
        assert!(window.controls().iter().any(|c| c == "Fit"));
        let mut model = at_rest();
        model.hosted_elsewhere = true;
        let mut window = Window::new(model, Page::Settings, egui::Theme::Dark, WIDE);
        window.form.settings.section = settings::Section::Display;
        window.pass(Vec::new());
        assert!(has_text(&window, HIDDEN_WHILE_SHARED));
        assert!(
            !window
                .controls()
                .iter()
                .any(|c| c == "1:1" || c == display::BADGE)
        );
        assert!(has_text(&window, display::HOST_RATE));
    }

    /// Settings, Display and quality: under its choices the section says
    /// when they take effect; not while this screen is shared, when the
    /// choices give way to the hidden card.
    #[test]
    fn the_display_choices_say_when_they_apply() {
        use settings::display;
        for size in [WIDE, NARROW] {
            let mut window = Window::new(at_rest(), Page::Settings, egui::Theme::Dark, size);
            window.form.settings.section = settings::Section::Display;
            window.pass(Vec::new());
            assert!(has_text(&window, display::NEXT_SESSION), "{size:?}");
            let mut model = at_rest();
            model.hosted_elsewhere = true;
            let mut window = Window::new(model, Page::Settings, egui::Theme::Dark, size);
            window.form.settings.section = settings::Section::Display;
            window.pass(Vec::new());
            assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{size:?}");
            assert!(!has_text(&window, display::NEXT_SESSION), "{size:?}");
        }
    }

    /// Settings, Connection: a private bridge line that does not parse is
    /// reported by its number only, its content shown nowhere but in its
    /// field, and Save waits until every line parses; the way to Tor sends
    /// its one change.
    #[test]
    fn a_bad_bridge_line_is_reported_by_its_number_only() {
        use super::super::model::{BridgeLines, SettingsChange, TorChoice};
        use settings::connection;
        use tornect_core::config::BridgeMode;
        const GOOD: &str =
            "obfs4 198.51.100.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        const BAD: &str = "obfs4 198.51.100.8:443 NOTAFINGERPRINT cert=SECRETCERT iat-mode=0";
        let stored = at_rest().settings.tor;
        let mut window = Window::new(at_rest(), Page::Settings, egui::Theme::Dark, WIDE);
        let at = window.center("Connection");
        assert!(window.click(at).is_empty());
        window.form.settings.bridge_lines = Some(format!("{GOOD}\n{BAD}"));
        window.pass(Vec::new());
        assert!(has_text(&window, &connection::bad_line(2)));
        assert!(!has_text(&window, &connection::bad_line(1)));
        assert!(window.node("Save").is_disabled());
        for node in &window.nodes {
            if node.role() == Role::Label {
                let value = node.value().unwrap_or("");
                assert!(
                    !value.contains("SECRETCERT") && !value.contains("198.51"),
                    "{value}"
                );
            }
        }
        window.form.settings.bridge_lines = Some(format!("{GOOD}\n\n"));
        window.pass(Vec::new());
        let at = window.center("Save");
        assert_eq!(
            window.click(at),
            vec![Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridge_lines: BridgeLines(vec![GOOD.to_owned()]),
                ..stored.clone()
            }))]
        );
        let at = window.center("Snowflake");
        assert_eq!(
            window.click(at),
            vec![Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridges: BridgeMode::Snowflake,
                ..stored
            }))]
        );
        for text in [
            connection::NEXT_START,
            connection::BY_NUMBER,
            connection::NO_DIRECT,
        ] {
            assert!(has_text(&window, text), "{text}");
        }
    }

    /// The first run's question on Home: "What should other devices call
    /// this computer?" with the saved name filled in (on a fresh home the
    /// neutral default), Save and Skip; until it is answered Home offers
    /// nothing else (no connect field, no other card).
    #[test]
    fn home_asks_the_name_first_with_the_neutral_default() {
        let mut model = at_rest();
        model.name_question = true;
        let neutral = model.settings.device_name.clone();
        for size in [WIDE, NARROW] {
            let mut window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            assert!(has_text(&window, home::NAME_QUESTION), "{size:?}");
            let fields: Vec<&str> = window
                .nodes
                .iter()
                .filter(|n| n.role() == Role::TextInput)
                .filter_map(Node::value)
                .collect();
            assert_eq!(
                fields,
                [neutral.as_str()],
                "{size:?}: only the name's field"
            );
            let chrome = chrome_controls(&model, size);
            let mut own: Vec<String> = window
                .controls()
                .into_iter()
                .filter(|c| !chrome.contains(c))
                .collect();
            own.sort();
            assert_eq!(own, ["", "Save", "Skip"], "{size:?}: the field, Save, Skip");
            let at = window.center("Skip");
            assert_eq!(
                window.click(at),
                vec![Action::FirstRunName(None)],
                "{size:?}"
            );
            window.form.first_name = Some("Desk by the window".to_owned());
            window.pass(Vec::new());
            let at = window.center("Save");
            assert_eq!(
                window.click(at),
                vec![Action::FirstRunName(Some("Desk by the window".to_owned()))],
                "{size:?}"
            );
        }
        model.name_question = false;
        let window = Window::new(model, Page::Home, egui::Theme::Dark, WIDE);
        assert!(!has_text(&window, home::NAME_QUESTION));
    }

    /// While this screen may be in a picture that leaves it (here another
    /// Tornect process hosts this home), the first run's question is not
    /// drawn: Home shows the hidden card in its place, with no name field,
    /// no Save and no Skip.
    #[test]
    fn home_hides_the_name_question_while_shared() {
        let mut model = at_rest();
        model.name_question = true;
        model.hosted_elsewhere = true;
        for size in [WIDE, NARROW] {
            let window = Window::new(model.clone(), Page::Home, egui::Theme::Dark, size);
            assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{size:?}");
            assert!(!has_text(&window, home::NAME_QUESTION), "{size:?}");
            assert!(
                window.nodes.iter().all(|n| n.role() != Role::TextInput),
                "{size:?}: no name field"
            );
            let controls = window.controls();
            for gone in ["Save", "Skip"] {
                assert!(!controls.iter().any(|c| c == gone), "{size:?}: {gone}");
            }
        }
    }

    /// §B.8.6.1 (decision M1-67): on the address book's Devices tab a granted
    /// device's card says why its sessions are view only, in the plan's two
    /// lines (its password marked; this computer's account settings, with the
    /// device's label), and how many of its admin commands ran nothing; every
    /// card links to Settings, Security, and the link asks the backend
    /// nothing; a device without unattended access gets the link only.
    #[test]
    fn the_view_only_lines_show_where_the_plan_puts_them() {
        use super::super::model::{DeviceCard, ViewOnly};
        let devices_tab = |model: Model| {
            let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, TALL);
            window.form.book.tab = Tab::Devices;
            for _ in 0..2 {
                assert!(window.pass(Vec::new()).is_empty());
            }
            window
        };
        let mut model = with_book(false);
        let (laptop, tablet) = (model.book.devices[0].id, model.book.devices[1].id);
        model.wizard.cards = vec![
            (
                laptop,
                DeviceCard {
                    view_only: Some(ViewOnly::UntilNewPassword),
                    nothing_ran: Some(2),
                },
            ),
            (
                tablet,
                DeviceCard {
                    view_only: Some(ViewOnly::AccountSettings),
                    nothing_ran: Some(0),
                },
            ),
        ];
        let mut window = devices_tab(model.clone());
        assert!(has_text(&window, address_book::VIEW_ONLY_UNTIL));
        assert!(has_text(
            &window,
            &address_book::VIEW_ONLY_ACCOUNT.replace("<device>", "Tablet")
        ));
        assert!(has_text(&window, "Admin commands that ran nothing: 2"));
        assert!(has_text(&window, "Admin commands that ran nothing: 0"));
        let at = window.center(address_book::MANAGE);
        assert!(window.click(at).is_empty(), "asks nothing");
        assert_eq!(window.form.page, Page::Settings);
        assert_eq!(window.form.settings.section, settings::Section::Security);
        model.wizard.cards.clear();
        let window = devices_tab(model);
        assert!(!has_text(&window, "View only"));
        assert!(!has_text(&window, "Admin commands that ran nothing"));
        let links = window
            .nodes
            .iter()
            .filter(|n| n.label() == Some(address_book::MANAGE))
            .count();
        assert_eq!(links, 2, "one per card");
    }

    /// B27: the Devices tab removes a paired device, with unattended access
    /// or without, after a question that names it by its label and device
    /// words: the first click only asks, "Keep it" takes it back, and only
    /// Remove sends the window host's *Remove device* for that device, once
    /// (the guard's unpair, then the pin). Without the window host's guard
    /// no card offers it, and the tab says so.
    #[test]
    fn the_devices_tab_removes_a_device_after_asking() {
        use super::super::model::{Manager, ManagerOp};
        let devices_tab = |model: Model| {
            let mut window = Window::new(model, Page::AddressBook, egui::Theme::Dark, TALL);
            window.form.book.tab = Tab::Devices;
            for _ in 0..2 {
                assert!(window.pass(Vec::new()).is_empty());
            }
            window
        };
        let remove_buttons = |window: &Window| -> Vec<egui::Pos2> {
            window
                .nodes
                .iter()
                .filter(|n| n.label() == Some(address_book::REMOVE_DEVICE))
                .filter_map(Node::bounds)
                .map(|b| egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32))
                .collect()
        };
        let mut model = with_book(false);
        model.manager = Some(Manager::default());
        let tablet = &model.book.devices[1];
        let (id, words) = (tablet.id, tablet.words.expect("derived").shown());
        let question = address_book::remove_question("Tablet");
        let named = |window: &Window| {
            let words = format!("device words: {words}");
            window
                .nodes
                .iter()
                .filter(|n| n.value() == Some(words.as_str()))
                .count()
        };
        let mut window = devices_tab(model.clone());
        assert_eq!(remove_buttons(&window).len(), 2, "one per card");
        assert!(!has_text(&window, address_book::NO_REMOVE));
        let on_its_card = named(&window);
        assert!(on_its_card > 0);
        let at = remove_buttons(&window)[1];
        assert!(window.click(at).is_empty(), "the question first");
        assert_eq!(window.form.book.removing, Some(id));
        assert!(window.pass(Vec::new()).is_empty());
        assert!(has_text(&window, &question));
        assert_eq!(named(&window), 2 * on_its_card, "and in the question");
        let keep = window.center("Keep it");
        assert!(window.click(keep).is_empty());
        assert_eq!(window.form.book.removing, None);
        assert!(window.pass(Vec::new()).is_empty());
        assert!(!has_text(&window, &question));
        let at = remove_buttons(&window)[1];
        assert!(window.click(at).is_empty());
        assert!(window.pass(Vec::new()).is_empty());
        let sure = window.center(address_book::REMOVE);
        assert_eq!(
            window.click(sure),
            vec![Action::Manager(ManagerOp::Remove(id))]
        );
        assert_eq!(window.form.book.removing, None);
        for _ in 0..3 {
            assert!(window.pass(Vec::new()).is_empty(), "sent once");
        }
        assert!(!has_text(&window, &question));
        model.manager = None;
        let window = devices_tab(model);
        assert!(remove_buttons(&window).is_empty());
        assert!(has_text(&window, address_book::NO_REMOVE));
    }

    // ------------------------------------------------------------ the Sessions page (§B.8.13)

    /// A session that ended here, a refused request and a client connect, as
    /// the log holds them: with a device key, a grant id, a path, a transport
    /// and free details, none of which the page may show.
    fn session_lines() -> Vec<tornect_core::session_log::SessionRecord> {
        use tornect_core::session_log::{SessionEvent, SessionMode, SessionRecord, TransportKind};
        let [laptop, tablet, desk] = [1, 2, 3].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        let mut started = SessionRecord::now(SessionEvent::SessionStarted)
            .peer(laptop, "Office laptop")
            .session("s1")
            .mode(SessionMode::Control)
            .unattended(true)
            .transport(TransportKind::Direct)
            .grant(&[7; 8]);
        started.path = Some("/home/someone/secret".to_owned());
        let ended = SessionRecord::now(SessionEvent::SessionEnded)
            .peer(laptop, "Office laptop")
            .session("s1")
            .detail("Killed(3)");
        let denied = SessionRecord::now(SessionEvent::SessionDenied)
            .peer(tablet, "Tablet")
            .detail("busy elsewhere");
        let connect = SessionRecord::now(SessionEvent::UnattendedConnect)
            .peer(desk, "Desk")
            .session("c1")
            .mode(SessionMode::ViewOnly)
            .unattended(true)
            .reason("accepted");
        vec![started, ended, denied, connect]
    }

    /// The Sessions page over `records`' rows at `size`, this screen shared
    /// or not.
    fn sessions_window(
        records: &[tornect_core::session_log::SessionRecord],
        shared: bool,
        size: (f32, f32),
    ) -> Window {
        let mut model = at_rest();
        model.sessions = Some(session_rows(records));
        model.log_folder = Some("/home/someone/.local/share/tornect/logs".to_owned());
        if shared {
            model.sharing = vec![super::super::model::Sharing {
                session_id: "00".to_owned(),
                label: "Viewer".to_owned(),
                control: false,
                unattended: false,
                since: Instant::now(),
                capture: None,
            }];
        }
        Window::new(model, Page::Sessions, egui::Theme::Dark, size)
    }

    /// Whether any node of `window` names or says `text`.
    fn anywhere(window: &Window, text: &str) -> bool {
        window.nodes.iter().any(|n| {
            n.value().is_some_and(|v| v.contains(text))
                || n.label().is_some_and(|l| l.contains(text))
        })
    }

    /// §B.8.13, as the operator ruled: the Sessions page shows the time, the
    /// pinned label, the mode, attended or unattended and how it ended, each
    /// from a fixed list, and nothing else of the lines: no device key, grant
    /// id, path, transport or free detail; drawing it asks nothing; "Open log
    /// folder" shows the folder's path and asks nothing.
    #[test]
    fn the_sessions_page_shows_only_the_planned_columns() {
        let records = session_lines();
        let laptop = tornect_core::DeviceId::from_bytes([1; 32]);
        for size in [WIDE, NARROW] {
            let mut window = sessions_window(&records, false, size);
            for title in sessions::COLUMNS {
                assert!(has_text(&window, title), "{size:?}: {title}");
            }
            for text in [
                "Office laptop",
                "Control",
                "Unattended",
                "ended here",
                "Tablet",
                "refused",
                "Desk",
                "View only",
                "connected",
            ] {
                assert!(has_text(&window, text), "{size:?}: {text}");
            }
            for hidden in [
                laptop.fingerprint(),
                "0707070707070707".to_owned(),
                "/home/someone".to_owned(),
                "Killed".to_owned(),
                "busy elsewhere".to_owned(),
                "Direct".to_owned(),
            ] {
                assert!(!anywhere(&window, &hidden), "{size:?}: {hidden}");
            }
            assert!(window.pass(Vec::new()).is_empty(), "drawing asks nothing");
            let at = window.center(sessions::OPEN_LOG_FOLDER);
            assert!(window.click(at).is_empty(), "{size:?}: asks nothing");
            // The path is drawn in the pass after the click.
            assert!(window.pass(Vec::new()).is_empty());
            assert!(
                has_text(&window, "/home/someone/.local/share/tornect/logs"),
                "{size:?}"
            );
        }
    }

    /// While this screen may be in a picture that leaves it, the Sessions
    /// page shows the hidden card: no row, no column, no folder.
    #[test]
    fn the_sessions_page_while_shared_shows_the_hidden_card() {
        let records = session_lines();
        for size in [WIDE, NARROW] {
            let window = sessions_window(&records, true, size);
            assert!(has_text(&window, HIDDEN_WHILE_SHARED), "{size:?}");
            assert!(has_text(&window, sessions::HIDDEN), "{size:?}");
            for text in ["Office laptop", "Tablet", "Desk", "How it ended"] {
                assert!(!anywhere(&window, text), "{size:?}: {text}");
            }
            assert!(!anywhere(&window, sessions::OPEN_LOG_FOLDER), "{size:?}");
        }
    }

    /// Settings, Privacy links to the Sessions page, but not while this
    /// screen is shared.
    #[test]
    fn the_privacy_page_links_to_the_sessions_page() {
        use settings::privacy::PAST_SESSIONS;
        // Tall enough for the page's last sections.
        let mut window = privacy(with_book(false), (1200.0, 2400.0));
        let at = window.center(PAST_SESSIONS);
        assert!(window.click(at).is_empty());
        assert_eq!(window.form.page, Page::Sessions);
        let mut shared = with_book(false);
        shared.hosted_elsewhere = true;
        let window = privacy(shared, (1200.0, 2400.0));
        assert!(!anywhere(&window, PAST_SESSIONS));
    }
}
