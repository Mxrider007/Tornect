//! The main window's pages (the redesign's §4). In this version Home and the
//! Address book show what works today; Sessions and Settings, whose content
//! comes in later versions, each show one plain line saying so, and never a
//! control that does nothing. The widget gallery is reached only from the
//! preview. Trust surfaces are not pages: the open questions are drawn above
//! the page, the banner above everything (`view`).

mod address_book;
mod gallery;
mod home;

use std::time::Instant;

use egui::{RichText, Ui};
use tornect_core::address_book::Day;

pub use self::address_book::BookForm;
use super::model::Model;
use super::nav::Page;
use super::theme::{self, Face};
use super::view::{Action, Form};

/// Draw `page`.
pub fn draw(
    ui: &mut Ui,
    page: Page,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    match page {
        Page::Home => home::home(ui, model, form, now, actions),
        Page::AddressBook => address_book::page(ui, model, form, model.screen_shared(now), actions),
        Page::Sessions => later(
            ui,
            page,
            "The list of past sessions arrives in a later version; each session is already \
             recorded in this computer's session log.",
        ),
        Page::Settings => later(
            ui,
            page,
            "Settings arrive in a later version; until then, the command line's help lists \
             the commands that change them.",
        ),
        Page::Widgets => gallery::gallery(ui),
    }
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

/// A page whose content comes in a later version: its title and one line.
fn later(ui: &mut Ui, page: Page, note: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(page.title())
            .font(theme::font(ui.ctx(), Face::Bold, 26.0))
            .color(t.text_primary),
    );
    ui.label(
        RichText::new(note)
            .font(theme::font(ui.ctx(), Face::Regular, 14.0))
            .color(t.text_secondary),
    );
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use egui::accesskit::{Node, Role};
    use tornect_core::TornectId;
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

    /// A page whose content comes later shows its one line and no control:
    /// nothing to press or type into but the sidebar's pages.
    #[test]
    fn a_later_page_offers_no_control() {
        let listed: Vec<&str> = Page::LISTED.iter().map(|p| p.title()).collect();
        for page in [Page::Sessions, Page::Settings] {
            for size in [WIDE, NARROW] {
                let window = Window::new(at_rest(), page, egui::Theme::Dark, size);
                for control in window.controls() {
                    assert!(
                        listed.contains(&control.as_str()),
                        "{page:?}: \"{control}\" does nothing yet"
                    );
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
    /// own, and saves it with the name typed.
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
            ("not an id".to_owned(), Some("That is not a Tornect ID")),
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
        // The saved cards' Connect: the first "Connect" is the connect card's.
        let connects: Vec<egui::Pos2> = window
            .nodes
            .iter()
            .filter(|n| n.label() == Some("Connect"))
            .filter_map(Node::bounds)
            .map(|b| egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32))
            .collect();
        assert_eq!(connects.len(), 4, "the connect card's and three saved ones");
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
    /// the newest card's Deny and accepts are inside the sheet's room; and
    /// when the room shrinks, they are brought back into view.
    #[test]
    fn the_newest_questions_answers_stay_in_view() {
        for size in [WIDE, NARROW] {
            for questions in [
                vec![pairing_question(1), session_question(2, "Laptop")],
                vec![
                    pairing_question(1),
                    session_question(2, "Laptop"),
                    session_question(3, "Tablet"),
                ],
            ] {
                let open = questions.len();
                let mut model = at_rest();
                model.popups = questions;
                let mut window = Window::new(model, Page::Home, egui::Theme::Dark, size);
                assert!(has_text(&window, &format!("{open} questions are open")));
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
}
