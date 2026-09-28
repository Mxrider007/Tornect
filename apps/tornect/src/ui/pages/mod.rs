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
        Page::AddressBook => address_book::page(ui, model, form, actions),
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
            let now = self.start + Duration::from_secs(5);
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
}
