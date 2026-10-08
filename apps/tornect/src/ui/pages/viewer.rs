//! The stream window's state between frames (the redesign's S6). It lives in
//! the app's stream window of one session and dies with it, so nothing in it
//! outlives the session.

/// What the stream window of one session keeps between frames.
#[derive(Debug, Default)]
pub struct ViewerState {
    /// This computer's screen may be in a picture that leaves it
    /// (`Model::screen_shared`), read every frame: the window then names
    /// nobody.
    pub shared: bool,
    /// The chord took the keyboard back from the remote computer: keys go to
    /// this window's controls until the chord again, or a press on the
    /// picture, gives it back.
    pub keyboard_local: bool,
}
