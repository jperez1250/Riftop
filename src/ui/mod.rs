#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
//! Terminal UI built with ratatui.

#![allow(clippy::all)]

pub mod app;
pub mod events;
pub mod render;
pub mod terminal;

pub use app::App;
pub use events::run_ui;
pub use terminal::{init_terminal, restore_terminal, Term};
