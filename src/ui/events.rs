#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
#![allow(clippy::all)]
//! UI event loop and keyboard input handling.

use std::io;
use std::time::Instant;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use crate::flow::Aggregate;
use crate::top::ViewMode;
use crate::ui::app::App;
use crate::ui::render::draw;
use crate::ui::terminal::Term;

/// Runs the interactive terminal UI event loop until user quits or signal received.
///
/// # Errors
///
/// Returns an error if terminal drawing or event polling fails.
pub fn run_ui(app: &mut App, terminal: &mut Term, interval_ms: u64) -> io::Result<()> {
    let tick = std::time::Duration::from_millis(interval_ms);

    loop {
        {
            let now = Instant::now();
            let snap = app.flows.lock().snapshot(app.max_lines, now);
            if let Some(ae) = app.alerts.as_mut() {
                ae.evaluate(&snap, now);
            }
        }

        terminal.draw(|f| draw(f, app))?;

        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('n') => app.enable_dns = !app.enable_dns,
                    KeyCode::Char('p') => {
                        app.show_ports = !app.show_ports;
                        app.flows.lock().set_show_ports(app.show_ports);
                    }
                    KeyCode::Char('s') => {
                        app.aggregate = Aggregate::Source;
                        app.flows.lock().set_aggregate(Aggregate::Source);
                    }
                    KeyCode::Char('d') => {
                        app.aggregate = Aggregate::Destination;
                        app.flows.lock().set_aggregate(Aggregate::Destination);
                    }
                    KeyCode::Char('a') => {
                        app.aggregate = Aggregate::Pair;
                        app.flows.lock().set_aggregate(Aggregate::Pair);
                    }
                    KeyCode::Char('1') => app.view = ViewMode::Flows,
                    KeyCode::Char('2') => app.view = ViewMode::Hosts,
                    KeyCode::Char('3') => app.view = ViewMode::Ports,
                    KeyCode::Char('4') => app.view = ViewMode::Protocols,
                    KeyCode::Tab => app.view = app.view.cycle(),
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }

        if !app.offline {
            app.flows
                .lock()
                .expire(Instant::now(), std::time::Duration::from_secs(60));
        }
    }
    Ok(())
}
