//! Terminal UI built with ratatui.

use std::io::{self, Stdout};
use std::time::Instant;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;
use ratatui::Terminal;

use crate::capture::SharedFlows;
use crate::dns::DnsCache;
use crate::flow::{format_bytes, format_rate};

pub struct App {
    pub flows: SharedFlows,
    pub dns: std::sync::Arc<DnsCache>,
    pub interface: String,
    pub show_ports: bool,
    pub enable_dns: bool,
    pub max_lines: usize,
    pub should_quit: bool,
}

impl App {
    pub fn new(
        flows: SharedFlows,
        dns: std::sync::Arc<DnsCache>,
        interface: String,
        show_ports: bool,
        enable_dns: bool,
        max_lines: usize,
    ) -> Self {
        Self {
            flows,
            dns,
            interface,
            show_ports,
            enable_dns,
            max_lines,
            should_quit: false,
        }
    }
}

type Term = Terminal<CrosstermBackend<Stdout>>;

pub fn init_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

pub fn restore_terminal(terminal: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

pub fn run_ui(app: &mut App, terminal: &mut Term, interval_ms: u64) -> io::Result<()> {
    let tick = std::time::Duration::from_millis(interval_ms);

    loop {
        terminal.draw(|f| draw(f, app))?;

        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('n') => {
                        app.enable_dns = !app.enable_dns;
                    }
                    KeyCode::Char('p') => {
                        app.show_ports = !app.show_ports;
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }

        {
            let mut table = app.flows.lock();
            table.expire(Instant::now(), std::time::Duration::from_secs(60));
        }
    }
    Ok(())
}

fn draw(f: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);
    draw_table(f, chunks[1], app);
    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let title = format!(
        " Riftop — interface: {}  |  flows: {}  |  DNS: {}  |  ports: {} ",
        app.interface,
        app.flows.lock().len(),
        if app.enable_dns { "on" } else { "off" },
        if app.show_ports { "on" } else { "off" },
    );
    let header = Paragraph::new(title)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Realtime bandwidth"));
    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame<'_>, area: Rect, app: &App) {
    let now = Instant::now();
    let table = app.flows.lock();
    let top = table.top(app.max_lines, now);

    if app.enable_dns {
        for stats in &top {
            app.dns.resolve_async(stats.key.a);
            app.dns.resolve_async(stats.key.b);
        }
    }

    let header_cells = ["#", "Host pair", "2s", "10s", "40s", "Total"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows = top.iter().enumerate().map(|(i, stats)| {
        let a = app.dns.display(&stats.key.a, app.enable_dns);
        let b = app.dns.display(&stats.key.b, app.enable_dns);
        let pair = if app.show_ports {
            format!("{a}:{} \u2194 {b}:{}", stats.key.port_a, stats.key.port_b)
        } else {
            format!("{a} \u2194 {b}")
        };

        let cells = [
            Cell::from((i + 1).to_string()),
            Cell::from(pair),
            Cell::from(format_rate(stats.rate_2s(now))),
            Cell::from(format_rate(stats.rate_10s(now))),
            Cell::from(format_rate(stats.rate_40s(now))),
            Cell::from(format_bytes(stats.total_bytes)),
        ];
        Row::new(cells)
    });

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(45),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let t = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top flows"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(t, area);
}

fn draw_footer(f: &mut Frame<'_>, area: Rect) {
    let help = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" toggle DNS  "),
        Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" toggle ports"),
    ]);
    let footer = Paragraph::new(help).block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, area);
}
