//! Terminal UI built with ratatui.

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;
use ratatui::Terminal;

use riftop::capture::SharedFlows;
use riftop::dns::DnsCache;
use riftop::filters::ScreenFilter;
use riftop::flow::{format_bytes, Aggregate, Snapshot};

use crate::alerts::AlertEngine;
use crate::top::{format_top_row, top_hosts, top_ports, top_protocols, ViewMode};

use riftop::flow::SortBy;

pub struct App {
    pub flows: SharedFlows,
    pub dns: std::sync::Arc<DnsCache>,
    pub interface: String,
    pub show_ports: bool,
    pub no_port_resolution: bool,
    pub use_bytes: bool,
    pub no_bars: bool,
    pub enable_dns: bool,
    pub max_lines: usize,
    pub should_quit: bool,
    pub aggregate: Aggregate,
    pub sort: SortBy,
    pub screen_filter: ScreenFilter,
    pub capture_filter: Option<String>,
    pub offline: bool,
    pub view: ViewMode,
    pub dropped: Option<Arc<AtomicU64>>,
    pub alerts: Option<AlertEngine>,
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
            no_port_resolution: false,
            use_bytes: false,
            no_bars: false,
            enable_dns,
            max_lines,
            should_quit: false,
            aggregate: Aggregate::Pair,
            sort: SortBy::Rate10s,
            screen_filter: ScreenFilter::default(),
            capture_filter: None,
            offline: false,
            view: ViewMode::Flows,
            dropped: None,
            alerts: None,
        }
    }
}

type Term = Terminal<CrosstermBackend<Stdout>>;

pub fn init_terminal() -> io::Result<Term> {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        default_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
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

fn draw(f: &mut Frame<'_>, app: &App) {
    let has_alerts = app
        .alerts
        .as_ref()
        .map(|a| a.recent().next().is_some())
        .unwrap_or(false);
    let header_h = if has_alerts { 6 } else { 5 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_h),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(f.size());

    draw_header(f, chunks[0], app);
    draw_table(f, chunks[1], app);
    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let now = Instant::now();
    let snap = app
        .flows
        .lock()
        .snapshot_sorted(app.max_lines, now, app.sort);
    let g = &snap.globals;
    let drop_n = app
        .dropped
        .as_ref()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(0);

    let agg = match app.aggregate {
        Aggregate::Pair => "pair",
        Aggregate::Source => "src",
        Aggregate::Destination => "dst",
    };
    let mode = if app.offline { "PCAP" } else { "LIVE" };
    let bpf = app.capture_filter.as_deref().unwrap_or("(none)");

    let line1 = format!(
        " {mode}  iface: {}  |  view: {}  |  agg: {agg}  |  DNS: {} ",
        app.interface,
        app.view.title(),
        if app.enable_dns { "on" } else { "off" },
    );
    let line2 = format!(" CAPTURE FILTER: {bpf}");
    let line3 = format!(
        " CAPTURED: {} pkts / {}   VISIBLE: {}   TX {}  RX {}   DROP {} ",
        g.packets_accepted,
        format_bytes(g.bytes_total),
        snap.flows.len().min(app.max_lines),
        format_bytes(g.bytes_sent),
        format_bytes(g.bytes_recv),
        drop_n,
    );

    let mut text = vec![
        Line::from(Span::styled(
            line1,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(line2, Style::default().fg(Color::Yellow))),
        Line::from(Span::styled(line3, Style::default().fg(Color::Green))),
    ];

    if let Some(ae) = &app.alerts {
        if let Some(msg) = ae.latest_messages(1).into_iter().next() {
            text.push(Line::from(Span::styled(
                format!(" ALERT: {msg} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )));
        }
    }

    let header = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Riftop — realtime bandwidth"),
    );
    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame<'_>, area: Rect, app: &App) {
    let now = Instant::now();
    let snap = app.flows.lock().snapshot_sorted(256, now, app.sort);

    if app.enable_dns {
        for stats in &snap.flows {
            app.dns.resolve_async(stats.key.a);
            app.dns.resolve_async(stats.key.b);
        }
    }

    match app.view {
        ViewMode::Flows => draw_flows(f, area, app, &snap, now),
        ViewMode::Hosts => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_hosts(&snap, now, app.max_lines),
        ),
        ViewMode::Ports => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_ports(&snap, now, app.max_lines),
        ),
        ViewMode::Protocols => draw_top_rows(
            f,
            area,
            app.view.title(),
            &top_protocols(&snap, now, app.max_lines),
        ),
    }
}

fn draw_flows(f: &mut Frame<'_>, area: Rect, app: &App, snap: &Snapshot, now: Instant) {
    let header_cells = ["#", "Host pair", "2s", "10s", "40s", "Total", "TCP"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows = snap
        .flows
        .iter()
        .filter(|stats| {
            let a = app.dns.display(&stats.key.a, app.enable_dns);
            let b = app.dns.display(&stats.key.b, app.enable_dns);
            app.screen_filter.matches(&a, &b)
        })
        .take(app.max_lines)
        .enumerate()
        .map(|(i, stats)| {
            let a = app.dns.display(&stats.key.a, app.enable_dns);
            let b = app.dns.display(&stats.key.b, app.enable_dns);
            let port_a_str = if app.no_port_resolution {
                stats.key.port_a.to_string()
            } else {
                riftop::services::service_name(stats.key.port_a, stats.key.protocol)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| stats.key.port_a.to_string())
            };
            let port_b_str = if app.no_port_resolution {
                stats.key.port_b.to_string()
            } else {
                riftop::services::service_name(stats.key.port_b, stats.key.protocol)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| stats.key.port_b.to_string())
            };
            let pair = if app.show_ports {
                format!("{a}:{port_a_str} \u{2194} {b}:{port_b_str}")
            } else {
                format!("{a} \u{2194} {b}")
            };
            Row::new([
                Cell::from((i + 1).to_string()),
                Cell::from(pair),
                Cell::from(riftop::flow::format_rate_units(
                    stats.rate_2s(now),
                    app.use_bytes,
                )),
                Cell::from(riftop::flow::format_rate_units(
                    stats.rate_10s(now),
                    app.use_bytes,
                )),
                Cell::from(riftop::flow::format_rate_units(
                    stats.rate_40s(now),
                    app.use_bytes,
                )),
                Cell::from(format_bytes(stats.total_bytes)),
                Cell::from(stats.tcp.summary()),
            ])
        });

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(40),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(14),
    ];
    let t = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top flows"));
    f.render_widget(t, area);
}

fn draw_top_rows(f: &mut Frame<'_>, area: Rect, title: &str, rows_data: &[crate::top::TopRow]) {
    let header_cells = ["#", "Name", "2s", "10s", "40s", "Total"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows = rows_data.iter().enumerate().map(|(i, row)| {
        let (label, r2, r10, r40, tot) = format_top_row(row);
        Row::new([
            Cell::from((i + 1).to_string()),
            Cell::from(label),
            Cell::from(r2),
            Cell::from(r10),
            Cell::from(r40),
            Cell::from(tot),
        ])
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
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(t, area);
}

fn draw_footer(f: &mut Frame<'_>, area: Rect) {
    let help = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("quit  "),
        Span::styled(" 1-4 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("views  "),
        Span::styled(" Tab ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("cycle  "),
        Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("ports"),
    ]);
    let footer = Paragraph::new(help).block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, area);
}
