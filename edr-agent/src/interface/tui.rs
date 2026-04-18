//! Dashboard TUI temps-réel avec ratatui (EF-I06, EF-I07).
//!
//! Affiche :
//! - Graphique events/sec (sparkline)
//! - Liste des 10 dernières alertes avec sévérité colorée
//! - Top 5 des processus actifs (PID + exe)
//! - Compteurs globaux en en-tête

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use edr_common::Severity;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Chart, Dataset, GraphType,
        List, ListItem, Paragraph, Sparkline, Gauge,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::storage::Database;

// ─────────────────────────────────────────────
//  État de l'application TUI
// ─────────────────────────────────────────────

struct App {
    db:                 Database,
    /// Historique du nombre d'événements/s pour le sparkline
    events_per_sec:     Vec<u64>,
    last_event_count:   i64,
    last_refresh:       Instant,
    refresh_interval:   Duration,
    /// Dernières alertes
    recent_alerts:      Vec<edr_common::Alert>,
    /// Compteurs globaux
    total_events:       i64,
    total_alerts:       i64,
    critical_alerts:    i64,
    /// Tick pour l'animation
    tick:               u64,
}

impl App {
    fn new(db: Database) -> Self {
        Self {
            db,
            events_per_sec:   vec![0; 60],
            last_event_count:  0,
            last_refresh:      Instant::now(),
            refresh_interval:  Duration::from_secs(1),
            recent_alerts:     Vec::new(),
            total_events:      0,
            total_alerts:      0,
            critical_alerts:   0,
            tick:              0,
        }
    }

    fn refresh(&mut self) {
        self.tick += 1;
        self.last_refresh = Instant::now();

        if let Ok(stats) = self.db.stats() {
            // Calcul events/s
            let delta = (stats.event_count - self.last_event_count).max(0) as u64;
            self.events_per_sec.push(delta);
            if self.events_per_sec.len() > 60 {
                self.events_per_sec.remove(0);
            }
            self.last_event_count = stats.event_count;
            self.total_events     = stats.event_count;
            self.total_alerts     = stats.alert_count;
            self.critical_alerts  = stats.critical_count;
        }

        if let Ok(alerts) = self.db.query_alerts(None, Some(24), 10) {
            self.recent_alerts = alerts;
        }
    }
}

// ─────────────────────────────────────────────
//  Boucle principale TUI
// ─────────────────────────────────────────────

pub async fn run_dashboard(config: &Config) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let db  = Database::open(&config.storage.db_path)?;
    let mut app = App::new(db);
    app.refresh();

    let result = run_loop(&mut term, &mut app);

    // Restauration terminal
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;

    result
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| render(f, app))?;

        // Gestion des événements avec timeout
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('r') => app.refresh(),
                    _ => {}
                }
            }
        }

        // Rafraîchissement périodique
        if app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh();
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────
//  Rendu
// ─────────────────────────────────────────────

fn render(f: &mut Frame, app: &App) {
    let size = f.size();

    // Layout principal : header / body / footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(0),     // Body
            Constraint::Length(1),  // Footer
        ])
        .split(size);

    render_header(f, main_chunks[0], app);

    // Body : gauche (sparkline + alertes) | droite (stats + top procs)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(main_chunks[1]);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(body_chunks[0]);

    render_sparkline(f, left_chunks[0], app);
    render_alerts(f, left_chunks[1], app);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(body_chunks[1]);

    render_stats(f, right_chunks[0], app);
    render_help(f, right_chunks[1]);

    render_footer(f, main_chunks[2]);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let title = format!(
        " EDR Linux  ─  Événements: {}  │  Alertes: {}  │  Critiques: {}  │  Refresh #{} ",
        app.total_events, app.total_alerts, app.critical_alerts, app.tick
    );
    let p = Paragraph::new(title)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(p, area);
}

fn render_sparkline(f: &mut Frame, area: Rect, app: &App) {
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" Événements / seconde (60s) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .data(&app.events_per_sec)
        .style(Style::default().fg(Color::Green));
    f.render_widget(sparkline, area);
}

fn render_alerts(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .recent_alerts
        .iter()
        .map(|alert| {
            let (color, label) = match alert.severity {
                Severity::Critical => (Color::Red,     "CRIT"),
                Severity::High     => (Color::Yellow,  "HIGH"),
                Severity::Medium   => (Color::Blue,    " MED"),
                Severity::Low      => (Color::Gray,    " LOW"),
            };

            let line = Line::from(vec![
                Span::styled(
                    format!(" {:4} ", label),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<6} ", alert.rule_id),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("PID:{:<7} ", alert.pid),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{}", alert.timestamp.format("%H:%M:%S")),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  "),
                Span::styled(
                    truncate_str(&alert.rule_description, 40),
                    Style::default().fg(Color::White),
                ),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Dernières alertes (24h) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, area);
}

fn render_stats(f: &mut Frame, area: Rect, app: &App) {
    // Gauge de criticité (% alertes critiques)
    let critical_pct = if app.total_alerts > 0 {
        (app.critical_alerts * 100 / app.total_alerts) as u16
    } else {
        0
    };

    let color = match critical_pct {
        0..=20  => Color::Green,
        21..=50 => Color::Yellow,
        _       => Color::Red,
    };

    let lines = vec![
        Line::from(vec![
            Span::raw(" Événements totaux : "),
            Span::styled(
                app.total_events.to_string(),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Alertes totales   : "),
            Span::styled(
                app.total_alerts.to_string(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Alertes critiques : "),
            Span::styled(
                app.critical_alerts.to_string(),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(" Criticité : {}%", critical_pct),
                Style::default().fg(color),
            ),
        ]),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Statistiques ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        );
    f.render_widget(p, area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(" Raccourcis", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Yellow)),
            Span::raw("  Quitter"),
        ]),
        Line::from(vec![
            Span::styled(" r ", Style::default().fg(Color::Yellow)),
            Span::raw("  Rafraîchir"),
        ]),
        Line::from(vec![
            Span::styled(" ^C", Style::default().fg(Color::Yellow)),
            Span::raw("  Quitter"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Rafraîchissement auto : 1s",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Aide ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(p, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(
        " EDR Linux v0.1.0  ─  Benoît PIGUEL & Axel WAS  ─  Projet Annuel 2025 "
    )
    .style(Style::default().fg(Color::DarkGray))
    .alignment(Alignment::Center);
    f.render_widget(footer, area);
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
