//! Dashboard TUI temps-réel avec ratatui.
//!
//! Affiche :
//! - Compteurs globaux (événements, alertes)
//! - Liste des 15 dernières alertes avec sévérité colorée
//!
//! Quitter : q ou Ctrl-C

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::{io, sync::Arc, time::Duration};

use crate::storage::Database;

pub async fn run(db: Arc<Database>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, &db).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn event_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    db: &Database,
) -> Result<()> {
    loop {
        // Lecture des données
        let (total_events, total_alerts) = db.stats().unwrap_or((0, 0));
        let alerts = db.recent_alerts(15).unwrap_or_default();

        terminal.draw(|f| render(f, total_events, total_alerts, &alerts))?;

        // Gestion clavier avec timeout 1s
        if event::poll(Duration::from_secs(1))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn render(
    f: &mut Frame,
    total_events: i64,
    total_alerts: i64,
    alerts: &[(String, String, String)],
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(f.size());

    // ── En-tête ──────────────────────────────────────────────────────
    let header = Paragraph::new(format!(
        "  EDR Linux  │  Événements : {}  │  Alertes : {}",
        total_events, total_alerts
    ))
    .style(Style::default().fg(Color::White).bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .block(Block::default().borders(Borders::NONE));
    f.render_widget(header, chunks[0]);

    // ── Liste des alertes ─────────────────────────────────────────────
    let items: Vec<ListItem> = alerts.iter().map(|(rule, sev, msg)| {
        let color = match sev.as_str() {
            "CRITICAL" => Color::Red,
            "HIGH"     => Color::Yellow,
            "MEDIUM"   => Color::Blue,
            _          => Color::Gray,
        };
        let line = Line::from(vec![
            Span::styled(format!(" {:8} ", sev), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<8} ", rule), Style::default().fg(Color::Cyan)),
            Span::raw(msg.as_str()),
        ]);
        ListItem::new(line)
    }).collect();

    let list = List::new(items)
        .block(Block::default().title(" Dernières alertes ").borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)));
    f.render_widget(list, chunks[1]);

    // ── Pied de page ─────────────────────────────────────────────────
    let footer = Paragraph::new("  q : quitter")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}
