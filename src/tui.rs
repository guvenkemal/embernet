use crate::proto::{Envelope, KeypairFile, Message};
use crate::store::{self, ChannelRef, PolicyMode, append_message};
use crate::sync;
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Normal,
    Post,
    Peer,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    None,
    Post(String),
    Sync(String),
}

struct App {
    datadir: PathBuf,
    identity: KeypairFile,
    channels: Vec<String>,
    selected: usize,
    messages: Vec<Envelope>,
    scroll: u16,
    audit: bool,
    mode: InputMode,
    input: String,
    status: String,
    role: String,
    policy_conflicts: usize,
    moderation_conflicts: usize,
    quit: bool,
}

impl App {
    fn load(datadir: PathBuf) -> Result<Self> {
        let identity_path = datadir.join("keys/identity.json");
        let identity = KeypairFile::load(&identity_path)
            .with_context(|| format!("load identity {}", identity_path.display()))?;
        let channels = store::list_channels(&datadir)?;
        let mut app = Self {
            datadir,
            identity,
            channels,
            selected: 0,
            messages: Vec::new(),
            scroll: 0,
            audit: false,
            mode: InputMode::Normal,
            input: String::new(),
            status: "ready".into(),
            role: "-".into(),
            policy_conflicts: 0,
            moderation_conflicts: 0,
            quit: false,
        };
        app.refresh()?;
        Ok(app)
    }

    fn channel(&self) -> Option<&str> {
        self.channels.get(self.selected).map(String::as_str)
    }

    fn refresh(&mut self) -> Result<()> {
        let Some(channel) = self.channel().map(str::to_owned) else {
            self.messages.clear();
            self.role = "-".into();
            return Ok(());
        };
        let chan = ChannelRef::parse(&channel)?;
        self.messages =
            store::read_channel_tail_with_options(&self.datadir, &chan, 500, self.audit)?;
        let policy = store::read_channel_policy(&self.datadir, &chan)?;
        self.role = if policy.mode == PolicyMode::Open {
            "open writer".into()
        } else if policy.owner.as_deref() == Some(&self.identity.public_key) {
            "owner".into()
        } else if policy.moderators.contains(&self.identity.public_key) {
            "moderator".into()
        } else if policy.writers.contains(&self.identity.public_key) {
            "writer".into()
        } else {
            "reader".into()
        };
        self.policy_conflicts = store::list_policy_conflicts(&self.datadir, &chan)?.len();
        self.moderation_conflicts = store::list_moderation_conflicts(&self.datadir, &chan)?.len();
        self.scroll = 0;
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<Action> {
        if self.mode != InputMode::Normal {
            return Ok(match key.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Normal;
                    self.input.clear();
                    Action::None
                }
                KeyCode::Enter => {
                    let value = self.input.trim().to_string();
                    let mode = self.mode;
                    self.mode = InputMode::Normal;
                    self.input.clear();
                    if value.is_empty() {
                        Action::None
                    } else if mode == InputMode::Post {
                        Action::Post(value)
                    } else {
                        Action::Sync(value)
                    }
                }
                KeyCode::Backspace => {
                    self.input.pop();
                    Action::None
                }
                KeyCode::Char(character) => {
                    self.input.push(character);
                    Action::None
                }
                _ => Action::None,
            });
        }

        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Up | KeyCode::Char('K') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.refresh()?;
                }
            }
            KeyCode::Down | KeyCode::Char('J') => {
                if self.selected + 1 < self.channels.len() {
                    self.selected += 1;
                    self.refresh()?;
                }
            }
            KeyCode::Char('k') | KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Char('j') | KeyCode::PageDown => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Char('a') => {
                self.audit = !self.audit;
                self.refresh()?;
                self.status = if self.audit {
                    "audit view includes tombstoned messages".into()
                } else {
                    "normal moderated view".into()
                };
            }
            KeyCode::Char('p') if self.channel().is_some() => {
                self.mode = InputMode::Post;
                self.input.clear();
            }
            KeyCode::Char('s') if self.channel().is_some() => {
                self.mode = InputMode::Peer;
                self.input = "ws://127.0.0.1:4444/sync".into();
            }
            KeyCode::Char('r') => {
                self.channels = store::list_channels(&self.datadir)?;
                self.selected = self.selected.min(self.channels.len().saturating_sub(1));
                self.refresh()?;
                self.status = "refreshed".into();
            }
            _ => {}
        }
        Ok(Action::None)
    }

    async fn apply(&mut self, action: Action) {
        if action == Action::None {
            return;
        }
        let result: Result<String> = async {
            let channel = self.channel().context("no channel selected")?.to_string();
            let chan = ChannelRef::parse(&channel)?;
            match action {
                Action::Post(body) => {
                    let envelope = Envelope::sign(
                        self.identity.clone(),
                        &channel,
                        Message::new_text(None, Vec::new(), body, Vec::new()),
                    )?;
                    let id = append_message(&self.datadir, &chan, &envelope)?;
                    Ok(format!("posted {}", &id[..12]))
                }
                Action::Sync(peer) => {
                    let received = sync::sync_from_peer(&self.datadir, &peer, &channel).await?;
                    Ok(format!("sync complete: {received} received"))
                }
                Action::None => unreachable!("no-op actions are handled before execution"),
            }
        }
        .await;
        match result {
            Ok(status) => {
                self.status = status;
                if let Err(error) = self.refresh() {
                    self.status = format!("refresh failed: {error:#}");
                }
            }
            Err(error) => self.status = format!("error: {error:#}"),
        }
    }
}

pub async fn run(datadir: PathBuf) -> Result<()> {
    let mut app = App::load(datadir)?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    while !app.quit {
        terminal.draw(|frame| render(frame, app))?;
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            let action = app.handle_key(key)?;
            if action != Action::None {
                app.apply(action).await;
            }
        }
    }
    Ok(())
}

fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(4)])
        .split(frame.area());
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(areas[0]);
    render_channels(frame, app, body[0]);
    render_timeline(frame, app, body[1]);
    render_footer(frame, app, areas[1]);
}

fn render_channels(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let items: Vec<ListItem<'_>> = app
        .channels
        .iter()
        .map(|channel| ListItem::new(channel.as_str()))
        .collect();
    let mut state = ListState::default().with_selected(if items.is_empty() {
        None
    } else {
        Some(app.selected)
    });
    let list = List::new(items)
        .block(Block::default().title(" Channels ").borders(Borders::ALL))
        .highlight_symbol("> ")
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_timeline(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let mut lines = Vec::new();
    for envelope in &app.messages {
        let time = chrono::DateTime::from_timestamp(envelope.ts, 0)
            .map(|time| time.format("%H:%M").to_string())
            .unwrap_or_else(|| "??:??".into());
        let author = envelope
            .from_alias
            .as_deref()
            .unwrap_or_else(|| envelope.from.get(..10).unwrap_or(&envelope.from));
        lines.push(Line::from(vec![
            Span::styled(time, Style::default().fg(Color::DarkGray)),
            Span::raw("  "),
            Span::styled(
                author.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::raw(
            envelope
                .body_text()
                .unwrap_or("[non-text message]")
                .to_string(),
        ));
        lines.push(Line::raw(""));
    }
    let title = format!(
        " {} · {}{} ",
        app.channel().unwrap_or("No channel"),
        app.role,
        if app.audit { " · AUDIT" } else { "" }
    );
    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));
    frame.render_widget(paragraph, area);
}

fn render_footer(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let conflicts = match (app.policy_conflicts, app.moderation_conflicts) {
        (0, 0) => String::new(),
        (policy, moderation) => format!(" · conflicts policy:{policy} moderation:{moderation}"),
    };
    let text = match app.mode {
        InputMode::Normal => format!(
            "{}{}\n↑↓ channel  j/k scroll  p post  s sync  a audit  r refresh  q quit",
            app.status, conflicts
        ),
        InputMode::Post => format!("Post: {}\nEnter submit · Esc cancel", app.input),
        InputMode::Peer => format!("Peer: {}\nEnter sync · Esc cancel", app.input),
    };
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::backend::TestBackend;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn test_app() -> App {
        App {
            datadir: PathBuf::new(),
            identity: KeypairFile::generate(Some("tester".into())),
            channels: vec!["one".into(), "two".into()],
            selected: 0,
            messages: Vec::new(),
            scroll: 0,
            audit: false,
            mode: InputMode::Normal,
            input: String::new(),
            status: "ready".into(),
            role: "owner".into(),
            policy_conflicts: 1,
            moderation_conflicts: 0,
            quit: false,
        }
    }

    #[test]
    fn composer_returns_post_action() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('p'))).unwrap();
        for character in "hello".chars() {
            app.handle_key(key(KeyCode::Char(character))).unwrap();
        }
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)).unwrap(),
            Action::Post("hello".into())
        );
        assert_eq!(app.mode, InputMode::Normal);
    }

    #[test]
    fn sync_prompt_has_default_peer_and_can_cancel() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('s'))).unwrap();
        assert_eq!(app.mode, InputMode::Peer);
        assert!(app.input.starts_with("ws://"));
        app.handle_key(key(KeyCode::Esc)).unwrap();
        assert_eq!(app.mode, InputMode::Normal);
    }

    #[test]
    fn render_contains_channels_and_conflict_status() {
        let app = test_app();
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("one"));
        assert!(rendered.contains("conflicts policy:1"));
        assert!(rendered.contains("p post"));
    }
}
