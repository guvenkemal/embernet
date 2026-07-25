use crate::proto::{Envelope, KeypairFile, Message};
use crate::store::{self, ChannelRef, PolicyMode, append_message};
use crate::sync;
use crate::{peers, sync::PeerSyncSummary};
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
use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;

const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(3);
const LOCAL_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

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

#[derive(Debug)]
enum AutoSyncEvent {
    Complete {
        peer: String,
        summary: PeerSyncSummary,
    },
    Failed {
        peer: String,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    length: u64,
    modified: Option<SystemTime>,
}

impl From<Metadata> for FileFingerprint {
    fn from(metadata: Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalStateFingerprint {
    channels: Vec<String>,
    selected_files: Vec<Option<FileFingerprint>>,
}

struct App {
    datadir: PathBuf,
    identity: KeypairFile,
    channels: Vec<String>,
    selected: usize,
    messages: Vec<Envelope>,
    scroll: u16,
    max_scroll: u16,
    follow_tail: bool,
    audit: bool,
    mode: InputMode,
    input: String,
    status: String,
    role: String,
    policy_conflicts: usize,
    moderation_conflicts: usize,
    peers: Vec<String>,
    connection: String,
    local_fingerprint: Option<LocalStateFingerprint>,
    quit: bool,
}

impl App {
    fn load(datadir: PathBuf) -> Result<Self> {
        let identity_path = datadir.join("keys/identity.json");
        let identity = KeypairFile::load(&identity_path)
            .with_context(|| format!("load identity {}", identity_path.display()))?;
        let channels = store::list_channels(&datadir)?;
        let peers = peers::list_peers(&datadir)?;
        let mut app = Self {
            datadir,
            identity,
            channels,
            selected: 0,
            messages: Vec::new(),
            scroll: 0,
            max_scroll: 0,
            follow_tail: true,
            audit: false,
            mode: InputMode::Normal,
            input: String::new(),
            status: "ready".into(),
            role: "-".into(),
            policy_conflicts: 0,
            moderation_conflicts: 0,
            connection: if peers.is_empty() {
                "offline · no saved peers".into()
            } else {
                format!("connecting · {} peer(s)", peers.len())
            },
            peers,
            local_fingerprint: None,
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
            self.local_fingerprint = Some(self.local_state_fingerprint()?);
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
        self.follow_tail = true;
        self.local_fingerprint = Some(self.local_state_fingerprint()?);
        Ok(())
    }

    fn local_state_fingerprint(&self) -> Result<LocalStateFingerprint> {
        let channels = store::list_channels(&self.datadir)?;
        let selected_files = self
            .channel()
            .map(|channel| {
                let channel_dir = crate::util::channel_to_path(&self.datadir, channel);
                [
                    channel_dir.join("log.ndjson"),
                    channel_dir.join("policy.ndjson"),
                    channel_dir.join("moderation.ndjson"),
                    channel_dir.join("policy-conflicts"),
                    channel_dir.join("moderation-conflicts"),
                ]
                .into_iter()
                .map(|path| file_fingerprint(&path))
                .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(LocalStateFingerprint {
            channels,
            selected_files,
        })
    }

    fn refresh_if_local_state_changed(&mut self) -> Result<bool> {
        let fingerprint = self.local_state_fingerprint()?;
        if self.local_fingerprint.as_ref() == Some(&fingerprint) {
            return Ok(false);
        }

        let selected = self.channel().map(str::to_owned);
        let scroll = self.scroll;
        let follow_tail = self.follow_tail;
        self.channels = fingerprint.channels;
        self.selected = selected
            .and_then(|selected| {
                self.channels
                    .iter()
                    .position(|channel| channel == &selected)
            })
            .unwrap_or_else(|| self.selected.min(self.channels.len().saturating_sub(1)));
        self.refresh()?;
        self.scroll = scroll;
        self.follow_tail = follow_tail;
        self.status = "local changes detected".into();
        Ok(true)
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
            KeyCode::Char('k') | KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(1);
                self.follow_tail = false;
            }
            KeyCode::Char('j') | KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(1).min(self.max_scroll);
                self.follow_tail = self.scroll >= self.max_scroll;
            }
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
                self.input = self
                    .peers
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ws://127.0.0.1:4444/sync".into());
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
                    self.follow_tail = true;
                    let envelope = Envelope::sign(
                        self.identity.clone(),
                        &channel,
                        Message::new_text(None, Vec::new(), body, Vec::new()),
                    )?;
                    let id = append_message(&self.datadir, &chan, &envelope)?;
                    Ok(format!("posted {}", &id[..12]))
                }
                Action::Sync(peer) => {
                    let peer = peers::add_peer(&self.datadir, &peer)?;
                    self.peers = peers::list_peers(&self.datadir)?;
                    let received = sync::sync_from_peer(&self.datadir, &peer, &channel).await?;
                    self.connection = format!("connected · {peer}");
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

    fn apply_auto_sync(&mut self, event: AutoSyncEvent) {
        match event {
            AutoSyncEvent::Complete { peer, summary } => {
                self.connection = format!("connected · {peer}");
                self.status = format!(
                    "auto-sync: {} channel(s), {} received",
                    summary.channels, summary.received
                );
                let selected = self.channel().map(str::to_owned);
                match store::list_channels(&self.datadir) {
                    Ok(channels) => {
                        let channels_changed = channels != self.channels;
                        if channels_changed || summary.received > 0 {
                            let scroll = self.scroll;
                            let follow_tail = self.follow_tail;
                            self.channels = channels;
                            if let Some(selected) = selected
                                && let Some(index) = self
                                    .channels
                                    .iter()
                                    .position(|channel| channel == &selected)
                            {
                                self.selected = index;
                            }
                            if let Err(error) = self.refresh() {
                                self.status = format!("refresh failed: {error:#}");
                            } else {
                                self.scroll = scroll;
                                self.follow_tail = follow_tail;
                            }
                        }
                    }
                    Err(error) => self.status = format!("channel refresh failed: {error:#}"),
                }
            }
            AutoSyncEvent::Failed { peer, error } => {
                self.connection = format!("offline · {peer}");
                self.status = format!("auto-sync error: {error}");
            }
        }
    }
}

fn file_fingerprint(path: &Path) -> Result<Option<FileFingerprint>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.into())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read metadata {}", path.display())),
    }
}

pub async fn run(datadir: PathBuf) -> Result<()> {
    let mut app = App::load(datadir)?;
    let (sync_tx, mut sync_rx) = mpsc::unbounded_channel();
    let sync_task = tokio::spawn(auto_sync_worker(app.datadir.clone(), sync_tx));
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app, &mut sync_rx).await;
    sync_task.abort();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    sync_rx: &mut mpsc::UnboundedReceiver<AutoSyncEvent>,
) -> Result<()> {
    let mut last_local_refresh = Instant::now();
    while !app.quit {
        while let Ok(event) = sync_rx.try_recv() {
            app.apply_auto_sync(event);
        }
        if last_local_refresh.elapsed() >= LOCAL_REFRESH_INTERVAL {
            if let Err(error) = app.refresh_if_local_state_changed() {
                app.status = format!("local refresh failed: {error:#}");
            }
            last_local_refresh = Instant::now();
        }
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

async fn auto_sync_worker(datadir: PathBuf, tx: mpsc::UnboundedSender<AutoSyncEvent>) {
    let mut interval = tokio::time::interval(AUTO_SYNC_INTERVAL);
    loop {
        interval.tick().await;
        let configured = match peers::list_peers(&datadir) {
            Ok(configured) => configured,
            Err(error) => {
                let _ = tx.send(AutoSyncEvent::Failed {
                    peer: "configuration".into(),
                    error: format!("{error:#}"),
                });
                continue;
            }
        };
        for peer in configured {
            let event = match sync::sync_all_from_peer(&datadir, &peer).await {
                Ok(summary) => AutoSyncEvent::Complete {
                    peer: peer.clone(),
                    summary,
                },
                Err(error) => AutoSyncEvent::Failed {
                    peer: peer.clone(),
                    error: format!("{error:#}"),
                },
            };
            if tx.send(event).is_err() {
                return;
            }
        }
    }
}

fn render(frame: &mut ratatui::Frame<'_>, app: &mut App) {
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

fn render_timeline(frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
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
    let content_width = area.width.saturating_sub(2);
    let rendered_line_count = wrapped_line_count(&lines, content_width);
    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    let visible_height = area.height.saturating_sub(2) as usize;
    app.max_scroll = rendered_line_count
        .saturating_sub(visible_height)
        .min(u16::MAX as usize) as u16;
    if app.follow_tail {
        app.scroll = app.max_scroll;
    } else {
        app.scroll = app.scroll.min(app.max_scroll);
    }
    let paragraph = paragraph.scroll((app.scroll, 0));
    frame.render_widget(paragraph, area);
}

fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    let width = usize::from(width.max(1));
    lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(width))
        .sum()
}

fn render_footer(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let conflicts = match (app.policy_conflicts, app.moderation_conflicts) {
        (0, 0) => String::new(),
        (policy, moderation) => format!(" · conflicts policy:{policy} moderation:{moderation}"),
    };
    let text = match app.mode {
        InputMode::Normal => format!(
            "{}{} · {}\n↑↓ channel  j/k scroll  p post  s sync  a audit  r refresh  q quit",
            app.status, conflicts, app.connection
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

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
            max_scroll: 0,
            follow_tail: true,
            audit: false,
            mode: InputMode::Normal,
            input: String::new(),
            status: "ready".into(),
            role: "owner".into(),
            policy_conflicts: 1,
            moderation_conflicts: 0,
            peers: Vec::new(),
            connection: "offline · no saved peers".into(),
            local_fingerprint: None,
            quit: false,
        }
    }

    fn stored_app() -> (App, ChannelRef) {
        let datadir = std::env::temp_dir().join(format!(
            "embernet_tui_refresh_test_{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&datadir);
        store::init_layout(&datadir).unwrap();
        let identity = KeypairFile::generate(Some("tester".into()));
        identity.save(&datadir.join("keys/identity.json")).unwrap();
        let channel = ChannelRef::parse("test/local-refresh").unwrap();
        store::create_channel(&datadir, &channel).unwrap();
        (App::load(datadir).unwrap(), channel)
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
        let mut app = test_app();
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("one"));
        assert!(rendered.contains("conflicts policy:1"));
        assert!(rendered.contains("p post"));
    }

    #[test]
    fn automatic_sync_updates_connection_status() {
        let mut app = test_app();
        app.apply_auto_sync(AutoSyncEvent::Complete {
            peer: "ws://localhost:4444/sync".into(),
            summary: PeerSyncSummary {
                channels: 2,
                received: 0,
            },
        });
        assert!(app.connection.starts_with("connected"));
        assert_eq!(app.status, "auto-sync: 2 channel(s), 0 received");
    }

    #[test]
    fn local_refresh_detects_external_append_and_ignores_unchanged_state() {
        let (mut app, channel) = stored_app();
        assert!(!app.refresh_if_local_state_changed().unwrap());
        app.scroll = 7;
        app.follow_tail = false;

        let envelope = Envelope::sign(
            KeypairFile::generate(Some("external".into())),
            &channel.full_name,
            Message::new_text(None, Vec::new(), "from server".into(), Vec::new()),
        )
        .unwrap();
        append_message(&app.datadir, &channel, &envelope).unwrap();

        assert!(app.refresh_if_local_state_changed().unwrap());
        assert_eq!(app.messages.len(), 1);
        assert_eq!(app.messages[0].body_text(), Some("from server"));
        assert_eq!(app.scroll, 7);
        assert_eq!(app.status, "local changes detected");
        assert!(!app.refresh_if_local_state_changed().unwrap());
    }

    #[test]
    fn timeline_follows_new_messages_only_while_pinned_to_bottom() {
        let (mut app, channel) = stored_app();
        for index in 0..8 {
            let envelope = Envelope::sign(
                KeypairFile::generate(Some("external".into())),
                &channel.full_name,
                Message::new_text(None, Vec::new(), format!("message {index}"), Vec::new()),
            )
            .unwrap();
            append_message(&app.datadir, &channel, &envelope).unwrap();
        }
        app.refresh().unwrap();

        let backend = TestBackend::new(60, 16);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let original_bottom = app.scroll;
        assert!(original_bottom > 0);
        assert_eq!(app.scroll, app.max_scroll);

        let newest = Envelope::sign(
            KeypairFile::generate(Some("external".into())),
            &channel.full_name,
            Message::new_text(None, Vec::new(), "newest".into(), Vec::new()),
        )
        .unwrap();
        append_message(&app.datadir, &channel, &newest).unwrap();
        app.refresh_if_local_state_changed().unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        assert!(app.scroll > original_bottom);
        assert_eq!(app.scroll, app.max_scroll);

        app.handle_key(key(KeyCode::Char('k'))).unwrap();
        let reading_position = app.scroll;
        assert!(!app.follow_tail);
        let later = Envelope::sign(
            KeypairFile::generate(Some("external".into())),
            &channel.full_name,
            Message::new_text(None, Vec::new(), "later".into(), Vec::new()),
        )
        .unwrap();
        append_message(&app.datadir, &channel, &later).unwrap();
        app.refresh_if_local_state_changed().unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        assert_eq!(app.scroll, reading_position);
    }
}
