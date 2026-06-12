//! A slot machine served over SSH — a full ratatui app running in-process.
//!
//! Run it:
//! ```text
//! cargo run -p ssh-tui --example slots
//! ssh -p 2222 demo@127.0.0.1        # password: demo
//! ```
//! Space spins, ↑/↓ adjusts the bet, `r` refills when broke, `q` quits. Resize the
//! terminal mid-game: `window-change` flows through and ratatui repaints at the new
//! size. Everything is in-process — no PTY, no child process, just a handler drawing
//! frames into the SSH channel.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{
    ChannelSession, ExecContext, ExecHandler, HandlerFuture, ServeConfig, load_or_create_host_key,
    serve_with,
};
use ssh_transport::rand_core::{OsRng, RngCore};
use ssh_transport::{ServerAuthHandler, ServerConnection, UserPublicKey};
use ssh_tui::ratatui::Frame;
use ssh_tui::ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ssh_tui::ratatui::style::{Color, Modifier, Style};
use ssh_tui::ratatui::text::{Line, Span};
use ssh_tui::ratatui::widgets::{Block, BorderType, Padding, Paragraph};
use ssh_tui::{InputParser, KeyCode, SshTerminal};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;

struct DemoAuth;
impl ServerAuthHandler for DemoAuth {
    fn verify_password(&mut self, user: &str, password: &str) -> bool {
        user == "demo" && password == "demo"
    }
    fn is_authorized_key(&mut self, _u: &str, _k: &UserPublicKey) -> bool {
        false
    }
}

struct ReelSymbol {
    glyph: &'static str,
    name: &'static str,
    color: Color,
    /// Multiplier on the bet for three of a kind.
    payout: u64,
}

const SYMBOLS: [ReelSymbol; 5] = [
    ReelSymbol {
        glyph: "♦",
        name: "DIAMOND",
        color: Color::Cyan,
        payout: 4,
    },
    ReelSymbol {
        glyph: "♥",
        name: "HEART",
        color: Color::Red,
        payout: 6,
    },
    ReelSymbol {
        glyph: "♣",
        name: "CLUB",
        color: Color::Green,
        payout: 10,
    },
    ReelSymbol {
        glyph: "★",
        name: "STAR",
        color: Color::Yellow,
        payout: 25,
    },
    ReelSymbol {
        glyph: "7",
        name: "SEVEN",
        color: Color::Magenta,
        payout: 100,
    },
];

/// Ticks (at the spin interval) after which each reel locks in, left to right.
const REEL_STOPS: [u32; 3] = [10, 18, 26];

struct Game {
    credits: u64,
    bet: u64,
    reels: [usize; 3],
    /// `Some(tick)` while spinning; reel `i` keeps rolling until `tick == REEL_STOPS[i]`.
    spin: Option<u32>,
    message: String,
}

impl Game {
    fn new() -> Self {
        Self {
            credits: 100,
            bet: 5,
            reels: [0, 1, 2],
            spin: None,
            message: "Welcome! Space to spin.".into(),
        }
    }

    fn spinning(&self) -> bool {
        self.spin.is_some()
    }

    fn start_spin(&mut self) {
        if self.spinning() {
            return;
        }
        if self.credits < self.bet {
            self.message = "Not enough credits — press r to refill.".into();
            return;
        }
        self.credits -= self.bet;
        self.spin = Some(0);
        self.message = "Spinning…".into();
    }

    fn adjust_bet(&mut self, up: bool) {
        if self.spinning() {
            return;
        }
        self.bet = if up {
            (self.bet + 5).min(100)
        } else {
            self.bet.saturating_sub(5).max(5)
        };
    }

    fn refill(&mut self) {
        if !self.spinning() && self.credits < self.bet {
            self.credits = 100;
            self.message = "Refilled to 100 credits. Easy come, easy go.".into();
        }
    }

    fn tick(&mut self, rng: &mut OsRng) {
        let Some(tick) = self.spin.as_mut() else {
            return;
        };
        *tick += 1;
        let tick = *tick;
        for (reel, stop) in self.reels.iter_mut().zip(REEL_STOPS) {
            if tick <= stop {
                *reel = (rng.next_u32() as usize) % SYMBOLS.len();
            }
        }
        if tick > REEL_STOPS[2] {
            self.spin = None;
            self.settle();
        }
    }

    fn settle(&mut self) {
        let [a, b, c] = self.reels;
        let win = if a == b && b == c {
            self.bet * SYMBOLS[a].payout
        } else if a == b || b == c || a == c {
            self.bet * 2
        } else {
            0
        };
        self.credits += win;
        self.message = if a == b && b == c {
            format!("JACKPOT! Three {} pay {win}!", SYMBOLS[a].name)
        } else if win > 0 {
            format!("A pair — you win {win}.")
        } else {
            "No luck. Spin again?".into()
        };
    }
}

struct SlotMachine;

impl ExecHandler for SlotMachine {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let Some(pty) = session.pty().cloned() else {
                let _ = session
                    .write_stderr(b"the casino needs a terminal (try: ssh -t ...)\r\n")
                    .await;
                return 1;
            };
            let mut resize = session.resize_events();
            let (mut reader, writer) = session.split();
            let Ok(mut terminal) = SshTerminal::new(writer, (pty.cols, pty.rows)).await else {
                return 1;
            };

            let mut game = Game::new();
            let mut rng = OsRng;
            let mut parser = InputParser::new();
            let mut buf = [0u8; 64];
            let mut spin_tick = tokio::time::interval(Duration::from_millis(70));
            spin_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

            let exit = loop {
                if terminal.draw(|frame| ui(frame, &game)).await.is_err() {
                    return 1; // client gone — no screen left to restore
                }
                tokio::select! {
                    read = reader.read(&mut buf) => match read {
                        Ok(0) | Err(_) => return 1, // stdin EOF / channel gone
                        Ok(n) => {
                            let quit = parser.feed(&buf[..n]).into_iter().any(|key| {
                                handle_key(&mut game, key)
                            });
                            if quit {
                                break 0;
                            }
                        }
                    },
                    changed = resize.changed() => match changed {
                        Ok(()) => terminal.resize(*resize.borrow_and_update()),
                        Err(_) => return 1,
                    },
                    _ = spin_tick.tick(), if game.spinning() => game.tick(&mut rng),
                }
            };
            let _ = terminal.restore().await;
            exit
        })
    }
}

/// Apply one key press; returns `true` when the user wants out.
fn handle_key(game: &mut Game, key: ssh_tui::KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        _ if key.is_interrupt() => return true,
        KeyCode::Char(' ') | KeyCode::Enter => game.start_spin(),
        KeyCode::Up | KeyCode::Char('+') => game.adjust_bet(true),
        KeyCode::Down | KeyCode::Char('-') => game.adjust_bet(false),
        KeyCode::Char('r') => game.refill(),
        _ => {}
    }
    false
}

fn ui(frame: &mut Frame, game: &Game) {
    let area = frame.area();
    if area.width < 40 || area.height < 14 {
        frame.render_widget(
            Paragraph::new("Terminal too small for the casino\n(need at least 40x14)")
                .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let [title, reels, status, help] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(7),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new("★ ★ ★  S S H   S L O T S  ★ ★ ★")
            .alignment(Alignment::Center)
            .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .block(Block::bordered().border_type(BorderType::Double)),
        title,
    );

    let columns = Layout::horizontal([Constraint::Ratio(1, 3); 3]).split(reels);
    for (column, &reel) in columns.iter().zip(&game.reels) {
        draw_reel(frame, *column, &SYMBOLS[reel], game.spinning());
    }

    let line = Line::from(vec![
        Span::raw("  Credits: "),
        Span::styled(
            game.credits.to_string(),
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::raw("   Bet: "),
        Span::styled(
            game.bet.to_string(),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled(&game.message, Style::new().fg(Color::Yellow)),
    ]);
    frame.render_widget(Paragraph::new(line).block(Block::bordered()), status);

    frame.render_widget(
        Paragraph::new("space: spin   ↑/↓: bet   r: refill   q: quit")
            .alignment(Alignment::Center)
            .style(Style::new().fg(Color::DarkGray)),
        help,
    );
}

fn draw_reel(frame: &mut Frame, area: Rect, symbol: &ReelSymbol, spinning: bool) {
    let border = if spinning {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border)
        .padding(Padding::top(area.height.saturating_sub(4) / 2));
    let body = vec![
        Line::styled(
            symbol.glyph,
            Style::new().fg(symbol.color).add_modifier(Modifier::BOLD),
        ),
        Line::styled(symbol.name, Style::new().fg(symbol.color)),
    ];
    frame.render_widget(
        Paragraph::new(body)
            .alignment(Alignment::Center)
            .block(block),
        area,
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_key = load_or_create_host_key("slots_host_key", &mut OsRng)?;
    let listener = TcpListener::bind("127.0.0.1:2222").await?;
    eprintln!(
        "casino open on 127.0.0.1:2222 — connect with: ssh -p 2222 demo@127.0.0.1 (password: demo)"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?; // keystroke latency matters
        let host_key = host_key.clone();
        tokio::spawn(async move {
            let ctx = ExecContext::new().on_shell(SlotMachine);
            let mut conn = ServerConnection::new(OsRng, host_key, DemoAuth);
            conn.set_allow_pty(true);
            if let Err(e) = serve_with(
                stream,
                conn,
                ctx,
                ServeConfig::default(),
                Some(peer),
                &ssh_io::NoRetryReaction,
            )
            .await
            {
                eprintln!("[{peer}] connection ended with error: {e}");
            }
        });
    }
}
