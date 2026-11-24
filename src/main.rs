//! NetFlow - analisis jalur data di port. Oleh Panz-08.

mod app;
mod cli;
mod export;
mod model;
mod source;
mod theme;
mod ui;

use std::{
    io,
    time::{Duration, Instant},
};

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::{app::App, source::SourceEvent};

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = match cli::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("ntf: {err}\n\n{}", cli::USAGE);
            std::process::exit(2);
        }
    };

    if args.help {
        println!("{}", cli::HELP);
        return Ok(());
    }
    if args.version {
        println!("ntf {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.list {
        print_interfaces();
        return Ok(());
    }

    let (tx, mut rx) = mpsc::channel::<SourceEvent>(1024);
    let (mode, iface, status) = start_source(tx, &args);
    let mut app = App::new(mode, iface, args.belajar, status);

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app, &mut rx).await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    rx: &mut mpsc::Receiver<SourceEvent>,
) -> io::Result<()> {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(33));
    let mut last = Instant::now();

    while !app.quit {
        tokio::select! {
            _ = tick.tick() => {
                let now = Instant::now();
                app.update((now - last).as_secs_f32());
                last = now;
                terminal.draw(|f| ui::draw(f, app))?;
            }
            Some(event) = rx.recv() => match event {
                SourceEvent::Packet(packet) => app.on_packet(packet),
                SourceEvent::Status { text, warn } => app.set_status(text, warn),
            },
            Some(Ok(Event::Key(key))) = events.next() => {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code, key.modifiers);
                }
            }
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    if modifiers.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('c')) {
        app.quit = true;
        return;
    }
    match code {
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Esc => {
            if app.show_help {
                app.show_help = false;
            } else if app.full_detail {
                app.full_detail = false;
            } else {
                app.quit = true;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.prev(),
        KeyCode::Char(' ') => app.paused = !app.paused,
        KeyCode::Enter => {
            if app.show_help {
                app.show_help = false;
            } else {
                app.full_detail = !app.full_detail;
            }
        }
        KeyCode::Char('?') => app.show_help = !app.show_help,
        KeyCode::Char('c') => app.contrast = !app.contrast,
        KeyCode::Char('s') => app.export(),
        _ => {}
    }
}

fn start_source(
    tx: mpsc::Sender<SourceEvent>,
    args: &cli::Args,
) -> (String, String, Option<(String, bool)>) {
    if args.sim {
        start_sim(tx);
        return ("SIMULASI".into(), "-".into(), None);
    }
    match &args.iface {
        Some(name) => start_live(tx, name.clone(), args.filter.clone()),
        None => {
            start_sim(tx);
            ("SIMULASI".into(), "-".into(), None)
        }
    }
}

fn start_sim(tx: mpsc::Sender<SourceEvent>) -> (String, String, Option<(String, bool)>) {
    tokio::spawn(source::sim::run(tx));
    ("SIMULASI".into(), "-".into(), None)
}

#[cfg(feature = "live")]
fn start_live(
    tx: mpsc::Sender<SourceEvent>,
    iface: String,
    filter: Option<String>,
) -> (String, String, Option<(String, bool)>) {
    let name = iface.clone();
    tokio::task::spawn_blocking(move || {
        let reporter = tx.clone();
        if let Err(err) = source::live::run(tx, name.clone(), filter) {
            let _ =
                reporter.blocking_send(SourceEvent::status(format!("pcap {name}: {err}"), true));
        }
    });
    ("LIVE".into(), iface, None)
}

#[cfg(not(feature = "live"))]
fn start_live(
    tx: mpsc::Sender<SourceEvent>,
    iface: String,
    _filter: Option<String>,
) -> (String, String, Option<(String, bool)>) {
    tokio::spawn(source::sim::run(tx));
    (
        "SIMULASI".into(),
        "-".into(),
        Some((
            format!("Fitur live tidak aktif; {iface} diabaikan, memakai simulasi. Build: cargo build --features live"),
            true,
        )),
    )
}

#[cfg(feature = "live")]
fn print_interfaces() {
    match source::live::interfaces() {
        Ok(items) => {
            println!("Interface tersedia:");
            for (name, addrs) in items {
                if addrs.is_empty() {
                    println!("  {name}");
                } else {
                    let list: Vec<String> = addrs.iter().map(|ip| ip.to_string()).collect();
                    println!("  {name:<16} {}", list.join(", "));
                }
            }
        }
        Err(err) => eprintln!("ntf: gagal membaca daftar interface: {err}"),
    }
}

#[cfg(not(feature = "live"))]
fn print_interfaces() {
    eprintln!("ntf: fitur live tidak aktif pada binary ini.");
    eprintln!("     Build ulang dengan: cargo build --release --features live");
}
