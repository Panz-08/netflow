//! Tata letak utama: header, jalur, detail, footer, bantuan, dan layar detail penuh.

pub mod detail;
pub mod pipes;

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Padding, Paragraph},
    Frame,
};

use crate::{app::App, theme};

fn frame_block() -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::BG))
}

pub fn panel(title: &str) -> Block<'static> {
    frame_block().title(Span::styled(
        format!(" {title} "),
        Style::default().fg(theme::DIM).add_modifier(Modifier::BOLD),
    ))
}

pub fn fmt_f(n: f64) -> String {
    if n < 1024.0 {
        format!("{n:.0} B")
    } else if n < 1_048_576.0 {
        format!("{:.1} KB", n / 1024.0)
    } else {
        format!("{:.1} MB", n / 1_048_576.0)
    }
}

pub fn fmt_bytes(n: u64) -> String {
    fmt_f(n as f64)
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(theme::BG)), area);

    if app.full_detail {
        full(f, app);
    } else {
        normal(f, app);
    }
    if app.show_help {
        help(f);
    }
}

fn normal(f: &mut Frame, app: &App) {
    let area = f.area();
    // Panel detail hanya muncul kalau semua jalur tetap muat. Kalau jalur
    // dinamis bertambah, jalur lebih penting daripada panel detail.
    let lane_rows = app.lanes.len() as u16 * 4;
    let remaining = area.height.saturating_sub(lane_rows + 6);
    let detail_h = if remaining >= 12 {
        12
    } else if remaining >= 8 {
        8
    } else if remaining >= 5 {
        5
    } else {
        0
    };
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(detail_h),
        Constraint::Length(1),
    ])
    .split(area);

    header(f, rows[0], app);
    pipes::render(f, rows[1], app);
    detail::compact(f, rows[2], app);
    footer(f, rows[3], false);
}

fn full(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);

    header(f, rows[0], app);
    pipes::render_single(f, rows[1], app);
    detail::stats_line(f, rows[2], app);
    detail::table(f, rows[3], app);
    detail::lesson_or_legend(f, rows[4], app);
    footer(f, rows[5], true);
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let block = frame_block();
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dim = Style::default().fg(theme::dim(app.contrast));
    let text = Style::default().fg(theme::text(app.contrast));
    let accent = Style::default()
        .fg(theme::boost(theme::ACCENT, app.contrast))
        .add_modifier(Modifier::BOLD);
    let mode_color = if app.mode == "LIVE" {
        theme::boost(theme::OK, app.contrast)
    } else {
        theme::boost(theme::WARN, app.contrast)
    };
    let warn_color = Style::default().fg(theme::boost(theme::WARN, app.contrast));
    let ok_color = Style::default().fg(theme::boost(theme::OK, app.contrast));

    let (left, right) = if let Some((message, warn)) = &app.status {
        // Saat ada pesan penting, pesan itu yang tampil di kiri.
        let mut reserved = app.iface.chars().count() + app.mode.chars().count() + 7;
        if app.paused {
            reserved += 8;
        }
        if app.contrast {
            reserved += 10;
        }
        let max = inner.width.saturating_sub(reserved as u16 + 4) as usize;
        let left = Line::from(vec![
            Span::styled(
                if *warn { " ⚠ " } else { " ✓ " },
                if *warn { warn_color } else { ok_color },
            ),
            Span::styled(
                clip(message, max),
                if *warn { warn_color } else { ok_color },
            ),
        ]);
        let mut right = vec![
            Span::styled(format!("{}  ·  ", app.iface), dim),
            Span::styled(app.mode.clone(), Style::default().fg(mode_color)),
        ];
        if app.paused {
            right.push(Span::styled("  ·  JEDA", warn_color));
        }
        if app.contrast {
            right.push(Span::styled("  ·  KONTRAS", dim));
        }
        right.push(Span::raw(" "));
        (left, Line::from(right))
    } else {
        let left = if inner.width < 70 {
            Line::from(Span::styled(" NetFlow", accent))
        } else {
            Line::from(vec![
                Span::styled(" NetFlow", accent),
                Span::styled("  Analisis Jalur Data", dim),
            ])
        };
        let mut right = vec![
            Span::styled("oleh ", dim),
            Span::styled("Panz-08", text),
            Span::styled(format!("  ·  {}  ·  ", app.iface), dim),
            Span::styled(app.mode.clone(), Style::default().fg(mode_color)),
        ];
        if app.paused {
            right.push(Span::styled("  ·  JEDA", warn_color));
        }
        if app.contrast {
            right.push(Span::styled("  ·  KONTRAS", dim));
        }
        right.push(Span::raw(" "));
        (left, Line::from(right))
    };

    f.render_widget(Paragraph::new(left), inner);
    f.render_widget(Paragraph::new(right).alignment(Alignment::Right), inner);
}

fn clip(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn footer(f: &mut Frame, area: Rect, full: bool) {
    let dim = Style::default().fg(theme::dim(false));
    let key = Style::default().fg(theme::ACCENT);
    let compact = area.width < 90;
    let left = if full {
        if compact {
            Line::from(vec![
                Span::styled(" ↑/↓ ", key),
                Span::styled("jalur   ", dim),
                Span::styled("Esc ", key),
                Span::styled("kembali   ", dim),
                Span::styled("? ", key),
                Span::styled("bantuan   ", dim),
                Span::styled("q ", key),
                Span::styled("keluar", dim),
            ])
        } else {
            Line::from(vec![
                Span::styled(" ↑/↓ ", key),
                Span::styled("ganti jalur   ", dim),
                Span::styled("Esc ", key),
                Span::styled("kembali   ", dim),
                Span::styled("? ", key),
                Span::styled("bantuan   ", dim),
                Span::styled("q ", key),
                Span::styled("keluar", dim),
            ])
        }
    } else if compact {
        Line::from(vec![
            Span::styled(" ↑/↓ ", key),
            Span::styled("pilih   ", dim),
            Span::styled("Spasi ", key),
            Span::styled("jeda   ", dim),
            Span::styled("? ", key),
            Span::styled("bantuan   ", dim),
            Span::styled("q ", key),
            Span::styled("keluar", dim),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ↑/↓ ", key),
            Span::styled("pilih   ", dim),
            Span::styled("Spasi ", key),
            Span::styled("jeda   ", dim),
            Span::styled("Enter ", key),
            Span::styled("detail   ", dim),
            Span::styled("? ", key),
            Span::styled("bantuan   ", dim),
            Span::styled("q ", key),
            Span::styled("keluar", dim),
        ])
    };
    let right = Line::from(Span::styled("NetFlow v0.2 · Panz-08 ", dim));
    f.render_widget(Paragraph::new(left), area);
    f.render_widget(Paragraph::new(right).alignment(Alignment::Right), area);
}

fn help(f: &mut Frame) {
    let area = f.area();
    let width = area.width.saturating_sub(4).min(68);
    let height = area.height.saturating_sub(2).min(20);
    if width < 20 || height < 6 {
        return;
    }
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .split(area);
    let horizontal = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width),
        Constraint::Fill(1),
    ])
    .split(vertical[1]);
    let popup = horizontal[1];

    f.render_widget(Clear, popup);
    let block = panel("Bantuan · NetFlow").padding(Padding::horizontal(1));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let dim = Style::default().fg(theme::DIM);
    let text = Style::default().fg(theme::TEXT);
    let key = Style::default().fg(theme::ACCENT);
    let lines = vec![
        Line::from(vec![
            Span::styled("● ", Style::default().fg(theme::TEXT)),
            Span::styled("paket besar (>800 B)     ", dim),
            Span::styled("• ", Style::default().fg(theme::TEXT)),
            Span::styled("paket kecil", dim),
        ]),
        Line::from(vec![
            Span::styled("▶ ", Style::default().fg(theme::OK)),
            Span::styled("baris atas = masuk       ", dim),
            Span::styled("◀ ", Style::default().fg(theme::OK)),
            Span::styled("baris bawah = keluar", dim),
        ]),
        Line::from(Span::styled("━━  ekor bola, memudar ke arah belakang", dim)),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" ↑/↓ / j k  ", key),
            Span::styled("pilih jalur", text),
        ]),
        Line::from(vec![
            Span::styled(" Spasi      ", key),
            Span::styled("jeda / lanjut", text),
        ]),
        Line::from(vec![
            Span::styled(" Enter      ", key),
            Span::styled("detail penuh jalur terpilih", text),
        ]),
        Line::from(vec![
            Span::styled(" Esc        ", key),
            Span::styled("kembali, atau keluar", text),
        ]),
        Line::from(vec![
            Span::styled(" c          ", key),
            Span::styled("kontras tinggi untuk proyektor", text),
        ]),
        Line::from(vec![
            Span::styled(" s          ", key),
            Span::styled("simpan snapshot CSV", text),
        ]),
        Line::from(vec![
            Span::styled(" ?          ", key),
            Span::styled("tutup bantuan", text),
        ]),
        Line::from(vec![
            Span::styled(" q          ", key),
            Span::styled("keluar", text),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "Jalur port lain muncul saat ramai, lalu memudar setelah sepi.",
            dim,
        )),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}
