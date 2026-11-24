//! Gambar jalur (selang) dan bola (paket). Ini jantung tampilan NetFlow.
//!
//! Satu jalur = 4 baris:
//!
//! ```text
//!   ╭──────────────────────────╮   atas dinding selang
//!   │┈┈┈━━●┈┈┈┈┈┈┈┈┈•┈┈┈┈┈┈┈┈▶   jalur MASUK  (bola ke kanan)
//!   ◀┈┈┈┈┈┈┈•━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈│   jalur KELUAR (bola ke kiri)
//!   ╰──────────────────────────╯   bawah dinding selang
//! ```

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    Frame,
};

use crate::{
    app::App,
    model::{Dir, Lane},
    theme,
};

use super::{fmt_f, panel};

const LABEL_W: u16 = 14;
const STATS_W: u16 = 18;
const LANE_H: u16 = 4;

/// Posisi satu jalur di layar.
#[derive(Clone, Copy)]
struct LaneRect {
    label_x: u16,
    x: u16,
    y: u16,
    w: u16,
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = panel("Jalur Data");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < LABEL_W + STATS_W + 12 || inner.height < LANE_H {
        return;
    }
    let pipe_x = inner.x + LABEL_W;
    let pipe_w = inner.width - LABEL_W - STATS_W;

    let count = app.lanes.len();
    let all_fit = inner.height >= count as u16 * LANE_H;
    let buf = f.buffer_mut();

    if all_fit {
        let gap = if inner.height >= count as u16 * (LANE_H + 1) {
            1
        } else {
            0
        };
        let pad = u16::from(inner.height > count as u16 * LANE_H);
        for (i, lane) in app.lanes.iter().enumerate() {
            let y = inner.y + pad + i as u16 * (LANE_H + gap);
            draw_lane(
                buf,
                LaneRect {
                    label_x: inner.x + 1,
                    x: pipe_x,
                    y,
                    w: pipe_w,
                },
                lane,
                i == app.selected,
                app,
            );
        }
    } else {
        // Terminal pendek: tampilkan jendela jalur di sekitar pilihan.
        let fit = (inner.height / LANE_H).max(1) as usize;
        let start = app
            .selected
            .saturating_sub(fit / 2)
            .min(count.saturating_sub(fit));
        for (offset, lane) in app.lanes.iter().skip(start).take(fit).enumerate() {
            let y = inner.y + offset as u16 * LANE_H;
            draw_lane(
                buf,
                LaneRect {
                    label_x: inner.x + 1,
                    x: pipe_x,
                    y,
                    w: pipe_w,
                },
                lane,
                start + offset == app.selected,
                app,
            );
        }
        let used = fit as u16 * LANE_H;
        if count > fit && inner.height > used {
            let text = format!("↓ {} jalur lagi", count - fit);
            let width = text.chars().count() as u16;
            if width + 2 <= inner.width {
                buf.set_string(
                    inner.right() - width - 1,
                    inner.y + used,
                    text,
                    Style::default().fg(theme::dim(app.contrast)),
                );
            }
        }
    }
}

/// Satu jalur saja, selebar panel (dipakai layar detail penuh).
pub fn render_single(f: &mut Frame, area: Rect, app: &App) {
    let lane = app.selected_lane();
    let block = panel(&format!("Jalur · {}", lane.name));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < LABEL_W + STATS_W + 12 || inner.height < LANE_H {
        return;
    }
    let x = inner.x + LABEL_W;
    let w = inner.width - LABEL_W - STATS_W;
    draw_lane(
        f.buffer_mut(),
        LaneRect {
            label_x: inner.x + 1,
            x,
            y: inner.y,
            w,
        },
        lane,
        true,
        app,
    );
}

fn draw_lane(buf: &mut Buffer, rect: LaneRect, lane: &Lane, selected: bool, app: &App) {
    let LaneRect { label_x, x, y, w } = rect;
    let color = theme::lane_color(lane.kind, app.contrast);
    let mut wall_color = theme::wall_color(selected, app.contrast);
    if lane.pulse > 0.01 {
        wall_color = theme::mix(wall_color, theme::WARN, 0.45 * lane.pulse);
    } else if lane.quiet(app.clock) {
        wall_color = theme::mix(wall_color, theme::BG, 0.55);
    }
    let wall = Style::default().fg(wall_color);
    let guide = Style::default().fg(if app.contrast {
        theme::mix(theme::GUIDE, theme::TEXT_HI, 0.28)
    } else {
        theme::GUIDE
    });
    let inner_w = (w - 2) as usize;

    // Label di kiri.
    let name_style = if selected {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::text(app.contrast))
    };
    buf.set_string(
        label_x,
        y + 1,
        if selected { "▎" } else { " " },
        Style::default().fg(color),
    );
    buf.set_string(label_x + 2, y + 1, &lane.name, name_style);
    buf.set_string(
        label_x + 2,
        y + 2,
        &lane.port_label,
        Style::default().fg(theme::dim(app.contrast)),
    );

    // Dinding selang + garis putus-putus di dalamnya.
    buf.set_string(x, y, format!("╭{}╮", "─".repeat(inner_w)), wall);
    buf.set_string(x, y + 3, format!("╰{}╯", "─".repeat(inner_w)), wall);
    for row in [y + 1, y + 2] {
        buf.set_string(x + 1, row, "┈".repeat(inner_w), guide);
    }
    buf.set_string(x, y + 1, "│", wall);
    buf.set_string(x + w - 1, y + 1, "▶", Style::default().fg(color));
    buf.set_string(x, y + 2, "◀", Style::default().fg(color));
    buf.set_string(x + w - 1, y + 2, "│", wall);

    // Bola + ekornya.
    let span = (w - 3) as f32;
    for p in &lane.particles {
        let col = x + 1 + (p.x.clamp(0.0, 1.0) * span).round() as u16;
        let (row, sign) = match p.dir {
            Dir::In => (y + 1, 1i32),
            Dir::Out => (y + 2, -1i32),
        };
        for t in (1..=3i32).rev() {
            let tc = col as i32 - sign * t;
            if tc >= (x + 1) as i32 && tc <= (x + w - 2) as i32 {
                let c = theme::mix(color, theme::GUIDE, t as f32 / 4.0);
                buf.set_string(tc as u16, row, "━", Style::default().fg(c));
            }
        }
        // Fade-in 150 ms supaya bola baru tidak "muncul mendadak".
        let fade = (1.0 - (p.age / 0.15).min(1.0)) * 0.65;
        let particle_color = theme::mix(color, theme::TEXT_HI, fade);
        let glyph = if p.big { "●" } else { "•" };
        buf.set_string(
            col,
            row,
            glyph,
            Style::default()
                .fg(particle_color)
                .add_modifier(Modifier::BOLD),
        );
    }

    // Throughput di kanan.
    let sx = x + w + 2;
    buf.set_string(
        sx,
        y + 1,
        format!("↓ {}/s", fmt_f(lane.rate_in)),
        Style::default().fg(theme::text(app.contrast)),
    );
    buf.set_string(
        sx,
        y + 2,
        format!("↑ {}/s", fmt_f(lane.rate_out)),
        Style::default().fg(theme::dim(app.contrast)),
    );
}
