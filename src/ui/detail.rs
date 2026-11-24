//! Panel detail ringkas dan layar detail penuh (tombol Enter).

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Padding, Paragraph, Row, Sparkline, Table},
    Frame,
};

use crate::{
    app::App,
    model::{service_name, Lane, LaneKind, Proto},
    theme,
};

use super::{fmt_bytes, panel};

pub fn compact(f: &mut Frame, area: Rect, app: &App) {
    if area.height == 0 {
        return;
    }
    let lane = app.selected_lane();
    let color = theme::lane_color(lane.kind, app.contrast);
    let dim = Style::default().fg(theme::dim(app.contrast));
    let text = Style::default().fg(theme::text(app.contrast));
    let color_style = Style::default().fg(color);

    let block = panel(&format!("Detail · {}", lane.name)).padding(Padding::horizontal(1));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 2 {
        return;
    }

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(inner);

    stats_line_in(f, rows[0], app, lane, dim, text, color_style);
    sparkline(f, rows[1], lane, dim, color);
    connections(f, rows[2], app, lane, dim, text, color_style, 5);

    let last = if app.belajar {
        lesson_line(lane, dim, color_style)
    } else {
        legend_line(app, dim)
    };
    f.render_widget(Paragraph::new(last), rows[3]);
}

pub fn stats_line(f: &mut Frame, area: Rect, app: &App) {
    let lane = app.selected_lane();
    let dim = Style::default().fg(theme::dim(app.contrast));
    let text = Style::default().fg(theme::text(app.contrast));
    let color = Style::default().fg(theme::lane_color(lane.kind, app.contrast));
    stats_line_in(f, area, app, lane, dim, text, color);
}

fn stats_line_in(
    f: &mut Frame,
    area: Rect,
    app: &App,
    lane: &Lane,
    dim: Style,
    text: Style,
    color: Style,
) {
    if area.height == 0 {
        return;
    }
    let mut spans = vec![
        Span::styled("Masuk ", dim),
        Span::styled(format!("↓ {}", fmt_bytes(lane.bytes_in)), color),
        Span::styled("   Keluar ", dim),
        Span::styled(format!("↑ {}", fmt_bytes(lane.bytes_out)), color),
        Span::styled("   Paket ", dim),
        Span::styled(lane.packets.to_string(), text),
    ];
    if lane.kind == LaneKind::Fixed(Proto::Ssh) {
        spans.push(Span::styled("   Sesi ", dim));
        spans.push(Span::styled(
            lane.active_sessions(app.clock, 60.0).to_string(),
            text,
        ));
        if let Some((ip, bytes)) = lane.top_remote_sender(app.clock, 60.0) {
            spans.push(Span::styled("   Remote ", dim));
            spans.push(Span::styled(format!("{ip} ({})", fmt_bytes(bytes)), color));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn sparkline(f: &mut Frame, area: Rect, lane: &Lane, dim: Style, color: ratatui::style::Color) {
    if area.height == 0 {
        return;
    }
    let cols = Layout::horizontal([Constraint::Length(9), Constraint::Min(1)]).split(area);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled("60 dtk  ", dim))),
        cols[0],
    );
    let data: Vec<u64> = lane.spark.iter().copied().collect();
    f.render_widget(
        Sparkline::default()
            .data(data)
            .style(Style::default().fg(color)),
        cols[1],
    );
}

#[allow(clippy::too_many_arguments)]
fn connections(
    f: &mut Frame,
    area: Rect,
    app: &App,
    lane: &Lane,
    dim: Style,
    text: Style,
    color: Style,
    limit: usize,
) {
    if area.height == 0 {
        return;
    }
    let count = (area.height as usize).min(limit);
    let flows = lane.top_flows(count);
    if flows.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Belum ada koneksi tercatat; tunggu paket berikutnya.",
                dim,
            ))),
            area,
        );
        return;
    }
    let mut lines = Vec::with_capacity(flows.len());
    for (src, dst, flow) in flows {
        let arrow = flow.dir.arrow();
        let arrow_style = match flow.dir {
            crate::model::Dir::In => color,
            crate::model::Dir::Out => dim,
        };
        let mut spans = vec![
            Span::styled(format!("{arrow} "), arrow_style),
            Span::styled(src.label(), text),
            Span::styled(" → ", dim),
            Span::styled(dst.label(), text),
            Span::styled(format!("   {}", fmt_bytes(flow.bytes)), color),
            Span::styled(format!("  {} pkt", flow.packets), dim),
        ];
        if lane.kind == LaneKind::Fixed(Proto::Ssh) && app.clock - flow.last_seen < 60.0 {
            spans.push(Span::styled("  aktif", Style::default().fg(theme::OK)));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), area);
}

pub fn table(f: &mut Frame, area: Rect, app: &App) {
    if area.height == 0 {
        return;
    }
    let lane = app.selected_lane();
    let dim = Style::default().fg(theme::dim(app.contrast));
    let text = Style::default().fg(theme::text(app.contrast));
    let color = Style::default().fg(theme::lane_color(lane.kind, app.contrast));

    let header = Row::new(vec![
        Cell::from(""),
        Cell::from("Sumber"),
        Cell::from("Tujuan"),
        Cell::from("Byte"),
        Cell::from("Paket"),
    ])
    .style(dim.add_modifier(Modifier::BOLD));

    let mut rows = Vec::new();
    for (src, dst, flow) in lane.top_flows(5) {
        let arrow = flow.dir.arrow();
        let arrow_style = match flow.dir {
            crate::model::Dir::In => color,
            crate::model::Dir::Out => dim,
        };
        rows.push(Row::new(vec![
            Cell::from(arrow).style(arrow_style),
            Cell::from(src.label()).style(text),
            Cell::from(dst.label()).style(text),
            Cell::from(fmt_bytes(flow.bytes)).style(color),
            Cell::from(flow.packets.to_string()).style(dim),
        ]));
    }
    if rows.is_empty() {
        rows.push(Row::new(vec![
            Cell::from("Belum ada koneksi tercatat.").style(dim)
        ]));
    }

    let widths = [
        Constraint::Length(2),
        Constraint::Percentage(38),
        Constraint::Percentage(38),
        Constraint::Length(10),
        Constraint::Length(7),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(panel(&format!("Koneksi Teratas · {}", lane.name)));
    f.render_widget(table, area);
}

pub fn lesson_or_legend(f: &mut Frame, area: Rect, app: &App) {
    if area.height == 0 {
        return;
    }
    let lane = app.selected_lane();
    let dim = Style::default().fg(theme::dim(app.contrast));
    let color = Style::default().fg(theme::lane_color(lane.kind, app.contrast));
    let line = if app.belajar {
        lesson_line(lane, dim, color)
    } else {
        legend_line(app, dim)
    };
    f.render_widget(Paragraph::new(line), area);
}

fn lesson_line(lane: &Lane, dim: Style, color: Style) -> Line<'static> {
    let lesson = match lane.kind {
        LaneKind::Fixed(proto) => proto.lesson().to_string(),
        LaneKind::Port(port) => match service_name(port) {
            Some(name) => format!(
                "Port {port} biasanya dipakai {name}; jalur ini muncul karena port itu ramai."
            ),
            None => format!("Port {port} tidak ada di tabel layanan, tetapi tetap dipantau."),
        },
    };
    Line::from(vec![
        Span::styled("Belajar · ", color),
        Span::styled(lesson, dim),
    ])
}

fn legend_line(app: &App, dim: Style) -> Line<'static> {
    let mut spans = vec![Span::styled("Legenda  ", dim)];
    for lane in &app.lanes {
        spans.push(Span::styled(
            "● ",
            Style::default().fg(theme::lane_color(lane.kind, app.contrast)),
        ));
        spans.push(Span::styled(format!("{}   ", lane.name), dim));
    }
    Line::from(spans)
}
