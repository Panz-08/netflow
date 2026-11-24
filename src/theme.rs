//! Palet NetFlow: slate gelap yang tenang, aksen hangat dan sejuk yang lembut.
//! Sengaja BUKAN neon/cyber. Jangan tambah warna terang menyala.

use ratatui::style::Color;

use crate::model::{LaneKind, Proto};

pub const BG: Color = Color::Rgb(22, 27, 34);
pub const BORDER: Color = Color::Rgb(56, 66, 82);
pub const TEXT: Color = Color::Rgb(213, 220, 230);
pub const DIM: Color = Color::Rgb(125, 135, 152);
pub const ACCENT: Color = Color::Rgb(99, 160, 245);
pub const OK: Color = Color::Rgb(112, 200, 150);
pub const WARN: Color = Color::Rgb(240, 184, 90);

/// Warna versi kontras tinggi (tombol `c`, untuk proyektor kelas).
pub const TEXT_HI: Color = Color::Rgb(246, 249, 253);
pub const DIM_HI: Color = Color::Rgb(188, 198, 214);

/// Dinding selang.
pub const PIPE: Color = Color::Rgb(78, 90, 110);
pub const PIPE_HI: Color = Color::Rgb(122, 138, 164);
/// Garis putus-putus di dalam selang.
pub const GUIDE: Color = Color::Rgb(44, 52, 66);

const WHITE: Color = Color::Rgb(255, 255, 255);

/// Enam warna lembut untuk jalur dinamis (port lain yang ramai).
pub const DYNAMIC: [Color; 6] = [
    Color::Rgb(214, 158, 130), // terakota
    Color::Rgb(140, 190, 140), // sage
    Color::Rgb(196, 162, 212), // lilac
    Color::Rgb(120, 185, 210), // langit
    Color::Rgb(220, 178, 120), // pasir
    Color::Rgb(160, 170, 220), // periwinkle
];

pub fn proto_color(p: Proto) -> Color {
    match p {
        Proto::Ssh => Color::Rgb(78, 201, 176),
        Proto::Https => Color::Rgb(106, 166, 255),
        Proto::Http => Color::Rgb(176, 148, 250),
        Proto::Dns => Color::Rgb(245, 190, 92),
        Proto::Other => Color::Rgb(150, 160, 178),
    }
}

pub fn lane_color(kind: LaneKind, contrast: bool) -> Color {
    let base = match kind {
        LaneKind::Fixed(p) => proto_color(p),
        LaneKind::Port(port) => DYNAMIC[port as usize % DYNAMIC.len()],
    };
    boost(base, contrast)
}

pub fn wall_color(selected: bool, contrast: bool) -> Color {
    let base = if selected { PIPE_HI } else { PIPE };
    if contrast {
        mix(base, TEXT_HI, 0.35)
    } else {
        base
    }
}

pub fn dim(contrast: bool) -> Color {
    if contrast {
        DIM_HI
    } else {
        DIM
    }
}

pub fn text(contrast: bool) -> Color {
    if contrast {
        TEXT_HI
    } else {
        TEXT
    }
}

/// Naikkan kecerahan warna untuk mode kontras tinggi.
pub fn boost(c: Color, contrast: bool) -> Color {
    if contrast {
        mix(c, WHITE, 0.30)
    } else {
        c
    }
}

/// Campur dua warna RGB. `t` = 0.0 (a) sampai 1.0 (b). Dipakai untuk ekor bola.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
            Color::Rgb(l(r1, r2), l(g1, g2), l(b1, b2))
        }
        _ => a,
    }
}
