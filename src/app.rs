//! State aplikasi NetFlow: pemilihan jalur, jeda, jalur dinamis, dan status.

use std::{cmp::Ordering, collections::HashMap};

use crate::{
    export,
    model::{Lane, LaneKind, PacketEvent, Proto},
};

#[derive(Default)]
struct PortWindow {
    win: u64,
    rate: f64,
    last_seen: f64,
}

pub struct App {
    pub lanes: Vec<Lane>,
    pub selected: usize,
    pub paused: bool,
    pub quit: bool,
    pub mode: String,
    pub iface: String,
    /// Pesan status (teks, peringatan?) yang tampil di header.
    pub status: Option<(String, bool)>,
    status_until: f64,
    pub contrast: bool,
    pub show_help: bool,
    pub belajar: bool,
    pub full_detail: bool,
    /// Jam aplikasi dalam detik, dipakai untuk fade dan umur alur.
    pub clock: f64,
    acc: f32,
    ports: HashMap<u16, PortWindow>,
}

impl App {
    pub fn new(mode: String, iface: String, belajar: bool, status: Option<(String, bool)>) -> Self {
        Self {
            lanes: Proto::ALL.iter().map(|p| Lane::new_fixed(*p)).collect(),
            selected: 0,
            paused: false,
            quit: false,
            mode,
            iface,
            status,
            status_until: 0.0,
            contrast: false,
            show_help: false,
            belajar,
            full_detail: false,
            clock: 0.0,
            acc: 0.0,
            ports: HashMap::new(),
        }
    }

    pub fn set_status(&mut self, text: impl Into<String>, warn: bool) {
        self.status = Some((text.into(), warn));
        self.status_until = if warn {
            f64::INFINITY
        } else {
            self.clock + 8.0
        };
    }

    pub fn selected_lane(&self) -> &Lane {
        &self.lanes[self.selected.min(self.lanes.len().saturating_sub(1))]
    }

    pub fn on_packet(&mut self, ev: PacketEvent) {
        if self.paused {
            return;
        }
        let now = self.clock;
        let proto = Proto::from_port(ev.port);

        // Catat semua port non-tetap untuk memilih jalur dinamis teramai.
        if proto == Proto::Other && ev.port != 0 {
            let entry = self.ports.entry(ev.port).or_default();
            entry.win += ev.bytes as u64;
            entry.last_seen = now;
        }

        let idx = match proto {
            Proto::Other if ev.port != 0 => self
                .lanes
                .iter()
                .position(|l| l.kind == LaneKind::Port(ev.port))
                .or_else(|| {
                    self.lanes
                        .iter()
                        .position(|l| l.kind == LaneKind::Fixed(Proto::Other))
                })
                .unwrap_or(0),
            other => self
                .lanes
                .iter()
                .position(|l| l.kind == LaneKind::Fixed(other))
                .unwrap_or(0),
        };
        self.lanes[idx].push(&ev, now);
    }

    pub fn update(&mut self, dt: f32) {
        if self.paused {
            return;
        }
        self.clock += dt as f64;
        if let Some((_, false)) = self.status {
            if self.clock > self.status_until {
                self.status = None;
            }
        }
        for lane in &mut self.lanes {
            lane.step(dt);
        }
        self.acc += dt;
        if self.acc >= 1.0 {
            self.acc -= 1.0;
            self.roll();
        }
    }

    fn roll(&mut self) {
        let now = self.clock;
        for lane in &mut self.lanes {
            lane.roll(now);
        }
        for window in self.ports.values_mut() {
            window.rate = window.win as f64;
            window.win = 0;
        }
        self.ports
            .retain(|_, window| now - window.last_seen < 120.0);
        self.sync_dynamic();
    }

    /// Jalur dinamis: top 3 port lain yang ramai, plus jalur yang baru sepi
    /// (tetap tampil redup sampai 30 detik).
    fn sync_dynamic(&mut self) {
        let now = self.clock;
        let mut candidates: Vec<(u16, f64)> = self
            .ports
            .iter()
            .filter(|(port, window)| {
                **port < 32768
                    && Proto::from_port(**port) == Proto::Other
                    && window.rate > 0.0
                    && now - window.last_seen < 5.0
            })
            .map(|(port, window)| (*port, window.rate))
            .collect();
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let top: Vec<u16> = candidates.iter().take(3).map(|(port, _)| *port).collect();

        let selected_kind = self.lanes.get(self.selected).map(|lane| lane.kind);

        self.lanes.retain(|lane| match lane.kind {
            LaneKind::Fixed(_) => true,
            LaneKind::Port(port) => now - lane.last_seen < 30.0 || top.contains(&port),
        });

        let mut dynamic_count = self
            .lanes
            .iter()
            .filter(|lane| lane.kind.is_dynamic())
            .count();
        for port in &top {
            if dynamic_count >= 5 {
                break;
            }
            if !self.lanes.iter().any(|l| l.kind == LaneKind::Port(*port)) {
                let mut lane = Lane::new_port(*port);
                lane.last_seen = now;
                self.lanes.push(lane);
                dynamic_count += 1;
            }
        }

        self.lanes.sort_by(|a, b| {
            let rank = |kind: LaneKind| match kind {
                LaneKind::Fixed(proto) => Proto::ALL
                    .iter()
                    .position(|p| *p == proto)
                    .unwrap_or(Proto::ALL.len()) as u8,
                LaneKind::Port(_) => Proto::ALL.len() as u8,
            };
            rank(a.kind).cmp(&rank(b.kind)).then_with(|| {
                b.rate_total()
                    .partial_cmp(&a.rate_total())
                    .unwrap_or(Ordering::Equal)
            })
        });

        self.selected = selected_kind
            .and_then(|kind| self.lanes.iter().position(|lane| lane.kind == kind))
            .unwrap_or_else(|| self.selected.min(self.lanes.len().saturating_sub(1)));
    }

    pub fn next(&mut self) {
        self.selected = (self.selected + 1) % self.lanes.len();
    }

    pub fn prev(&mut self) {
        self.selected = (self.selected + self.lanes.len() - 1) % self.lanes.len();
    }

    pub fn export(&mut self) {
        match export::snapshot(self) {
            Ok(name) => self.set_status(format!("Snapshot disimpan: {name}"), false),
            Err(err) => self.set_status(format!("Gagal menyimpan snapshot: {err}"), true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dir, Endpoint};
    use std::net::{IpAddr, Ipv4Addr};

    fn app() -> App {
        App::new("SIMULASI".into(), "-".into(), false, None)
    }

    fn packet(port: u16, bytes: u32) -> PacketEvent {
        PacketEvent {
            port,
            dir: Dir::In,
            bytes,
            src: Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                40000,
            )),
            dst: Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                port,
            )),
        }
    }

    fn lane_index(app: &App, kind: LaneKind) -> Option<usize> {
        app.lanes.iter().position(|lane| lane.kind == kind)
    }

    #[test]
    fn fixed_ports_go_to_fixed_lanes() {
        let mut app = app();
        app.on_packet(packet(22, 100));
        app.on_packet(packet(443, 200));
        assert_eq!(
            app.lanes[lane_index(&app, LaneKind::Fixed(Proto::Ssh)).unwrap()].packets,
            1
        );
        assert_eq!(
            app.lanes[lane_index(&app, LaneKind::Fixed(Proto::Https)).unwrap()].packets,
            1
        );
    }

    #[test]
    fn busy_other_port_gets_a_dynamic_lane() {
        let mut app = app();
        app.on_packet(packet(8080, 5000));
        app.update(1.0);
        let index = lane_index(&app, LaneKind::Port(8080)).expect("jalur dinamis dibuat");
        assert_eq!(app.lanes[index].packets, 0);

        app.on_packet(packet(8080, 1000));
        assert_eq!(app.lanes[index].packets, 1);
        assert_eq!(app.lanes[index].bytes_in, 1000);
        assert_eq!(
            app.lanes[lane_index(&app, LaneKind::Fixed(Proto::Other)).unwrap()].bytes_in,
            5000
        );
    }

    #[test]
    fn idle_dynamic_lane_fades_away_after_30_seconds() {
        let mut app = app();
        app.on_packet(packet(8080, 5000));
        app.update(1.0);
        assert!(lane_index(&app, LaneKind::Port(8080)).is_some());
        app.update(31.0);
        assert!(lane_index(&app, LaneKind::Port(8080)).is_none());
    }
}
