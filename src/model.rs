//! Model data NetFlow: paket, partikel (bola), alur (koneksi) dan jalur (selang).

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    /// Masuk ke mesin ini (bola bergerak ke kanan)
    In,
    /// Keluar dari mesin ini (bola bergerak ke kiri)
    Out,
}

impl Dir {
    pub fn arrow(self) -> &'static str {
        match self {
            Dir::In => "↓",
            Dir::Out => "↑",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Ssh,
    Https,
    Http,
    Dns,
    Other,
}

impl Proto {
    pub const ALL: [Proto; 5] = [
        Proto::Ssh,
        Proto::Https,
        Proto::Http,
        Proto::Dns,
        Proto::Other,
    ];

    pub fn from_port(port: u16) -> Self {
        match port {
            22 => Proto::Ssh,
            80 => Proto::Http,
            443 => Proto::Https,
            53 => Proto::Dns,
            _ => Proto::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Ssh => "SSH",
            Proto::Https => "HTTPS",
            Proto::Http => "HTTP",
            Proto::Dns => "DNS",
            Proto::Other => "Lainnya",
        }
    }

    pub fn port_label(self) -> &'static str {
        match self {
            Proto::Ssh => ":22",
            Proto::Https => ":443",
            Proto::Http => ":80",
            Proto::Dns => ":53",
            Proto::Other => "port lain",
        }
    }

    /// Satu kalimat untuk mode `--belajar`.
    pub fn lesson(self) -> &'static str {
        match self {
            Proto::Ssh => "SSH (:22) untuk masuk ke perangkat lain lewat terminal terenkripsi.",
            Proto::Https => "HTTPS (:443) web terenkripsi; hampir semua situs modern lewat sini.",
            Proto::Http => "HTTP (:80) web tanpa enkripsi; datanya bisa dibaca di jalan.",
            Proto::Dns => "DNS (:53) penerjemah nama domain ke alamat IP, sering lewat UDP.",
            Proto::Other => "Lainnya: port yang belum punya jalur sendiri tetap dihitung di sini.",
        }
    }
}

/// Nama layanan untuk port yang dikenal. `None` kalau tidak ada di tabel.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        587 => "SMTP",
        631 => "IPP",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        27017 => "MongoDB",
        _ => return None,
    })
}

/// Port layanan: port rendah yang umum, atau port yang ada di tabel layanan.
#[cfg_attr(not(feature = "live"), allow(dead_code))]
pub fn is_service_port(port: u16) -> bool {
    port != 0 && (port < 1024 || service_name(port).is_some())
}

/// Satu ujung koneksi: alamat IP + port.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn label(self) -> String {
        match self.ip {
            IpAddr::V4(ip) => format!("{ip}:{}", self.port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", self.port),
        }
    }
}

/// Satu paket yang dilaporkan oleh sumber data (simulasi atau pcap).
#[derive(Clone, Debug)]
pub struct PacketEvent {
    pub port: u16,
    pub dir: Dir,
    pub bytes: u32,
    pub src: Option<Endpoint>,
    pub dst: Option<Endpoint>,
}

/// Satu "bola" yang bergerak di dalam jalur. `x` = posisi 0.0..=1.0.
#[derive(Clone, Debug)]
pub struct Particle {
    pub x: f32,
    pub speed: f32,
    pub dir: Dir,
    pub big: bool,
    /// Usia dalam detik, dipakai untuk fade-in singkat.
    pub age: f32,
}

/// Satu koneksi (5-tuple sederhana tanpa protokol) yang tercatat di sebuah jalur.
#[derive(Clone, Debug)]
pub struct Flow {
    pub dir: Dir,
    pub bytes: u64,
    pub packets: u64,
    pub last_seen: f64,
}

/// Jenis jalur: lima jalur tetap, atau jalur dinamis untuk satu port.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LaneKind {
    Fixed(Proto),
    Port(u16),
}

impl LaneKind {
    pub fn service_port(self) -> Option<u16> {
        match self {
            LaneKind::Fixed(Proto::Ssh) => Some(22),
            LaneKind::Fixed(Proto::Https) => Some(443),
            LaneKind::Fixed(Proto::Http) => Some(80),
            LaneKind::Fixed(Proto::Dns) => Some(53),
            LaneKind::Fixed(Proto::Other) => None,
            LaneKind::Port(p) => Some(p),
        }
    }

    pub fn is_dynamic(self) -> bool {
        matches!(self, LaneKind::Port(_))
    }
}

const MAX_PARTICLES: usize = 48;
const MAX_FLOWS: usize = 256;
const SPARK_LEN: usize = 60;
const FLOW_IDLE: f64 = 180.0;

/// Satu jalur (selang) untuk satu jenis layanan.
pub struct Lane {
    pub kind: LaneKind,
    pub name: String,
    pub port_label: String,
    pub particles: Vec<Particle>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub rate_in: f64,
    pub rate_out: f64,
    /// Throughput total 60 detik terakhir (byte/detik).
    pub spark: VecDeque<u64>,
    pub flows: HashMap<(Endpoint, Endpoint), Flow>,
    /// Waktu (detik app) paket terakhir masuk jalur ini.
    pub last_seen: f64,
    /// 1.0 tepat saat lonjakan, lalu memudar.
    pub pulse: f32,
    win_in: u64,
    win_out: u64,
}

impl Lane {
    pub fn new_fixed(proto: Proto) -> Self {
        Self::new(
            LaneKind::Fixed(proto),
            proto.name().to_string(),
            proto.port_label().to_string(),
        )
    }

    pub fn new_port(port: u16) -> Self {
        Self::new(
            LaneKind::Port(port),
            service_name(port).unwrap_or("Port").to_string(),
            format!(":{port}"),
        )
    }

    fn new(kind: LaneKind, name: String, port_label: String) -> Self {
        Self {
            kind,
            name,
            port_label,
            particles: Vec::new(),
            bytes_in: 0,
            bytes_out: 0,
            packets: 0,
            rate_in: 0.0,
            rate_out: 0.0,
            spark: VecDeque::with_capacity(SPARK_LEN),
            flows: HashMap::new(),
            last_seen: 0.0,
            pulse: 0.0,
            win_in: 0,
            win_out: 0,
        }
    }

    pub fn push(&mut self, ev: &PacketEvent, now: f64) {
        match ev.dir {
            Dir::In => {
                self.bytes_in += ev.bytes as u64;
                self.win_in += ev.bytes as u64;
            }
            Dir::Out => {
                self.bytes_out += ev.bytes as u64;
                self.win_out += ev.bytes as u64;
            }
        }
        self.packets += 1;
        self.last_seen = now;

        if self.particles.len() < MAX_PARTICLES {
            // Paket kecil melaju lebih cepat, paket besar lebih santai.
            let small = 1.0 - (ev.bytes.min(1500) as f32 / 1500.0);
            let speed = 0.30 + 0.25 * small + (self.packets % 5) as f32 * 0.015;
            self.particles.push(Particle {
                x: if ev.dir == Dir::In { 0.0 } else { 1.0 },
                speed,
                dir: ev.dir,
                big: ev.bytes > 800,
                age: 0.0,
            });
        }

        if let (Some(src), Some(dst)) = (ev.src, ev.dst) {
            if !self.flows.contains_key(&(src, dst)) && self.flows.len() >= MAX_FLOWS {
                self.evict_flow();
            }
            let flow = self.flows.entry((src, dst)).or_insert(Flow {
                dir: ev.dir,
                bytes: 0,
                packets: 0,
                last_seen: now,
            });
            flow.bytes += ev.bytes as u64;
            flow.packets += 1;
            flow.last_seen = now;
        }
    }

    fn evict_flow(&mut self) {
        if let Some(oldest) = self
            .flows
            .iter()
            .min_by(|a, b| a.1.last_seen.total_cmp(&b.1.last_seen))
            .map(|(k, _)| *k)
        {
            self.flows.remove(&oldest);
        }
    }

    pub fn step(&mut self, dt: f32) {
        for p in &mut self.particles {
            match p.dir {
                Dir::In => p.x += p.speed * dt,
                Dir::Out => p.x -= p.speed * dt,
            }
            p.age += dt;
        }
        self.particles.retain(|p| (0.0..=1.0).contains(&p.x));
        self.pulse = (self.pulse - dt / 0.8).max(0.0);
    }

    /// Dipanggil tiap 1 detik untuk menghitung throughput dan mendeteksi lonjakan.
    pub fn roll(&mut self, now: f64) {
        self.rate_in = self.win_in as f64;
        self.rate_out = self.win_out as f64;
        self.win_in = 0;
        self.win_out = 0;

        let rate = self.rate_in + self.rate_out;
        let recent = self.spark.iter().rev().take(10);
        let (sum, count) = recent.fold((0.0, 0usize), |(s, c), v| (s + *v as f64, c + 1));
        let avg = if count > 0 { sum / count as f64 } else { 0.0 };
        if avg > 512.0 && rate > avg * 3.0 {
            self.pulse = 1.0;
        }

        if self.spark.len() == SPARK_LEN {
            self.spark.pop_front();
        }
        self.spark.push_back(rate as u64);
        self.prune_flows(now);
    }

    pub fn prune_flows(&mut self, now: f64) {
        self.flows
            .retain(|_, flow| now - flow.last_seen < FLOW_IDLE);
    }

    pub fn rate_total(&self) -> f64 {
        self.rate_in + self.rate_out
    }

    /// `true` kalau jalur sudah sepi lebih dari 20 detik (dinding meredup).
    pub fn quiet(&self, now: f64) -> bool {
        self.last_seen > 0.0 && now - self.last_seen > 20.0
    }

    /// Koneksi teratas diurutkan menurut byte.
    pub fn top_flows(&self, n: usize) -> Vec<(Endpoint, Endpoint, &Flow)> {
        let mut all: Vec<_> = self
            .flows
            .iter()
            .map(|((src, dst), flow)| (*src, *dst, flow))
            .collect();
        all.sort_by_key(|item| std::cmp::Reverse(item.2.bytes));
        all.truncate(n);
        all
    }

    /// Jumlah sesi aktif (ujung remote berbeda) dalam `window` detik terakhir.
    pub fn active_sessions(&self, now: f64, window: f64) -> usize {
        let Some(service) = self.kind.service_port() else {
            return 0;
        };
        let mut remotes = std::collections::HashSet::new();
        for ((src, dst), flow) in &self.flows {
            if now - flow.last_seen > window {
                continue;
            }
            let remote = if dst.port == service {
                src
            } else if src.port == service {
                dst
            } else {
                continue;
            };
            remotes.insert(remote.ip);
        }
        remotes.len()
    }

    /// IP remote yang paling banyak mengirim data masuk.
    pub fn top_remote_sender(&self, now: f64, window: f64) -> Option<(IpAddr, u64)> {
        let service = self.kind.service_port()?;
        let mut per_ip: HashMap<IpAddr, u64> = HashMap::new();
        for ((src, dst), flow) in &self.flows {
            if now - flow.last_seen > window
                || flow.dir != Dir::In
                || dst.port != service
                || src.port == service
            {
                continue;
            }
            *per_ip.entry(src.ip).or_default() += flow.bytes;
        }
        per_ip.into_iter().max_by_key(|(_, bytes)| *bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn packet(port: u16, dir: Dir, bytes: u32) -> PacketEvent {
        PacketEvent {
            port,
            dir,
            bytes,
            src: Some(Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000)),
            dst: Some(Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)),
        }
    }

    #[test]
    fn from_port_maps_fixed_services() {
        assert_eq!(Proto::from_port(22), Proto::Ssh);
        assert_eq!(Proto::from_port(443), Proto::Https);
        assert_eq!(Proto::from_port(80), Proto::Http);
        assert_eq!(Proto::from_port(53), Proto::Dns);
        assert_eq!(Proto::from_port(8080), Proto::Other);
    }

    #[test]
    fn step_moves_particles_and_drops_them_at_the_end() {
        let mut lane = Lane::new_fixed(Proto::Ssh);
        lane.push(&packet(22, Dir::In, 100), 0.0);
        assert_eq!(lane.particles.len(), 1);
        lane.step(0.1);
        assert!(lane.particles[0].x > 0.0);
        lane.step(10.0);
        assert!(lane.particles.is_empty());
    }

    #[test]
    fn roll_sets_rates_and_keeps_60_seconds_of_history() {
        let mut lane = Lane::new_fixed(Proto::Ssh);
        lane.push(&packet(22, Dir::In, 1000), 0.0);
        lane.roll(1.0);
        assert_eq!(lane.rate_in, 1000.0);
        assert_eq!(lane.rate_out, 0.0);
        assert_eq!(lane.spark.len(), 1);
        for i in 0..70 {
            lane.roll(i as f64 + 2.0);
        }
        assert_eq!(lane.spark.len(), SPARK_LEN);
        assert_eq!(lane.rate_in, 0.0);
    }

    #[test]
    fn flow_stats_and_sessions_are_tracked() {
        let mut lane = Lane::new_fixed(Proto::Ssh);
        for _ in 0..3 {
            lane.push(&packet(22, Dir::In, 100), 0.0);
        }
        assert_eq!(lane.packets, 3);
        assert_eq!(lane.bytes_in, 300);
        assert_eq!(lane.active_sessions(1.0, 60.0), 1);
        assert_eq!(lane.top_remote_sender(1.0, 60.0).map(|(_, b)| b), Some(300));
        assert_eq!(lane.top_flows(5).len(), 1);
    }

    #[test]
    fn top_remote_sender_ignores_outbound_flows() {
        let mut lane = Lane::new_fixed(Proto::Ssh);
        let local = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40000);
        let remote = Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 22);
        lane.push(
            &PacketEvent {
                port: 22,
                dir: Dir::Out,
                bytes: 500,
                src: Some(local),
                dst: Some(remote),
            },
            0.0,
        );
        assert!(lane.top_remote_sender(1.0, 60.0).is_none());
    }
}
