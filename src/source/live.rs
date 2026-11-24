//! Sumber data sungguhan lewat libpcap (fitur `live`).
//!
//! Mendukung Ethernet + VLAN 802.1Q + IPv4/IPv6 + TCP/UDP. Arah paket
//! ditentukan dari daftar IP lokal interface, bukan tebakan port.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use pcap::{Capture, Device, Error, Linktype};
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::model::{is_service_port, Dir, Endpoint, PacketEvent};

use super::SourceEvent;

/// Daftar interface beserta alamat IP-nya, untuk `ntf --list`.
pub fn interfaces() -> Result<Vec<(String, Vec<IpAddr>)>, Error> {
    Ok(Device::list()?
        .into_iter()
        .map(|device| {
            let addrs = device.addresses.into_iter().map(|a| a.addr).collect();
            (device.name, addrs)
        })
        .collect())
}

fn local_ips(iface: &str) -> HashSet<IpAddr> {
    let Ok(devices) = Device::list() else {
        return HashSet::new();
    };
    if iface == "any" {
        // `any` tidak punya alamat sendiri; gabungkan semua alamat mesin.
        return devices
            .into_iter()
            .flat_map(|device| device.addresses)
            .map(|a| a.addr)
            .collect();
    }
    devices
        .into_iter()
        .find(|device| device.name == iface)
        .map(|device| device.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

/// Device virtual tertentu tidak mendukung promiscuous mode. Kalau dipaksa,
/// libpcap gagal membuka capture (contoh: `Promiscuous mode not supported on
/// the "any" device`).
fn supports_promisc(iface: &str) -> bool {
    !(iface == "any"
        || iface.starts_with("nflog")
        || iface.starts_with("nfqueue")
        || iface.starts_with("dbus-")
        || iface == "bluetooth-monitor")
}

/// Jalankan di `spawn_blocking`. Berhenti saat channel ditutup.
pub fn run(
    tx: mpsc::Sender<SourceEvent>,
    iface: String,
    filter: Option<String>,
) -> Result<(), Error> {
    let local = local_ips(&iface);

    let mut builder = Capture::from_device(iface.as_str())?;
    // `any` (dan beberapa device virtual) tidak mendukung promiscuous mode;
    // kalau dipaksa, libpcap menolak membuka capture sama sekali.
    if supports_promisc(&iface) {
        builder = builder.promisc(true);
    }
    let mut cap = builder.snaplen(256).timeout(100).open()?;
    if let Some(program) = filter {
        cap.filter(&program, true)?;
    }

    let linktype = cap.get_datalink();
    let parser = Parser::for_linktype(local, linktype);
    if !parser.supported() {
        let _ = tx.try_send(SourceEvent::status(
            format!(
                "Linktype {} ({:?}) belum didukung; coba interface lain",
                linktype.0, linktype
            ),
            true,
        ));
        return Ok(());
    }

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(event) = parser.parse(packet.data, packet.header.len) {
                    if let Err(TrySendError::Closed(_)) = tx.try_send(SourceEvent::Packet(event)) {
                        break;
                    }
                }
            }
            Err(Error::TimeoutExpired) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Link {
    Ethernet,
    Sll,
    Sll2,
    Raw,
    Unsupported,
}

impl Link {
    fn from_linktype(linktype: Linktype) -> Self {
        if linktype == Linktype::ETHERNET {
            Link::Ethernet
        } else if linktype == Linktype::LINUX_SLL {
            Link::Sll
        } else if linktype == Linktype::LINUX_SLL2 {
            Link::Sll2
        } else if linktype == Linktype::RAW {
            Link::Raw
        } else {
            Link::Unsupported
        }
    }

    /// Kembalikan (offset L3, ethertype).
    fn payload(self, data: &[u8]) -> Option<(usize, u16)> {
        match self {
            Link::Ethernet => ethernet_payload(data),
            Link::Sll => {
                if data.len() < 16 {
                    return None;
                }
                Some((16, u16::from_be_bytes([data[14], data[15]])))
            }
            Link::Sll2 => {
                if data.len() < 20 {
                    return None;
                }
                Some((20, u16::from_be_bytes([data[0], data[1]])))
            }
            Link::Raw => match data.first()? >> 4 {
                4 => Some((0, 0x0800)),
                6 => Some((0, 0x86dd)),
                _ => None,
            },
            Link::Unsupported => None,
        }
    }
}

/// Parser paket yang bisa diuji tanpa membuka interface.
pub struct Parser {
    local: HashSet<IpAddr>,
    link: Link,
}

impl Parser {
    pub fn new(local: HashSet<IpAddr>) -> Self {
        Self {
            local,
            link: Link::Ethernet,
        }
    }

    pub fn for_linktype(local: HashSet<IpAddr>, linktype: Linktype) -> Self {
        let mut parser = Self::new(local);
        parser.link = Link::from_linktype(linktype);
        parser
    }

    pub fn supported(&self) -> bool {
        self.link != Link::Unsupported
    }

    pub fn parse(&self, data: &[u8], wire_len: u32) -> Option<PacketEvent> {
        let (l3, ethertype) = self.link.payload(data)?;
        let (src_ip, dst_ip, l4, protocol) = match ethertype {
            0x0800 => ipv4(data, l3)?,
            0x86dd => ipv6(data, l3)?,
            _ => return None,
        };
        let (src_port, dst_port) = match protocol {
            6 | 17 => ports(data, l4)?,
            _ => return None,
        };

        let src_local = self.local.contains(&src_ip);
        let dst_local = self.local.contains(&dst_ip);
        let dir = if self.local.is_empty() {
            fallback_dir(src_port, dst_port)
        } else {
            match (src_local, dst_local) {
                (true, false) => Dir::Out,
                (false, true) => Dir::In,
                (true, true) => fallback_dir(src_port, dst_port),
                (false, false) => return None,
            }
        };

        Some(PacketEvent {
            port: service_port(src_port, dst_port),
            dir,
            bytes: wire_len,
            src: Some(Endpoint::new(src_ip, src_port)),
            dst: Some(Endpoint::new(dst_ip, dst_port)),
        })
    }
}

/// Kalau IP lokal tidak diketahui, tebak dari port layanan. Ini cadangan saja.
fn fallback_dir(src_port: u16, dst_port: u16) -> Dir {
    let src_service = is_service_port(src_port);
    let dst_service = is_service_port(dst_port);
    match (src_service, dst_service) {
        (true, false) => Dir::In,
        (false, true) => Dir::Out,
        _ => Dir::In,
    }
}

/// Port yang dipakai untuk jalur: port layanan yang dikenal, kalau tidak ada
/// maka port yang lebih kecil.
fn service_port(src: u16, dst: u16) -> u16 {
    let src_service = is_service_port(src);
    let dst_service = is_service_port(dst);
    match (src_service, dst_service) {
        (false, true) => dst,
        (true, false) => src,
        (true, true) => src.min(dst),
        (false, false) => src.min(dst),
    }
}

/// Lewati header Ethernet dan lapisan VLAN (802.1Q / QinQ).
fn ethernet_payload(data: &[u8]) -> Option<(usize, u16)> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    let mut tags = 0;
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) && tags < 3 {
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        tags += 1;
    }
    Some((offset, ethertype))
}

fn ipv4(data: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, usize, u8)> {
    if data.len() < offset + 20 {
        return None;
    }
    let version_ihl = data[offset];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < offset + ihl {
        return None;
    }
    // Fragmen selain fragmen pertama tidak punya header TCP/UDP.
    let frag = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
    if frag & 0x1fff != 0 {
        return None;
    }
    let protocol = data[offset + 9];
    let src = IpAddr::V4(Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ));
    Some((src, dst, offset + ihl, protocol))
}

fn ipv6(data: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, usize, u8)> {
    if data.len() < offset + 40 || data[offset] >> 4 != 6 {
        return None;
    }
    let mut next = data[offset + 6];
    let src = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[offset + 8..offset + 24]).ok()?,
    ));
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[offset + 24..offset + 40]).ok()?,
    ));
    let mut cursor = offset + 40;
    let mut hops = 0;
    while hops < 8 {
        match next {
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                if data.len() < cursor + 2 {
                    return None;
                }
                let len = (data[cursor + 1] as usize + 1) * 8;
                next = data[cursor];
                cursor += len;
            }
            // Authentication header.
            51 => {
                if data.len() < cursor + 2 {
                    return None;
                }
                let len = (data[cursor + 1] as usize + 2) * 4;
                next = data[cursor];
                cursor += len;
            }
            // Fragment header: hanya fragmen pertama yang punya port.
            44 => {
                if data.len() < cursor + 8 {
                    return None;
                }
                let frag = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]);
                if frag & 0xfff8 != 0 {
                    return None;
                }
                next = data[cursor];
                cursor += 8;
            }
            _ => break,
        }
        hops += 1;
    }
    if data.len() < cursor {
        return None;
    }
    Some((src, dst, cursor, next))
}

fn ports(data: &[u8], offset: usize) -> Option<(u16, u16)> {
    if data.len() < offset + 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([data[offset], data[offset + 1]]),
        u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        let total = (20 + l4.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet.extend_from_slice(l4);
        packet
    }

    fn ipv6(next: u8, src: Ipv6Addr, dst: Ipv6Addr, l4: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        let len = l4.len() as u16;
        packet[4..6].copy_from_slice(&len.to_be_bytes());
        packet[6] = next;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet.extend_from_slice(l4);
        packet
    }

    fn tcp(src: u16, dst: u16) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0..2].copy_from_slice(&src.to_be_bytes());
        header[2..4].copy_from_slice(&dst.to_be_bytes());
        header
    }

    fn udp(src: u16, dst: u16) -> Vec<u8> {
        let mut header = vec![0u8; 8];
        header[0..2].copy_from_slice(&src.to_be_bytes());
        header[2..4].copy_from_slice(&dst.to_be_bytes());
        header
    }

    fn parser(local: &[&str]) -> Parser {
        Parser::new(local.iter().map(|ip| ip.parse().unwrap()).collect())
    }

    fn frame(payload: &[u8]) -> (Vec<u8>, u32) {
        let wire = payload.len() as u32;
        (ethernet(0x0800, payload), wire)
    }

    #[test]
    fn parses_inbound_ipv4_tcp() {
        let (packet, wire) = frame(&ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1], &tcp(40000, 22)));
        let event = parser(&["10.0.0.1"]).parse(&packet, wire).unwrap();
        assert_eq!(event.port, 22);
        assert_eq!(event.dir, Dir::In);
        assert_eq!(event.bytes, wire);
        assert_eq!(event.src.unwrap().port, 40000);
        assert_eq!(event.dst.unwrap().port, 22);
    }

    #[test]
    fn parses_outbound_ipv4_https() {
        let (packet, wire) = frame(&ipv4(
            6,
            [10, 0, 0, 1],
            [93, 184, 216, 34],
            &tcp(40000, 443),
        ));
        let event = parser(&["10.0.0.1"]).parse(&packet, wire).unwrap();
        assert_eq!(event.port, 443);
        assert_eq!(event.dir, Dir::Out);
    }

    #[test]
    fn parses_ipv6_udp_dns() {
        let src: Ipv6Addr = "2001:db8::53".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let payload = ipv6(17, src, dst, &udp(53, 5353));
        let packet = ethernet(0x86dd, &payload);
        let wire = packet.len() as u32;
        let event = parser(&["2001:db8::1"]).parse(&packet, wire).unwrap();
        assert_eq!(event.port, 53);
        assert_eq!(event.dir, Dir::In);
    }

    #[test]
    fn parses_vlan_tagged_ipv4() {
        let payload = ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1], &tcp(40000, 80));
        let mut tagged = vec![0u8; 12];
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64]); // VLAN ID 100
        tagged.extend_from_slice(&0x0800u16.to_be_bytes());
        tagged.extend_from_slice(&payload);
        let wire = tagged.len() as u32;
        let event = parser(&["10.0.0.1"]).parse(&tagged, wire).unwrap();
        assert_eq!(event.port, 80);
        assert_eq!(event.dir, Dir::In);
    }

    #[test]
    fn ignores_traffic_between_other_hosts() {
        let (packet, wire) = frame(&ipv4(6, [10, 0, 0, 2], [10, 0, 0, 3], &tcp(40000, 443)));
        assert!(parser(&["10.0.0.1"]).parse(&packet, wire).is_none());
    }

    #[test]
    fn parses_linux_sll_frames() {
        let payload = ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1], &tcp(40000, 443));
        let mut frame = vec![0u8; 16];
        frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&payload);
        let wire = frame.len() as u32;
        let local: HashSet<IpAddr> = ["10.0.0.1".parse().unwrap()].into_iter().collect();
        let parser = Parser::for_linktype(local, Linktype::LINUX_SLL);
        let event = parser.parse(&frame, wire).unwrap();
        assert_eq!(event.port, 443);
        assert_eq!(event.dir, Dir::In);
    }

    #[test]
    fn parses_linux_sll2_frames() {
        let payload = ipv4(6, [10, 0, 0, 1], [93, 184, 216, 34], &tcp(40000, 443));
        let mut frame = vec![0u8; 20];
        frame[0..2].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&payload);
        let wire = frame.len() as u32;
        let local: HashSet<IpAddr> = ["10.0.0.1".parse().unwrap()].into_iter().collect();
        let parser = Parser::for_linktype(local, Linktype::LINUX_SLL2);
        let event = parser.parse(&frame, wire).unwrap();
        assert_eq!(event.port, 443);
        assert_eq!(event.dir, Dir::Out);
    }

    #[test]
    fn service_port_prefers_known_service() {
        assert_eq!(service_port(40000, 22), 22);
        assert_eq!(service_port(443, 51000), 443);
        assert_eq!(service_port(40000, 50000), 40000);
    }

    #[test]
    fn skips_promisc_on_virtual_devices() {
        assert!(!supports_promisc("any"));
        assert!(!supports_promisc("nflog"));
        assert!(!supports_promisc("dbus-system"));
        assert!(supports_promisc("wlan0"));
        assert!(supports_promisc("enp4s0"));
    }
}
