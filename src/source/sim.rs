//! Sumber data simulasi: lalu lintas palsu supaya NetFlow bisa dicoba tanpa root.

use std::{net::IpAddr, time::Duration};

use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::mpsc;

use crate::model::{Dir, Endpoint, PacketEvent};

use super::SourceEvent;

pub async fn run(tx: mpsc::Sender<SourceEvent>) {
    let mut rng = StdRng::from_entropy();
    let local: IpAddr = "192.168.1.10".parse().expect("IP simulasi valid");
    let mut burst = 0u32;

    loop {
        let wait = if burst > 0 {
            burst -= 1;
            rng.gen_range(12..30u64)
        } else {
            if rng.gen_bool(0.025) {
                burst = rng.gen_range(8..16);
            }
            rng.gen_range(40..220u64)
        };
        tokio::time::sleep(Duration::from_millis(wait)).await;

        let roll: u8 = rng.gen_range(0..100);
        let port: u16 = match roll {
            0..=43 => 443,
            44..=63 => 22,
            64..=75 => 80,
            76..=90 => 53,
            91..=95 => 8080,
            96..=97 => 3306,
            98..=99 => 3389,
            _ => 8080,
        };
        let bytes: u32 = match port {
            22 => rng.gen_range(64..400),
            53 => rng.gen_range(70..180),
            80 | 8080 => rng.gen_range(200..1200),
            _ => rng.gen_range(100..1500),
        };
        let dir = if rng.gen_bool(0.55) {
            Dir::In
        } else {
            Dir::Out
        };
        let remote: IpAddr = match rng.gen_range(0..4) {
            0 => "93.184.216.34".parse().expect("IP valid"),
            1 => "142.250.4.100".parse().expect("IP valid"),
            2 => "151.101.1.140".parse().expect("IP valid"),
            _ => "203.0.113.7".parse().expect("IP valid"),
        };
        let ephemeral = rng.gen_range(32768..61000u16);

        let (src, dst) = match dir {
            Dir::In => (Endpoint::new(remote, ephemeral), Endpoint::new(local, port)),
            Dir::Out => (Endpoint::new(local, ephemeral), Endpoint::new(remote, port)),
        };

        let event = SourceEvent::Packet(PacketEvent {
            port,
            dir,
            bytes,
            src: Some(src),
            dst: Some(dst),
        });
        if tx.send(event).await.is_err() {
            break;
        }
    }
}
