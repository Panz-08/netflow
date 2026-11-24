//! Sumber data paket. `sim` selalu ada, `live` butuh fitur `live` (libpcap).

pub mod sim;

#[cfg(feature = "live")]
pub mod live;

use crate::model::PacketEvent;

/// Pesan dari sumber data ke loop utama.
#[derive(Debug)]
pub enum SourceEvent {
    Packet(PacketEvent),
    /// Pesan untuk header UI. `warn` = tampilkan sebagai peringatan amber.
    #[cfg_attr(not(feature = "live"), allow(dead_code))]
    Status {
        text: String,
        warn: bool,
    },
}

impl SourceEvent {
    #[cfg_attr(not(feature = "live"), allow(dead_code))]
    pub fn status(text: impl Into<String>, warn: bool) -> Self {
        Self::Status {
            text: text.into(),
            warn,
        }
    }
}
