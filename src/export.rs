//! Ekspor snapshot statistik per jalur ke CSV (tombol `s`).

use std::{
    fs::File,
    io::{self, BufWriter, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::app::App;

pub fn snapshot(app: &App) -> io::Result<String> {
    let (stamp, iso) = now_utc();
    let name = format!("netflow-{stamp}.csv");
    let file = File::create(&name)?;
    let mut out = BufWriter::new(file);

    writeln!(
        out,
        "waktu_utc,jalur,port,jenis,masuk_byte,keluar_byte,paket,rate_masuk_bps,rate_keluar_bps"
    )?;
    for lane in &app.lanes {
        writeln!(
            out,
            "{iso},{},{},{},{},{},{},{:.0},{:.0}",
            lane.name,
            lane.kind.service_port().unwrap_or(0),
            if lane.kind.is_dynamic() {
                "dinamis"
            } else {
                "tetap"
            },
            lane.bytes_in,
            lane.bytes_out,
            lane.packets,
            lane.rate_in,
            lane.rate_out,
        )?;
    }
    out.flush()?;
    Ok(name)
}

/// Kembalikan `YYYYmmdd-HHMMSS` dan `YYYY-MM-DDTHH:MM:SSZ` dalam UTC.
fn now_utc() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    (
        format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}"),
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"),
    )
}

/// Algoritma Howard Hinnant: hari sejak 1970-01-01 -> (tahun, bulan, hari).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if m <= 2 {
        y += 1;
    }
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::civil_from_days;

    #[test]
    fn civil_dates_match_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }
}
