//! Argumen baris perintah `ntf`.

#[derive(Debug, Default, PartialEq)]
pub struct Args {
    pub iface: Option<String>,
    pub filter: Option<String>,
    pub belajar: bool,
    pub list: bool,
    pub sim: bool,
    pub help: bool,
    pub version: bool,
}

pub const USAGE: &str = "\
Pemakaian:
  ntf                          simulasi (tanpa root)
  ntf <interface>              tangkap paket sungguhan
  ntf <interface> --filter \"tcp port 22\"
  ntf --list                   daftar interface dan alamat IP
  ntf --belajar                mode belajar untuk kelas TKJ

Opsi:
  --filter <bpf>   filter BPF saat menangkap paket
  --sim            paksa mode simulasi
  -h, --help       tampilkan bantuan
  -V, --version    tampilkan versi";

pub const HELP: &str = "\
NetFlow v0.2 — analisis jalur data di port, tampil sebagai selang dan bola.
Oleh Panz-08.

Pemakaian:
  ntf                          simulasi (tanpa root)
  ntf <interface>              tangkap paket sungguhan (butuh izin capture)
  ntf <interface> --filter \"tcp port 22\"
  ntf --list                   daftar interface dan alamat IP
  ntf --belajar                tampilkan penjelasan singkat tiap jalur
  ntf --sim                    paksa mode simulasi

Opsi:
  --filter <bpf>   filter BPF, contoh: \"tcp port 22\" atau \"udp port 53\"
  --sim            paksa mode simulasi walau interface diberikan
  -h, --help       tampilkan bantuan ini
  -V, --version    tampilkan versi

Contoh:
  ntf eth0
  sudo setcap cap_net_raw,cap_net_admin=eip \"$(command -v ntf)\"
  ntf wlan0 --filter \"tcp or udp\"

Tombol di dalam aplikasi:
  ↑/↓ pilih jalur · Spasi jeda · Enter detail · c kontras · s simpan CSV
  ? bantuan · q keluar";

pub fn parse<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut out = Args::default();
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => out.help = true,
            "-V" | "--version" => out.version = true,
            "--list" => out.list = true,
            "--belajar" | "--learn" => out.belajar = true,
            "--sim" | "--simulasi" => out.sim = true,
            "--filter" => {
                out.filter = Some(iter.next().ok_or("--filter butuh argumen BPF")?);
            }
            other if other.starts_with("--filter=") => {
                out.filter = Some(other["--filter=".len()..].to_string());
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("opsi tidak dikenal: {other}"));
            }
            other => {
                if out.iface.is_some() {
                    return Err(format!("interface ganda: {other}"));
                }
                out.iface = Some(other.to_string());
            }
        }
    }

    if out.filter.is_some() && out.iface.is_none() && !out.sim {
        return Err("--filter butuh nama interface".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Result<Args, String> {
        parse(items.iter().map(|s| s.to_string()))
    }

    #[test]
    fn empty_means_simulation() {
        assert_eq!(args(&[]).unwrap(), Args::default());
    }

    #[test]
    fn parses_interface_and_filter() {
        let parsed = args(&["eth0", "--filter", "tcp port 22"]).unwrap();
        assert_eq!(parsed.iface.as_deref(), Some("eth0"));
        assert_eq!(parsed.filter.as_deref(), Some("tcp port 22"));
    }

    #[test]
    fn parses_equals_filter_and_flags() {
        let parsed = args(&["--belajar", "wlan0", "--filter=udp port 53"]).unwrap();
        assert!(parsed.belajar);
        assert_eq!(parsed.iface.as_deref(), Some("wlan0"));
        assert_eq!(parsed.filter.as_deref(), Some("udp port 53"));
    }

    #[test]
    fn rejects_filter_without_interface() {
        assert!(args(&["--filter", "tcp"]).is_err());
    }

    #[test]
    fn rejects_unknown_option_and_double_interface() {
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["eth0", "wlan0"]).is_err());
    }
}
