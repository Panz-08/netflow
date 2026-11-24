# NetFlow

**Lihat data yang lewat di port, dalam bentuk selang dan bola yang jalan.**
Tools terminal buat belajar jaringan, dibuat santai buat anak TKJ.

Pernah penasaran kenapa Wi-Fi kerasa berat padahal nggak ada yang download?
Atau penasaran port 22, 443, dan 53 itu sebenernya ngapain aja?

NetFlow bikin semua itu kelihatan. Tiap layanan punya satu **selang**.
Tiap paket jadi satu **bola** yang lewat di dalam selang: ke kanan berarti data masuk,
ke kiri berarti data keluar. Sekali lihat, langsung kelihatan jalur mana yang ramai.

Stack-nya Rust + [ratatui](https://ratatui.rs) + tokio + libpcap.

---

## Sekilas tampilan

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│ NetFlow  Analisis Jalur Data                  oleh Panz-08  ·  eth0  ·  LIVE │
╰──────────────────────────────────────────────────────────────────────────────╯
╭ Jalur Data ──────────────────────────────────────────────────────────────────╮
│                                                                              │
│              ╭──────────────────────────────────────────╮                    │
│ ▎ SSH        │┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈━━━●●━━•┈┈┈┈▶  ↓ 1.2 KB/s        │
│   :22        ◀┈┈┈┈┈┈┈┈┈┈┈•━━━┈•━━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈│  ↑ 480 B/s         │
│              ╰──────────────────────────────────────────╯                    │
│              ╭──────────────────────────────────────────╮                    │
│   HTTPS      │┈┈┈┈━━━●━━●━━━●┈━━━●┈┈━━━●┈━━━●┈━━━●┈┈┈┈┈┈▶  ↓ 86.4 KB/s       │
│   :443       ◀┈┈┈┈┈┈●━━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈●━━━┈┈┈┈••━━━┈┈┈┈│  ↑ 12.1 KB/s       │
│              ╰──────────────────────────────────────────╯                    │
│              ╭──────────────────────────────────────────╮                    │
│   HTTP       │┈┈━━━•┈━━━•┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈▶  ↓ 3.4 KB/s        │
│   :80        ◀┈┈┈┈┈┈┈┈┈┈•━━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈•━━━┈┈┈┈┈┈┈│  ↑ 0.9 KB/s        │
│              ╰──────────────────────────────────────────╯                    │
│              ╭──────────────────────────────────────────╮                    │
│   DNS        │┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈━━━•┈┈┈┈┈┈┈┈┈┈┈┈┈┈━━━●┈┈┈┈▶  ↓ 220 B/s         │
│   :53        ◀┈┈┈┈┈┈┈┈┈┈┈●━•━━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈•━━━┈┈┈┈┈┈┈┈│  ↑ 190 B/s         │
│              ╰──────────────────────────────────────────╯                    │
│              ╭──────────────────────────────────────────╮                    │
│   Lainnya    │┈┈┈┈┈┈━━━●┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈▶  ↓ 1.1 KB/s        │
│   port lain  ◀┈┈┈┈┈●━━━┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈│  ↑ 300 B/s         │
│              ╰──────────────────────────────────────────╯                    │
╰──────────────────────────────────────────────────────────────────────────────╯
╭ Detail · SSH ────────────────────────────────────────────────────────────────╮
│ Masuk ↓ 1.8 MB   Keluar ↑ 640.2 KB   Paket 5201   Sesi 3                     │
│ 60 dtk   ▂▃▅▆▇█▇▅▃▂                                                          │
│ ↑ 192.168.1.10:42000 → 93.184.216.34:22   12.3 KB  8 pkt                     │
│ Legenda  ● SSH   ● HTTPS   ● HTTP   ● DNS   ● Lainnya                        │
╰──────────────────────────────────────────────────────────────────────────────╯
 ↑/↓ pilih   Spasi jeda   Enter detail   ? bantuan   q keluar                NetFlow v0.2 · Panz-08
```

### Bacanya gimana?

| Yang kamu lihat | Artinya |
| --- | --- |
| `╭──╮ ╰──╯` | Dinding selang. Makin terang kalau jalurnya lagi dipilih |
| `┈┈┈` | Jalur kosong di dalam selang |
| `●` | Paket gede (di atas 800 byte) |
| `•` | Paket kecil |
| `━━` di belakang bola | Ekor bola, makin ke belakang makin pudar |
| `▶` di kanan baris atas | Data **masuk** |
| `◀` di kiri baris bawah | Data **keluar** |
| `▎` di label | Jalur yang lagi dipilih |

Baris atas = masuk. Baris bawah = keluar. Gampangnya: bola ke kanan itu data yang
datang ke komputer kamu, bola ke kiri itu data yang kamu kirim.

Kalau ada port lain yang ramai, NetFlow otomatis bikinin jalur baru
(misalnya `:8080 HTTP-alt` atau `:3306 MySQL`). Kalau udah sepi 30 detik,
jalurnya memudar pelan-pelan, bukan langsung hilang.

## Pasang

Binary-nya namanya **`ntf`**. Paling gampang:

```bash
git clone https://github.com/Panz-08/netflow.git
cd netflow
./install.sh
```

Script itu build dengan fitur `live`, lalu masang `ntf` ke `~/.local/bin`.
Kalau belum ada `libpcap-dev` dan cuma mau coba simulasi:

```bash
FEATURES= ./install.sh
```

Kalau `ntf` belum kebaca, pastikan `~/.local/bin` masuk `PATH`.
Cek cepat:

```bash
ntf --version
ntf --list
```

Pasang manual juga nggak masalah:

```bash
cargo build --release --features live
install -Dm755 target/release/ntf ~/.local/bin/ntf
```

Atau lewat cargo:

```bash
cargo install --path . --features live
```

## Pakai

```bash
# Simulasi, aman tanpa root
ntf

# Lihat interface dan IP yang ada
ntf --list

# Tangkap paket beneran
sudo ntf wlan0
```

Biar nggak perlu `sudo` terus, kasih izin sekali aja:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v ntf)"
ntf wlan0
```

Catatan: kalau nanti `./install.sh` dijalankan lagi, binary-nya diganti dan
izin `setcap` perlu dipasang ulang.

Mau lebih spesifik? Pakai filter BPF:

```bash
ntf wlan0 --filter "tcp port 22"
ntf wlan0 --filter "udp port 53"
```

Kalau mau lihat semua interface sekaligus, pakai `any`:

```bash
ntf any
```

Mode ini memakai Linux cooked capture (SLL), jadi tetap bisa membaca paket dari
Wi-Fi, kabel, dan loopback dalam satu tampilan.

Buat ngajar di kelas:

```bash
ntf --belajar
```

Mode ini nampilin satu kalimat penjelasan tiap jalur, jadi murid nggak cuma lihat
angka tapi juga tahu SSH, HTTPS, DNS itu buat apa.

### Opsi

| Opsi | Buat apa |
| --- | --- |
| `ntf` | Simulasi, tanpa root |
| `ntf <interface>` | Tangkap paket asli (butuh fitur `live` + izin capture) |
| `--filter <bpf>` | Filter paket, contoh `tcp port 22` |
| `--list` | Daftar interface + alamat IP |
| `--belajar` | Tampilkan penjelasan singkat tiap jalur |
| `--sim` | Paksa mode simulasi |
| `-h`, `--help` | Bantuan |
| `-V`, `--version` | Versi |

### Tombol

| Tombol | Fungsi |
| --- | --- |
| `↑`/`↓` atau `j`/`k` | Pindah jalur |
| `Spasi` | Jeda / lanjut |
| `Enter` | Buka layar detail penuh |
| `Esc` | Kembali, atau keluar kalau lagi di layar utama |
| `c` | Mode kontras tinggi (enak buat proyektor) |
| `s` | Simpan snapshot CSV di folder sekarang |
| `?` | Bantuan singkat |
| `q` / `Ctrl+C` | Keluar |

CSV-nya namanya `netflow-YYYYmmdd-HHMMSS.csv` (waktu UTC). Isinya satu baris per
jalur: byte masuk, byte keluar, jumlah paket, dan laju saat snapshot.

## Fitur

- Lima jalur tetap: SSH, HTTPS, HTTP, DNS, dan Lainnya.
- Jalur dinamis buat port lain yang ramai (top 3), lengkap dengan nama layanan.
- Bola bergerak 30 FPS, ukuran dan kecepatannya ikut ukuran paket.
- Throughput masuk/keluar per detik.
- Panel detail: sparkline 60 detik, 5 koneksi teratas, sesi SSH, dan IP remote
  yang paling banyak ngirim.
- Layar detail penuh, mode kontras, bantuan, ekspor CSV, mode belajar.
- Masih enak dipakai di terminal 80x24. Kalau jalurnya kebanyakan, tampilannya
  gulir otomatis dan ada penanda "↓ n jalur lagi".
- Parser pcap: Ethernet, VLAN 802.1Q/QinQ, IPv4, IPv6, TCP/UDP, plus Linux SLL
  (buat interface `any`).

### Kalau capture-nya gagal

Biasanya karena belum punya izin. NetFlow nggak akan panik; pesan errornya
muncul di header dengan warna amber. Solusinya:

```bash
sudo ntf wlan0
# atau
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v ntf)"
```

Kalau interface-nya salah, cek dulu pakai `ntf --list`.

## Warna

Temanya namanya "Slate": gelap, tenang, nggak neon, nggak ala hacker.
Semua warna ada di `src/theme.rs`, jadi kalau mau ganti cukup di situ.

| Bagian | RGB |
| --- | --- |
| Latar | `22, 27, 34` |
| Garis panel | `56, 66, 82` |
| Teks | `213, 220, 230` |
| Teks redup | `125, 135, 152` |
| Aksen | `99, 160, 245` |
| Dinding selang | `78, 90, 110` (terpilih `122, 138, 164`) |
| Garis dalam selang | `44, 52, 66` |
| SSH | `78, 201, 176` |
| HTTPS | `106, 166, 255` |
| HTTP | `176, 148, 250` |
| DNS | `245, 190, 92` |
| Lainnya | `150, 160, 178` |
| Dinamis | 6 warna pastel di `theme::DYNAMIC` |
| OK / peringatan | `112, 200, 150` / `240, 184, 90` |

## Isi repo

```text
netflow/
├── Cargo.toml
├── install.sh         build + pasang binary `ntf`
├── LICENSE
├── README.md
└── src/
    ├── main.rs        loop utama tokio (tick 33 ms, input, paket)
    ├── cli.rs         parsing argumen `ntf`
    ├── app.rs         state aplikasi, routing paket, jalur dinamis
    ├── model.rs       Proto, PacketEvent, Particle, Flow, Lane
    ├── theme.rs       semua warna + mode kontras
    ├── export.rs      snapshot CSV
    ├── source/
    │   ├── mod.rs
    │   ├── sim.rs     lalu lintas simulasi
    │   └── live.rs    libpcap + parser IPv4/IPv6/VLAN/SLL
    └── ui/
        ├── mod.rs     layout: header, detail, footer, bantuan
        ├── detail.rs  panel detail + tabel koneksi
        └── pipes.rs   gambar selang dan bola
```

Alurnya sederhana: sumber data kirim `SourceEvent` lewat channel tokio,
`App::on_packet` bikin bola di jalur yang cocok, `App::update` gerakin bola tiap
tick dan hitung throughput tiap detik, lalu `ui::draw` menggambar.

## Ngoprek

```bash
cargo test                          # test biasa
cargo test --features live          # termasuk test parser pcap
cargo clippy --all-targets --features live
```

Unit test-nya nyakup `Lane::step`, `Lane::roll`, `Proto::from_port`, routing jalur
dinamis, parser IPv4/IPv6/VLAN/SLL, dan format tanggal CSV.

### Parser pcap

`src/source/live.rs` baca frame Ethernet, lewatin tag VLAN, dukung IPv4 dan IPv6
(termasuk header ekstensi), lalu ambil port TCP/UDP. Arah paket ditentukan dari
daftar IP milik interface, bukan nebak-nebak port. Port yang dipakai buat jalur
adalah port layanan yang dikenal; kalau nggak ada, pakai port yang lebih kecil.

## FAQ singkat

**Grafiknya kosong, padahal internet jalan.**
Kalau `ntf` dijalankan tanpa nama interface, itu mode simulasi. Coba `ntf --list`,
lalu jalankan `sudo ntf <interface>`. Kalau masih kosong, cek pesan di header.

**Aman nggak dipakai di jaringan sekolah atau kantor?**
NetFlow cuma membaca paket dan nggak mengubah apa pun. Tapi tetap minta izin admin
jaringan sebelum menangkap traffic di jaringan yang bukan punyamu.

**Kenapa angkanya beda sama speedtest?**
Yang dihitung adalah ukuran paket yang lewat di interface, bukan kecepatan langganan
internet. Jadi yang penting perbandingan antar jalur, bukan angka absolutnya.

**Bisa lihat isi paketnya?**
Nggak. Yang ditampilkan cuma alamat IP, port, dan ukuran paket. Isi data nggak
disimpan dan nggak ditampilkan.

**Kenapa muncul jalur baru terus hilang?**
Itu jalur dinamis. Port yang lagi ramai dapat jalur sendiri, lalu memudar setelah
sepi 30 detik supaya layar nggak penuh.

## Rencana

- [x] Tampilan selang + bola, tema Slate
- [x] Parser pcap IPv4/IPv6/VLAN/SLL, filter BPF
- [x] Jalur dinamis buat port ramai
- [x] Panel detail, sparkline, sesi SSH
- [x] Kontras tinggi, bantuan, tahan terminal kecil
- [x] Ekspor CSV + mode belajar
- [x] Binary `ntf` + installer
- [ ] Paket `.deb`
- [ ] Mode baca file `.pcap` buat bahan praktik

## Kontributor

- **Panz-08** ([@Panz-08](https://github.com/Panz-08)) — ide, kode, tampilan.
- **Nakki-Kun** ([@Nakki-Kun](https://github.com/Nakki-Kun)) — dokumentasi, FAQ,
  dan pengecekan.

Kalau nemu bug atau punya ide, silakan buka issue. Nggak harus jago Rust;
laporan "ini bingung dibacanya" juga berguna banget.

## Lisensi

MIT. Silakan dipakai, diubah, dan dibagikan. Lihat [LICENSE](LICENSE).

---

Dibuat sambil belajar. Semoga bermanfaat buat kelas TKJ. 🛰️
