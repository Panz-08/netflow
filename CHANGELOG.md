# Changelog

Semua perubahan penting di NetFlow dicatat di sini.
Formatnya santai, nggak harus rapi banget yang penting jelas.

## v0.2.0 — 2026-11-24

Rilis publik pertama.

### Tampilan

- Lima jalur tetap: SSH, HTTPS, HTTP, DNS, dan Lainnya.
- Jalur dinamis untuk port lain yang ramai, lengkap dengan nama layanan.
- Bola bergerak 30 FPS; ukuran dan kecepatan bola mengikuti ukuran paket.
- Ekor bola, fade-in, dan denyut saat ada lonjakan trafik.
- Panel detail: sparkline 60 detik, 5 koneksi teratas, sesi SSH, dan IP remote
  yang paling banyak mengirim.
- Layar detail penuh (`Enter`), mode kontras (`c`), bantuan (`?`).
- Tahan terminal 80x24: jalur digulir dan ada penanda "↓ n jalur lagi".

### Data

- Mode simulasi tanpa root, tanpa libpcap.
- Capture live lewat libpcap dengan fitur `live`.
- Parser Ethernet, VLAN 802.1Q/QinQ, IPv4, IPv6, TCP/UDP.
- Dukungan Linux cooked capture (SLL/SLL2) untuk interface `any`.
- Arah paket ditentukan dari daftar IP milik interface, bukan tebakan port.
- Filter BPF, daftar interface (`--list`), dan pesan error yang muncul di header
  tanpa bikin aplikasi panik.

### Lain-lain

- Ekspor snapshot CSV (`s`).
- Mode belajar (`--belajar`) untuk kelas TKJ.
- Binary `ntf` plus `install.sh`.
- 23 unit test, termasuk parser pcap dan routing jalur dinamis.

### Perbaikan

- `ntf any` gagal dibuka karena libpcap menolak promiscuous mode di device
  virtual. Sekarang promisc hanya dipakai di interface fisik.
- IP remote di panel SSH tidak lagi menampilkan IP lokal.

### Terima kasih

- **Panz-08** — ide, kode, dan tampilan.
- **Nakki-Kun** — dokumentasi, FAQ, dan pengecekan.
