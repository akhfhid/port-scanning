# Ultra Port Scanner (Julia)

Port scanner multithreaded ditulis dengan Julia — memindai port TCP pada target host, opsi banner grabbing, dan kemampuan menjalankan perintah shell ketika port terbuka.

> **Catatan penting:** gunakan alat ini hanya pada target yang kamu miliki izin eksplisit untuk memindai. Port scanning tanpa izin dapat dianggap tindakan intrusi dan melanggar hukum atau kebijakan jaringan.

---

## Fitur

* Mendukung pemindaian port tunggal, daftar port (dipisah koma), rentang (`1000-2000`) atau `all` (1–65535).
* Multithreaded (sesuaikan `--threads`).
* Opsi banner grab (`--grab`) untuk membaca data awal dari service.
* Opsi menjalankan perintah shell saat port terbuka (`--action`), dengan placeholder `{host}` dan `{port}`.
* Output berupa JSON (satu baris) cocok untuk pemrosesan lebih lanjut.

---

## Prasyarat

* Julia 1.x (disarankan versi terbaru stable)
* Paket Julia:

  * `ArgParse`
  * `JSON3`

Instal paket yang diperlukan (dijalankan di REPL Julia):

```julia
using Pkg
Pkg.add("ArgParse")
Pkg.add("JSON3")
```

---

## Cara menjalankan

Pastikan file script (mis. `check_port_ultra.jl`) dapat dieksekusi atau jalankan lewat `julia`:

```bash
# Menjalankan langsung jika executable
./check_port_ultra.jl <host> "<ports>" [opsi]

# Atau lewat julia
julia check_port_ultra.jl <host> "<ports>" [opsi]
```

### Argumen & opsi

* `host` — hostname atau alamat IP target (positional, wajib).
* `ports` — port tunggal, daftar dipisah koma, rentang (`1000-2000`), atau `all`.

Opsi:

* `--timeout`, `-t` — timeout koneksi (detik). Default: `2.0`.
* `--threads`, `-T` — jumlah thread worker. Default: `200`.
* `--grab`, `-g` — flag untuk melakukan banner grab (mencoba membaca data dari service setelah connect).
* `--action`, `-a` — template perintah shell untuk dijalankan bila port terbuka. Gunakan placeholder `{host}` dan `{port}`.

### Contoh

Scan port 22 dan 80:

```bash
julia check_port_ultra.jl example.com "22,80"
```

Scan rentang 1–1024 dengan 100 thread dan timeout 1 detik:

```bash
julia check_port_ultra.jl 192.168.1.1 "1-1024" -T 100 -t 1.0
```

Scan semua port (HATI-HATI):

```bash
julia check_port_ultra.jl 10.0.0.5 all -T 500
```

Scan dan ambil banner lalu jalankan action ketika port terbuka:

```bash
julia check_port_ultra.jl host.com "22,80" -g -a "echo Port {port} terbuka di {host}"
```

---

## Format output

Script mengeluarkan satu baris JSON yang merupakan array objek. Contoh (disederhanakan):

```json
[
  {"port":22,"status":"open","banner":"SSH-2.0-OpenSSH_8.2p1...","action_output":""},
  {"port":23,"status":"closed","banner":null,"action_output":null}
]
```

Field:

* `port` — port yang dipindai (integer).
* `status` — `open` atau `closed`.
* `banner` — string hasil banner grab atau `null` jika tidak ada / tidak diminta.
* `action_output` — output dari perintah shell jika `--action` dipakai, atau `null`.

---

## Keterbatasan & catatan teknis

* **Permissions & legal:** pastikan kamu punya izin untuk memindai target.
* **Resource:** default `--threads=200` bisa tinggi untuk sistem tertentu — sesuaikan berdasarkan CPU/IO dan limit file descriptor.
* **Timeout & banner grab:** banner grab saat ini menunggu sampai sejumlah byte atau loop berulang; bisa jadi butuh perbaikan timeout baca untuk menghindari hanging.
* **Keamanan:** opsi `--action` mengeksekusi perintah shell. Jangan menjalankan action yang tidak tepercaya karena berisiko injection/eksekusi berbahaya.
* **Silent errors:** beberapa `catch` di script menangkap error tanpa logging — ini memudahkan pemindaian tapi menyulitkan debugging.

---

## Saran perbaikan (opsional)

* Ganti mekanisme queue `ports` dengan `Channel` untuk performa dan penanganan concurrency yang lebih baik.
* Validasi input port agar berada dalam rentang `1..65535`.
* Tambahkan timeout baca untuk `banner_grab` dan/atau batas waktu total per port.
* Tambahkan mode verbose / logging untuk debugging.
* Sanitasi input untuk `--action` atau hindari eksekusi shell langsung.

---

## Kontribusi

PR dan issue dipersilakan. Untuk perubahan besar, buatkan issue terlebih dahulu agar kita dapat berdiskusi.

---

## Lisensi

Lisensi default: MIT (ubah sesuai kebutuhan).

---

## LICENSE (MIT)

```
MIT License

Copyright (c) YEAR AUTHOR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Ganti `YEAR` dan `AUTHOR` sesuai repo-mu (mis. `2025 Affan Khulafa`).

---

## Contoh direktori & file tambahan

Berikut contoh file yang mungkin berguna saat mengunggah ke GitHub.

### 1) `examples/run_scan.sh`

Skrip shell sederhana untuk menjalankan scanner (executable `check_port_ultra.jl` harus ada di folder yang sama):

```bash
#!/usr/bin/env bash
# contoh: ./run_scan.sh example.com "22,80" -T 50 -t 1.5 -g -a "echo Port {port} di {host}"
TARGET="$1"
PORTS="$2"
shift 2

if [[ -z "$TARGET" || -z "$PORTS" ]]; then
  echo "Usage: $0 <target> \"<ports>\" [extra args]"
  exit 1
fi

julia check_port_ultra.jl "$TARGET" "$PORTS" "$@"
```

Jangan lupa `chmod +x examples/run_scan.sh`.

---

### 2) `examples/action_example.sh`

Contoh action yang bisa dipanggil lewat `--action` (misal untuk catatan/log ketika port terbuka):

```bash
#!/usr/bin/env bash
HOST="$1"
PORT="$2"
TIMESTAMP=$(date --iso-8601=seconds)
LOGFILE="open_ports.log"

echo "[$TIMESTAMP] Open port $PORT on $HOST" >> "$LOGFILE"
```

Contoh pemanggilan via scanner:

```bash
julia check_port_ultra.jl 192.168.1.10 "22,80" -g -a "examples/action_example.sh {host} {port}"
```

> Catatan: `--action` menjalankan perintah melalui `/bin/sh -c`, sehingga jika action script berada di file, sertakan path relatif atau absolut. Pastikan script executable.

---

### 3) `.gitignore` rekomendasi

Tambahkan file log dan file temporer agar tidak ter-commit:

```
*.log
*.tmp
.env
```

---

### 4) `CONTRIBUTING.md` (singkat)

Tambahkan file `CONTRIBUTING.md` kecil yang berisi panduan singkat kontribusi:

```
1. Fork repo.
2. Buat branch fitur/bugfix: git checkout -b feat/namafitur
3. Commit perubahan, push ke fork.
4. Buat Pull Request dan jelaskan perubahan.
```

---