# Berkas Kandidat

## Skenario nyata
Pengguna adalah pelamar kerja yang mempersiapkan beberapa lamaran dan membutuhkan ruang pribadi untuk menyimpan salinan berkas. Mereka menyimpan identitas/kontak pada formulir, pindaian KTP, CV atau surat lamaran (PDF/DOC/DOCX), daftar pengalaman/portofolio (XLS/XLSX), dan video perkenalan. Kebocoran dapat memicu pencurian identitas, penyalahgunaan nomor kontak, dan pengungkapan riwayat kerja. Aplikasi ini bukan portal rekrutmen publik: tidak ada fitur HR untuk melihat berkas pengguna lain.

## Klasifikasi privasi dan dasar aturan
Rujukan: UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi, Pasal 1 (definisi), Pasal 4 (jenis), Pasal 16 (prinsip pemrosesan), dan Pasal 35–39 (pengamanan/kerahasiaan/pencegahan akses tidak sah).
Sumber resmi: https://jdih.komdigi.go.id/produk_hukum/view/id/832/t/crc32/

| Data | Keputusan aplikasi dan alasan |
| --- | --- |
| Nama, tanggal lahir, alamat, email, telepon | Privat karena dapat mengidentifikasi atau menghubungi pelamar, sendiri atau dalam kombinasi. |
| Pindaian KTP | Seluruh isi privat; berisi nomor identitas dan gabungan atribut identitas, foto, dan informasi lain. |
| CV, surat lamaran, spreadsheet | Seluruh isi privat karena memuat kontak, pendidikan, dan riwayat kerja. Informasi keuangan pribadi jika ada termasuk data spesifik. |
| Video perkenalan | Seluruh isi privat karena wajah, suara, dan narasi dapat mengidentifikasi pengguna. Karakteristik yang memungkinkan identifikasi unik perlu diperhatikan sebagai data biometrik menurut penjelasan Pasal 4. |

Keputusan desain ini bukan pernyataan bahwa implementasi sudah memenuhi seluruh kewajiban UU PDP. Pengguna sebaiknya memasukkan data simulasi dan hanya informasi yang diperlukan untuk tujuan lamaran.

## Alur sederhana
1. Daftar dan masuk.
2. Buka Berkas untuk mengunggah identitas, dokumen kantor, atau video.
3. Buka Data pribadi untuk menyimpan profil.
4. Setiap isi profil/file disimpan dalam tiga ciphertext terpisah: AES-256-CBC, DES-CBC, dan RC4.
5. Unduh file asli melalui algoritma pilihan atau unduh paket .enc. Halaman Dekripsi hanya menerima paket yang cocok dengan ciphertext milik akun yang sedang masuk dan masih tersimpan. Gambar terenkripsi utuh juga dapat dipulihkan.
6. Benchmark membandingkan ketiga cipher. Alamat /dashboard lama mengarah ke halaman Berkas; template dashboard lama dihapus.

Password menggunakan hash PBKDF2-HMAC-SHA256 dengan salt, bukan enkripsi yang dapat dibalik. Endpoint data dan file memeriksa sesi serta kepemilikan. Unduhan profil JSON kini dikirim dari memori, tanpa menulis plaintext baru ke instance/.

## Verifikasi
Pengujian integrasi di work/verify.py menggunakan database dan penyimpanan sementara di dalam folder proyek. Mencakup registrasi/login, semua halaman, pengalihan dashboard, profil pada ketiga cipher, lima ekstensi file, kesamaan byte hasil dekripsi, ekspor/impor .enc, penolakan pengguna lain termasuk impor paket pengguna lain, benchmark, dan paket rusak. Dokumen/video uji berisi payload byte sintetis untuk memeriksa pemulihan byte; bukan validasi pemutaran video atau pembukaan Office.

## Batas proyek akademik
DES dan RC4 tidak cocok untuk melindungi data nyata. Kunci cipher dan fallback secret masih mengikuti desain tugas lama dan perlu pengelolaan kunci produksi. Isi file/profil dienkripsi, tetapi metadata operasional seperti nama file, ukuran, waktu, dan username belum dienkripsi di database. Salinan plaintext lama yang sudah ada di instance/ tidak dihapus otomatis agar tidak menghilangkan data pengguna. Implementasi ini belum berarti seluruh data-at-rest dan seluruh kewajiban UU PDP terpenuhi.

Lingkungan .venv yang ada menunjuk instalasi Python 3.13 yang tidak dapat dijalankan pada sesi ini. Pengujian dijalankan dengan runtime Python bundel dan dependensi yang tersedia; untuk menjalankan sendiri, buat lingkungan Python yang aktif lalu instal requirements.txt (termasuk Pillow yang digunakan untuk gambar).

---

# Berkas Kandidat - Assignment 1

Web application untuk menyimpan data pribadi dan file secara terenkripsi dengan:
- AES-256-CBC
- DES-CBC
- RC4 (ARC4)

## Fitur
- Register dan login username/password
- Password disimpan sebagai PBKDF2-HMAC-SHA256 hash + salt
- Menyimpan data pribadi ke SQLite
- Upload ID card image
- Upload PDF/DOC/DOCX/XLS/XLSX
- Upload video
- Setiap data/file dibuatkan 3 ciphertext: AES, DES, dan RC4
- Download/decrypt file
- Download/decrypt data pribadi
- Benchmark waktu encryption/decryption dan ukuran ciphertext

> Catatan keamanan akademik: DES dan RC4 sudah dianggap tidak aman untuk sistem nyata. Keduanya digunakan di project ini karena diwajibkan assignment.

## 1. Install

Disarankan Python 3.11+.

```bash
python -m venv .venv
```

Windows:
```bash
.venv\Scripts\activate
```

Linux/macOS:
```bash
source .venv/bin/activate
```

Install:
```bash
pip install -r requirements.txt
```

## 2. Jalankan

```bash
python run.py
```

Buka:
http://127.0.0.1:5000

## 3. Struktur

```text
crypto_web_app/
├── app/
│   ├── __init__.py
│   ├── crypto.py
│   ├── db.py
│   ├── routes.py
│   ├── templates/
│   └── static/
├── benchmarks/
├── storage/
│   ├── encrypted/
│   └── uploads/
├── requirements.txt
└── run.py
```

## 4. Format storage

Untuk sebuah file bernama `example.pdf`, server menyimpan:

```text
storage/encrypted/<file_id>/
├── aes.bin
├── des.bin
├── rc4.bin
└── metadata.json
```

Metadata menyimpan IV AES/DES dan informasi yang diperlukan untuk dekripsi.

## 5. Benchmark

Benchmark dapat dijalankan dari halaman `/benchmark`.

Untuk eksperimen laporan:
- gunakan file yang sama
- ulangi upload/benchmark beberapa kali
- gunakan ukuran file yang berbeda
- catat encryption time
- catat decryption time
- catat ciphertext size

Jangan membandingkan hanya satu file kecil karena overhead IV/metadata dapat mendominasi hasil.

## 6. Catatan desain

### AES
AES-256-CBC digunakan dengan IV random 16 byte.

### DES
DES-CBC digunakan dengan IV random 8 byte.

### RC4
ARC4/RC4 adalah stream cipher sehingga tidak membutuhkan IV untuk implementasi ini.

### Password
Password tidak disimpan menggunakan AES/DES/RC4. Password disimpan sebagai PBKDF2-HMAC-SHA256 hash karena password hashing berbeda dari encryption.

## 7. Untuk laporan

Bahas:
1. Mengapa menggunakan Flask.
2. Mengapa password tidak disimpan plaintext.
3. Mengapa AES/DES menggunakan CBC.
4. Perbedaan block cipher vs stream cipher.
5. Perbandingan running time.
6. Perbandingan ciphertext size.
7. Mengapa ciphertext berbeda walaupun plaintext sama.
8. Kelemahan DES dan RC4 pada sistem nyata.

## Transparansi kunci demo
Halaman Berkas menampilkan kunci AES, DES, dan RC4 yang benar-benar dipakai oleh modul crypto.py, dalam HEX beserta panjangnya. Tombol Salin menyalin nilai HEX; jika clipboard browser tidak tersedia, kolom dipilih untuk disalin manual. Halaman membutuhkan login dan dikirim dengan Cache-Control: no-store.
Kunci pada implementasi ini bersifat tetap dan dipakai bersama semua akun. Pembatasan kepemilikan berlaku di endpoint aplikasi, tetapi pengetahuan kunci memungkinkan dekripsi ciphertext yang diperoleh di luar aplikasi. Fitur ini ditujukan untuk demonstrasi tugas dengan data simulasi, bukan isolasi kriptografis per akun.
