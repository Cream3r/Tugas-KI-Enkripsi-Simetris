"""Reproducible in-memory measurements of the application's actual ciphers."""
import hashlib
import math
import platform
import random
import statistics
import time
from importlib.metadata import version

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import unpad
from .crypto import (
    AES_KEY, DES_KEY, RC4_KEY, encrypt_aes, encrypt_des, encrypt_rc4,
    decrypt_aes, decrypt_des, decrypt_rc4, pack_encrypted_file, decrypt_export,
)

CIPHERS = {
    "AES": (lambda data: encrypt_aes(data), decrypt_aes),
    "DES": (lambda data: encrypt_des(data), decrypt_des),
    "RC4": (lambda data: (encrypt_rc4(data), b""), lambda data, iv: decrypt_rc4(data)),
}
MAX_INPUT = 16 * 1024 * 1024
MAX_WORK = 256 * 1024 * 1024


def timing_stats(values, size):
    ordered = sorted(values)
    median = statistics.median(values)
    mean = statistics.mean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "median_ms": median, "mean_ms": mean, "stdev_ms": stdev,
        "p95_ms": ordered[math.ceil(.95 * len(ordered)) - 1],
        "min_ms": min(values), "max_ms": max(values),
        "cv_percent": 100 * stdev / mean if mean else 0.0,
        "throughput_mib_s": (size / (1024 * 1024)) / (median / 1000) if median else 0.0,
    }


def wrong_key_check(name, ciphertext, iv, original):
    # A wrong key need not raise an error: RC4 has no padding or authentication.
    key = bytearray({"AES": AES_KEY, "DES": DES_KEY, "RC4": RC4_KEY}[name])
    key[0] ^= 0x80  # Change an effective DES key bit, not only a parity bit.
    try:
        if name == "RC4":
            recovered = ARC4.new(bytes(key)).decrypt(ciphertext)
        else:
            cipher = AES if name == "AES" else DES
            recovered = unpad(cipher.new(bytes(key), cipher.MODE_CBC, iv).decrypt(ciphertext), cipher.block_size)
        return {"rejected": False, "equals_original": recovered == original}
    except ValueError:
        return {"rejected": True, "equals_original": False}


def evaluate(data, filename, repeats, seed=2026, mime_type="application/octet-stream"):
    if not data or len(data) > MAX_INPUT:
        raise ValueError("Isi pengujian harus 1 byte hingga 16 MiB.")
    if not 5 <= repeats <= 100:
        raise ValueError("Pengulangan harus antara 5 dan 100.")
    if len(data) * (repeats + 2) > MAX_WORK:
        raise ValueError("Beban terlalu besar. Kurangi ukuran file atau pengulangan (maksimal 256 MiB per cipher termasuk pemanasan).")
    raw = {name: {"encrypt": [], "decrypt": [], "correct": 0} for name in CIPHERS}
    digest = hashlib.sha256(data).hexdigest()
    rng = random.Random(seed)
    for _ in range(2):
        for encrypt, decrypt in CIPHERS.values():
            ciphertext, iv = encrypt(data)
            if decrypt(ciphertext, iv) != data:
                raise ValueError("Pemulihan gagal saat pemanasan.")
    started = time.perf_counter()
    # Randomized order per repetition mitigates fixed-order effects; seed is reported.
    for _ in range(repeats):
        order = list(CIPHERS)
        rng.shuffle(order)
        for name in order:
            encrypt, decrypt = CIPHERS[name]
            start = time.perf_counter_ns()
            ciphertext, iv = encrypt(data)
            middle = time.perf_counter_ns()
            restored = decrypt(ciphertext, iv)
            stop = time.perf_counter_ns()
            raw[name]["encrypt"].append((middle - start) / 1_000_000)
            raw[name]["decrypt"].append((stop - middle) / 1_000_000)
            if restored == data and hashlib.sha256(restored).hexdigest() == digest:
                raw[name]["correct"] += 1
        if time.perf_counter() - started > 20:
            raise ValueError("Pengujian melebihi 20 detik. Kurangi ukuran atau pengulangan; hasil parsial tidak disajikan.")
    rows = []
    for name, (encrypt, decrypt) in CIPHERS.items():
        ciphertext, iv = encrypt(data)
        repeated_ciphertext, repeated_iv = encrypt(data)
        package = pack_encrypted_file(ciphertext, name.lower(), filename, mime_type, iv)
        damaged_package = bytearray(package)
        damaged_package[-1] ^= 1
        try:
            decrypt_export(bytes(damaged_package))
            package_rejected = False
        except ValueError:
            package_rejected = True
        damaged_raw = bytearray(ciphertext)
        damaged_raw[0] ^= 1
        try:
            changed_plaintext = decrypt(bytes(damaged_raw), iv)
            raw_rejected = False
            raw_equal = changed_plaintext == data
        except ValueError:
            raw_rejected, raw_equal = True, False
        enc = timing_stats(raw[name]["encrypt"], len(data))
        dec = timing_stats(raw[name]["decrypt"], len(data))
        rows.append({
            "name": name, "mode": "stream cipher" if name == "RC4" else "CBC + PKCS#7",
            "encrypt": enc, "decrypt": dec,
            "ciphertext_bytes": len(ciphertext), "iv_bytes": len(iv),
            "raw_overhead_bytes": len(ciphertext) - len(data),
            "raw_overhead_percent": 100 * (len(ciphertext) - len(data)) / len(data),
            "package_bytes": len(package), "package_overhead_bytes": len(package) - len(data),
            "package_overhead_percent": 100 * (len(package) - len(data)) / len(data),
            "correct_count": raw[name]["correct"], "original_sha256": digest,
            "restored_sha256": hashlib.sha256(decrypt(ciphertext, iv)).hexdigest(),
            "same_ciphertext": ciphertext == repeated_ciphertext,
            "same_iv": iv == repeated_iv, "package_tamper_rejected": package_rejected,
            "raw_tamper_rejected": raw_rejected, "raw_tamper_equals_original": raw_equal,
            "wrong_key": wrong_key_check(name, ciphertext, iv, data),
            "samples_encrypt_ms": raw[name]["encrypt"], "samples_decrypt_ms": raw[name]["decrypt"],
        })
    fastest = min(rows, key=lambda row: row["encrypt"]["median_ms"])
    slowest = max(rows, key=lambda row: row["encrypt"]["median_ms"])
    spread = slowest["encrypt"]["median_ms"] - fastest["encrypt"]["median_ms"]
    interpretation = [
        f"Pada input ini, {fastest['name']} memiliki median enkripsi terendah. Selisih median terhadap yang tertinggi adalah {spread:.4f} ms. Ini hasil perangkat dan beban uji ini, bukan peringkat universal.",
        "Untuk CV dan profil kecil, selisih milidetik mungkin tidak terasa. Untuk video besar, perhatikan throughput dan uji ulang pada ukuran video yang mewakili penggunaan nyata.",
        "Throughput dihitung dari ukuran plaintext dibagi median waktu. Waktu mencakup pembuatan objek cipher, IV acak dan padding saat enkripsi, serta unpadding saat dekripsi. Upload, disk, database, rendering, dan verifikasi hash tidak masuk waktu cipher.",
        "Ciphertext mentah AES/DES bertambah karena padding; RC4 tidak memakai padding. Paket .enc juga memuat IV, metadata, Base64, dan HMAC, sehingga tambahan ukurannya bukan overhead cipher saja.",
        "Keutuhan dinilai lewat kesamaan byte dan SHA-256 pada setiap pengulangan. Ini membuktikan pemulihan pada input uji, bukan ketahanan terhadap semua serangan.",
        "CBC dan RC4 mentah tidak mengautentikasi data. Penolakan perubahan paket .enc berasal dari HMAC. Error padding sesekali pada ciphertext mentah bukan jaminan integritas.",
        "AES/DES seharusnya menghasilkan ciphertext berbeda ketika IV acak berubah. RC4 dengan kunci tetap mengulang keystream; enkripsi input sama menjadi sama. Ini kelemahan desain RC4 saat ini.",
        "DES dan RC4 hanya untuk pembanding akademik. Kunci tetap yang terlihat dan dipakai bersama antar akun membatasi kerahasiaan; lolos uji otorisasi endpoint tidak membuktikan isolasi kriptografis antar pengguna.",
    ]
    correct = sum(row["correct_count"] for row in rows)
    interpretation.insert(1, f"Pemulihan byte dan hash cocok pada {correct} dari {3 * repeats} operasi terukur. " +
                          ("Seluruh operasi uji berhasil memulihkan input." if correct == 3 * repeats else "Ada kegagalan pemulihan; perbaiki sebelum menilai performa."))
    min_package = min(rows, key=lambda row: row["package_bytes"])
    interpretation.insert(4, f"Paket .enc terkecil pada input ini adalah {min_package['name']}: {min_package['package_bytes']} byte, bertambah {min_package['package_overhead_percent']:.2f}% dari plaintext. Selisih ini terutama perlu dinilai pada profil kecil; bukan ukuran keamanan cipher.")
    if any(row["encrypt"]["cv_percent"] > 10 or row["decrypt"]["cv_percent"] > 10 for row in rows):
        interpretation.append("Ada variasi waktu CV > 10% pada pengujian ini (ambang heuristik). Tutup beban latar, ulangi beberapa sesi, dan jangan menarik kesimpulan kuat dari selisih kecil.")
    return {
        "filename": filename, "mime_type": mime_type, "size": len(data), "repeats": repeats, "warmups": 2, "seed": seed,
        "elapsed_seconds": time.perf_counter() - started, "rows": rows, "interpretation": interpretation,
        "environment": {"python": platform.python_version(), "pycryptodome": version("pycryptodome"),
                        "system": platform.system(), "machine": platform.machine(),
                        "processor": platform.processor() or "Tidak dilaporkan", "timer": "time.perf_counter_ns"},
    }


def audit_authorization(project_root):
    """Exercise actual production endpoints against an isolated fixture database."""
    import io
    import tempfile
    from pathlib import Path
    from flask import Flask
    from .db import init_db, get_db
    from .routes import bp

    root = Path(project_root)
    scratch = root / "work"
    scratch.mkdir(exist_ok=True)
    checks = []
    def check(label, response, expected):
        checks.append({"label": label, "passed": response.status_code == expected,
                       "expected": expected, "actual": response.status_code})
    with tempfile.TemporaryDirectory(prefix="evaluation-", dir=scratch) as directory:
        fixture = Flask("authorization_audit", root_path=str(root / "app"))
        fixture.config.update(TESTING=True, SECRET_KEY="isolated-test-only",
                              DATABASE=str(Path(directory) / "fixture.db"),
                              ENCRYPTED_STORAGE=str(Path(directory) / "encrypted"))
        fixture.register_blueprint(bp)
        with fixture.app_context():
            init_db()
            db = get_db()
            for username in ("fixture-owner", "fixture-other"):
                db.execute("INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)",
                           (username, "unused-test-hash", "unused-test-salt"))
            db.commit()
            db.close()
        owner, other, anonymous = fixture.test_client(), fixture.test_client(), fixture.test_client()
        for client, user_id in ((owner, 1), (other, 2)):
            with client.session_transaction() as state:
                state["user_id"] = user_id
                state["username"] = "fixture-owner" if user_id == 1 else "fixture-other"
        content = b"Synthetic applicant document for access-control audit."
        owner.post("/upload", data={"file": (io.BytesIO(content), "fixture.pdf")})
        owner.post("/personal", data={"full_name": "Synthetic applicant"})
        for name in CIPHERS:
            algorithm = name.lower()
            path = f"/file/1/{algorithm}"
            restored = owner.get(path)
            checks.append({"label": f"{name}: pemilik memulihkan file utuh", "passed": restored.status_code == 200 and restored.data == content,
                           "expected": "200 + byte identik", "actual": restored.status_code})
            check(f"{name}: tanpa login ditolak/diarahkan ke login", anonymous.get(path), 302)
            check(f"{name}: akun lain tidak dapat mengambil file", other.get(path), 404)
            check(f"{name}: akun lain tidak dapat mengekspor", other.get(path + "/encrypted?format=enc"), 404)
            package = owner.get(path + "/encrypted?format=enc")
            check(f"{name}: impor paket oleh akun lain ditolak", other.post("/decrypt", data={"file": (io.BytesIO(package.data), "fixture.enc")}), 403)
            check(f"{name}: profil akun lain ditolak", other.get(f"/personal/1/{algorithm}"), 404)
            check(f"{name}: profil tanpa login ditolak", anonymous.get(f"/personal/1/{algorithm}"), 302)
        check("Algoritma tidak dikenal ditolak", owner.get("/file/1/invalid"), 400)
    return checks
