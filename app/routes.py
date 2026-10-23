import hashlib
import io
import json
import os
import secrets
import time

from flask import (
    Blueprint, current_app, flash, redirect, render_template,
    request, send_file, session, url_for
)
from werkzeug.utils import secure_filename

from .crypto import (
    AES_KEY, DES_KEY, RC4_KEY,
    benchmark, decode_bytes, decrypt_aes, decrypt_des, decrypt_rc4,
    encrypt_all, serialize_personal_data, ALGORITHMS, IMAGE_FORMATS,
    pack_encrypted_file, encrypted_image, decrypt_export, unpack_encrypted_file
)
from .db import get_db

bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "webp",
    "pdf", "doc", "docx", "xls", "xlsx",
    "mp4", "avi", "mov", "mkv", "webm"
}

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 200_000
    )

def logged_in():
    return "user_id" in session

def current_user_id():
    return session.get("user_id")

def encrypted_root():
    path = current_app.config.get("ENCRYPTED_STORAGE") or os.path.join(
        current_app.root_path, "..", "storage", "encrypted"
    )
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)


def owned_file(file_id):
    db = get_db()
    try:
        return db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, current_user_id())
        ).fetchone()
    finally:
        db.close()


def decrypt_stored_file(item, algorithm):
    with open(item[f"{algorithm}_path"], "rb") as f:
        ciphertext = f.read()
    if algorithm == "aes":
        return decrypt_aes(ciphertext, item["aes_iv"])
    if algorithm == "des":
        return decrypt_des(ciphertext, item["des_iv"])
    return decrypt_rc4(ciphertext)


@bp.route("/files")
def files_page():
    if not logged_in():
        return redirect(url_for("main.login"))
    db = get_db()
    try:
        files = db.execute(
            "SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (current_user_id(),)
        ).fetchall()
    finally:
        db.close()
    keys = [
        {"id": "aes", "name": "AES-256-CBC", "hex": AES_KEY.hex(), "size": "32 byte / 256 bit"},
        {"id": "des", "name": "DES-CBC", "hex": DES_KEY.hex(), "size": "8 byte / 64 bit (56 bit efektif)"},
        {"id": "rc4", "name": "RC4", "hex": RC4_KEY.hex(), "size": "32 byte / 256 bit"},
    ]
    response = current_app.make_response(render_template("files.html", files=files, encryption_keys=keys))
    response.headers["Cache-Control"] = "no-store"
    return response

@bp.route("/")
def index():
    if not logged_in():
        return redirect(url_for("main.login"))
    return redirect(url_for("main.files_page"))

@bp.route("/dashboard")
def dashboard():
    return redirect(url_for("main.index"))

@bp.route("/personal", methods=["GET"])
def personal_page():
    if not logged_in():
        return redirect(url_for("main.login"))
    db = get_db()
    try:
        personal = db.execute("SELECT * FROM personal_data WHERE user_id = ? ORDER BY created_at DESC, id DESC", (current_user_id(),)).fetchall()
    finally:
        db.close()
    return render_template("personal.html", personal=personal)

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(password) < 8:
            flash("Username wajib diisi dan password minimal 8 karakter.")
            return redirect(url_for("main.register"))

        salt = secrets.token_bytes(16)
        password_hash = hash_password(password, salt)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)",
                (username, password_hash.hex(), salt.hex())
            )
            db.commit()
        except Exception:
            db.close()
            flash("Username sudah digunakan.")
            return redirect(url_for("main.register"))

        db.close()
        flash("Registrasi berhasil. Silakan login.")
        return redirect(url_for("main.login"))

    return render_template("register.html")

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        db.close()

        if user:
            salt = bytes.fromhex(user["password_salt"])
            expected = bytes.fromhex(user["password_hash"])
            actual = hash_password(password, salt)

            if secrets.compare_digest(actual, expected):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("main.index"))

        flash("Username atau password salah.")

    return render_template("login.html")

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))

@bp.route("/personal", methods=["POST"])
def save_personal():
    if not logged_in():
        return redirect(url_for("main.login"))

    data = {
        "full_name": request.form.get("full_name", ""),
        "birth_date": request.form.get("birth_date", ""),
        "phone": request.form.get("phone", ""),
        "address": request.form.get("address", ""),
        "email": request.form.get("email", ""),
    }

    encrypted = encrypt_all(serialize_personal_data(data))

    db = get_db()
    db.execute(
        """INSERT INTO personal_data
        (user_id, aes_data, des_data, rc4_data, aes_iv, des_iv)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (
            current_user_id(),
            encrypted["aes"],
            encrypted["des"],
            encrypted["rc4"],
            encrypted["aes_iv"],
            encrypted["des_iv"],
        )
    )
    db.commit()
    db.close()

    flash("Data pribadi berhasil disimpan menggunakan AES, DES, dan RC4.")
    return redirect(url_for("main.personal_page"))

@bp.route("/personal/<int:item_id>/<algorithm>")
def download_personal(item_id, algorithm):
    if not logged_in():
        return redirect(url_for("main.login"))

    if algorithm not in {"aes", "des", "rc4"}:
        return "Algorithm tidak valid", 400

    db = get_db()
    item = db.execute(
        "SELECT * FROM personal_data WHERE id = ? AND user_id = ?",
        (item_id, current_user_id())
    ).fetchone()
    db.close()

    if not item:
        return "Data tidak ditemukan", 404

    if algorithm == "aes":
        plaintext = decrypt_aes(item["aes_data"], item["aes_iv"])
    elif algorithm == "des":
        plaintext = decrypt_des(item["des_data"], item["des_iv"])
    else:
        plaintext = decrypt_rc4(item["rc4_data"])

    response = send_file(io.BytesIO(plaintext), as_attachment=True,
                         download_name=f"personal_data_{item_id}_{algorithm}.json",
                         mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@bp.route("/upload", methods=["POST"])
def upload():
    if not logged_in():
        return redirect(url_for("main.login"))

    uploaded = request.files.get("file")

    if not uploaded or not uploaded.filename:
        flash("Pilih file terlebih dahulu.")
        return redirect(url_for("main.index"))

    filename = secure_filename(uploaded.filename)
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if extension not in ALLOWED_EXTENSIONS:
        flash("Format file tidak didukung.")
        return redirect(url_for("main.index"))

    data = uploaded.read()
    if not data:
        flash("File kosong.")
        return redirect(url_for("main.index"))

    encrypted = encrypt_all(data)

    file_id = secrets.token_hex(16)
    directory = os.path.join(encrypted_root(), file_id)
    os.makedirs(directory, exist_ok=True)

    aes_path = os.path.join(directory, "aes.bin")
    des_path = os.path.join(directory, "des.bin")
    rc4_path = os.path.join(directory, "rc4.bin")

    with open(aes_path, "wb") as f:
        f.write(encrypted["aes"])
    with open(des_path, "wb") as f:
        f.write(encrypted["des"])
    with open(rc4_path, "wb") as f:
        f.write(encrypted["rc4"])

    metadata = {
        "original_name": filename,
        "mime_type": uploaded.mimetype,
        "original_size": len(data),
        "aes_iv": encrypted["aes_iv"].hex(),
        "des_iv": encrypted["des_iv"].hex(),
    }

    with open(os.path.join(directory, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f)

    db = get_db()
    db.execute(
        """INSERT INTO files
        (user_id, original_name, mime_type, aes_path, des_path, rc4_path,
         aes_iv, des_iv, original_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            current_user_id(),
            filename,
            uploaded.mimetype,
            aes_path,
            des_path,
            rc4_path,
            encrypted["aes_iv"],
            encrypted["des_iv"],
            len(data),
        )
    )
    db.commit()
    db.close()

    flash("File berhasil dienkripsi dengan AES, DES, dan RC4.")
    return redirect(url_for("main.files_page"))

@bp.route("/file/<int:file_id>/<algorithm>")
@bp.route("/file/<int:file_id>/<algorithm>/decrypt")
def download_file(file_id, algorithm):
    if not logged_in():
        return redirect(url_for("main.login"))

    if algorithm not in {"aes", "des", "rc4"}:
        return "Algorithm tidak valid", 400

    item = owned_file(file_id)

    if not item:
        return "File tidak ditemukan", 404

    try:
        plaintext = decrypt_stored_file(item, algorithm)
    except (OSError, ValueError):
        return "File terenkripsi tidak dapat dibaca atau didekripsi.", 400
    filename = secure_filename(item["original_name"]) or "decrypted_file"
    extension = filename.rsplit(".", 1)[-1].lower()
    inline = request.args.get("inline") == "1" and extension in IMAGE_FORMATS
    response = send_file(
        io.BytesIO(plaintext), as_attachment=not inline,
        download_name=filename,
        mimetype=image_mime(extension) if inline else (item["mime_type"] or "application/octet-stream")
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def image_mime(extension):
    return {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}[extension]


@bp.route("/file/<int:file_id>/<algorithm>/encrypted")
def download_encrypted_file(file_id, algorithm):
    if not logged_in():
        return redirect(url_for("main.login"))
    if algorithm not in ALGORITHMS:
        return "Algorithm tidak valid", 400
    item = owned_file(file_id)
    if not item:
        return "File tidak ditemukan", 404
    output_format = request.args.get("format", "image")
    if output_format not in {"image", "enc", "bin"}:
        return "Format keluaran tidak valid", 400
    try:
        with open(item[f"{algorithm}_path"], "rb") as f:
            ciphertext = f.read()
        name = secure_filename(item["original_name"]) or "file"
        extension = name.rsplit(".", 1)[-1].lower()
        iv = item[f"{algorithm}_iv"] if algorithm in {"aes", "des"} else b""
        package = pack_encrypted_file(ciphertext, algorithm, name, item["mime_type"], iv)
        is_image = output_format == "image" and extension in IMAGE_FORMATS
        if is_image:
            original = decrypt_stored_file(item, algorithm)
            result = encrypted_image(ciphertext, original, extension, package)
            download_name = f"encrypted_{algorithm}_{name}"
            mimetype = image_mime(extension)
        elif output_format == "bin":
            result, download_name, mimetype = ciphertext, f"{name}.{algorithm}.bin", "application/octet-stream"
        else:
            result, download_name, mimetype = package, f"{name}.{algorithm}.enc", "application/octet-stream"
    except (OSError, ValueError):
        return "File tidak dapat diekspor. Untuk gambar yang tidak valid, pilih format .enc.", 400
    response = send_file(
        io.BytesIO(result), download_name=download_name, mimetype=mimetype,
        as_attachment=not (is_image and request.args.get("inline") == "1")
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    if not logged_in():
        return redirect(url_for("main.login"))
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Pilih file terenkripsi terlebih dahulu.")
            return redirect(url_for("main.decrypt_page"))
        try:
            exported = uploaded.read()
            package = unpack_encrypted_file(exported)
            algorithm = package["algorithm"]
            db = get_db()
            try:
                candidates = db.execute("SELECT * FROM files WHERE user_id = ?", (current_user_id(),)).fetchall()
            finally:
                db.close()
            owned = False
            for item in candidates:
                iv = item[f"{algorithm}_iv"] if algorithm in {"aes", "des"} else b""
                if iv != package["iv"]:
                    continue
                try:
                    with open(item[f"{algorithm}_path"], "rb") as source:
                        if secrets.compare_digest(source.read(), package["ciphertext"]):
                            owned = True
                            break
                except OSError:
                    continue
            if not owned:
                return "Berkas ini bukan milik akun Anda atau tidak lagi tersimpan.", 403
            plaintext, original_name, mimetype = decrypt_export(exported)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("main.decrypt_page"))
        response = send_file(
            io.BytesIO(plaintext), as_attachment=True,
            download_name=secure_filename(original_name) or "decrypted_file",
            mimetype=mimetype
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    return render_template("decrypt.html")

@bp.route("/benchmark", methods=["GET", "POST"])
def benchmark_page():
    if not logged_in():
        return redirect(url_for("main.login"))

    results = None
    size = None
    repeats = 20

    if request.method == "POST":
        uploaded = request.files.get("file")
        try:
            repeats = max(1, min(1000, int(request.form.get("repeats", "20"))))
        except ValueError:
            repeats = 20

        if uploaded and uploaded.filename:
            data = uploaded.read()
            if data:
                size = len(data)
                results = benchmark(data, repeats)

    return render_template(
        "benchmark.html",
        results=results,
        size=size,
        repeats=repeats
    )
