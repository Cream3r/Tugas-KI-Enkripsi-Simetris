import hashlib
import io
import json
import os
import secrets
import shutil
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
        personal_item = personal[0] if personal else None
        decrypted_profile = None
        if personal_item:
            try:
                raw_json = decrypt_aes(personal_item["aes_data"], personal_item["aes_iv"])
                decrypted_profile = json.loads(raw_json.decode("utf-8"))
            except Exception:
                decrypted_profile = {}
        edit_mode = request.args.get("edit") == "1" and personal_item is not None
    finally:
        db.close()
    return render_template(
        "personal.html",
        personal=personal,
        personal_item=personal_item,
        decrypted_profile=decrypted_profile,
        edit_mode=edit_mode
    )

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

    db = get_db()
    try:
        existing = db.execute(
            "SELECT id FROM personal_data WHERE user_id = ?",
            (current_user_id(),)
        ).fetchone()
        if existing:
            flash("Anda sudah memiliki 1 entri data pribadi aktif. Silakan edit atau hapus data tersebut jika ingin mengubah.")
            return redirect(url_for("main.personal_page"))

        data = {
            "full_name": request.form.get("full_name", "").strip(),
            "birth_date": request.form.get("birth_date", "").strip(),
            "phone": request.form.get("phone", "").strip(),
            "address": request.form.get("address", "").strip(),
            "email": request.form.get("email", "").strip(),
        }

        encrypted = encrypt_all(serialize_personal_data(data))

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
    finally:
        db.close()

    flash("Data pribadi berhasil disimpan menggunakan AES, DES, dan RC4.")
    return redirect(url_for("main.personal_page"))

@bp.route("/personal/<int:item_id>/edit", methods=["GET", "POST"])
@bp.route("/personal/<int:item_id>/update", methods=["POST"])
def edit_personal(item_id):
    if not logged_in():
        return redirect(url_for("main.login"))

    db = get_db()
    try:
        item = db.execute(
            "SELECT * FROM personal_data WHERE id = ? AND user_id = ?",
            (item_id, current_user_id())
        ).fetchone()

        if not item:
            flash("Data pribadi tidak ditemukan atau bukan milik akun Anda.")
            return redirect(url_for("main.personal_page"))

        if request.method == "POST":
            data = {
                "full_name": request.form.get("full_name", "").strip(),
                "birth_date": request.form.get("birth_date", "").strip(),
                "phone": request.form.get("phone", "").strip(),
                "address": request.form.get("address", "").strip(),
                "email": request.form.get("email", "").strip(),
            }

            encrypted = encrypt_all(serialize_personal_data(data))

            db.execute(
                """UPDATE personal_data
                SET aes_data = ?, des_data = ?, rc4_data = ?,
                    aes_iv = ?, des_iv = ?, created_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?""",
                (
                    encrypted["aes"],
                    encrypted["des"],
                    encrypted["rc4"],
                    encrypted["aes_iv"],
                    encrypted["des_iv"],
                    item_id,
                    current_user_id(),
                )
            )
            db.commit()
            flash("Data pribadi berhasil diperbarui dan dienkripsi ulang dengan AES, DES, dan RC4.")
            return redirect(url_for("main.personal_page"))

        try:
            raw_json = decrypt_aes(item["aes_data"], item["aes_iv"])
            decrypted_profile = json.loads(raw_json.decode("utf-8"))
        except Exception:
            decrypted_profile = {}

        return render_template(
            "personal.html",
            personal=[item],
            personal_item=item,
            decrypted_profile=decrypted_profile,
            edit_mode=True
        )
    finally:
        db.close()

@bp.route("/personal/<int:item_id>/delete", methods=["POST"])
def delete_personal(item_id):
    if not logged_in():
        return redirect(url_for("main.login"))

    db = get_db()
    try:
        item = db.execute(
            "SELECT * FROM personal_data WHERE id = ? AND user_id = ?",
            (item_id, current_user_id())
        ).fetchone()

        if not item:
            return "Data pribadi tidak ditemukan", 404

        db.execute(
            "DELETE FROM personal_data WHERE id = ? AND user_id = ?",
            (item_id, current_user_id())
        )
        db.commit()
    finally:
        db.close()

    flash("Data pribadi berhasil dihapus secara permanen dari server.")
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


@bp.route("/file/<int:file_id>/delete", methods=["POST"])
def delete_file(file_id):
    if not logged_in():
        return redirect(url_for("main.login"))

    item = owned_file(file_id)
    if not item:
        return "File tidak ditemukan", 404

    root = encrypted_root()
    # Delete individual binary files if they exist
    for key in ("aes_path", "des_path", "rc4_path"):
        path = item[key]
        if path and os.path.isabs(path) and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    # Delete directory containing encrypted files and metadata.json
    if item["aes_path"]:
        file_dir = os.path.abspath(os.path.dirname(item["aes_path"]))
        try:
            if os.path.commonpath([root, file_dir]) == root and file_dir != root and os.path.isdir(file_dir):
                shutil.rmtree(file_dir, ignore_errors=True)
        except (ValueError, OSError):
            pass

    db = get_db()
    try:
        db.execute(
            "DELETE FROM files WHERE id = ? AND user_id = ?",
            (file_id, current_user_id())
        )
        db.commit()
    finally:
        db.close()

    flash(f"Berkas '{item['original_name']}' berhasil dihapus secara permanen dari server.")
    return redirect(url_for("main.files_page"))

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


# Developers are explicitly allowlisted by the server operator, never by form input.
def is_developer():
    allowed = current_app.config.get("DEVELOPER_USERNAMES", ())
    return logged_in() and session.get("username") in allowed


@bp.app_context_processor
def developer_navigation():
    return {"developer_enabled": is_developer()}


@bp.route("/developer/evaluation", methods=["GET", "POST"])
def developer_evaluation():
    from datetime import datetime, timezone, timedelta
    from .evaluation import evaluate, audit_authorization, MAX_INPUT

    if not logged_in():
        return redirect(url_for("main.login"))
    if not is_developer():
        return render_template("developer_denied.html"), 403
    # Request-specific limit; normal candidate uploads keep their existing limit.
    request.max_content_length = MAX_INPUT + 1024 * 1024
    token = session.setdefault("evaluation_csrf", secrets.token_urlsafe(32))
    report, error = None, None
    repeats = 30
    source = "sample"
    sample_size = "65536"
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf_token", "").encode("utf-8"), token.encode("utf-8")):
            return "Token formulir tidak valid. Muat ulang halaman evaluasi.", 400
        try:
            repeats = int(request.form.get("repeats", "30"))
            source = request.form.get("source", "sample")
            sample_size = request.form.get("sample_size", "65536")
            mime_type = "application/octet-stream"
            if source == "sample":
                sizes = {"1024", "65536", "1048576", "4194304"}
                if sample_size not in sizes:
                    raise ValueError("Ukuran sampel tidak valid.")
                import random
                data = random.Random(2026).randbytes(int(sample_size))
                filename = f"synthetic-{sample_size}.bin"
            elif source == "upload":
                uploaded = request.files.get("file")
                if not uploaded or not uploaded.filename:
                    raise ValueError("Pilih file untuk diuji.")
                filename = secure_filename(uploaded.filename) or "evaluation.bin"
                mime_type = uploaded.mimetype or "application/octet-stream"
                data = uploaded.read(MAX_INPUT + 1)
            else:
                raise ValueError("Sumber pengujian tidak valid.")
            report = evaluate(data, filename, repeats, mime_type=mime_type)
            report["authorization"] = audit_authorization(os.path.dirname(current_app.root_path))
            report["generated_at"] = datetime.now(timezone(timedelta(hours=7))).isoformat()
            if request.form.get("output") == "json":
                response = current_app.response_class(
                    json.dumps(report, ensure_ascii=False, indent=2), mimetype="application/json")
                response.headers["Content-Disposition"] = 'attachment; filename="evaluasi-cipher.json"'
                response.headers["Cache-Control"] = "no-store"
                return response
        except (ValueError, OverflowError) as exc:
            error = str(exc)
    response = current_app.make_response(render_template(
        "developer_evaluation.html", report=report, error=error, csrf_token=token,
        repeats=repeats, source=source, sample_size=sample_size))
    response.headers["Cache-Control"] = "no-store"
    return response
