import base64
import hashlib
import hmac
import io
import json
import math
import os
import struct
import time

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image, UnidentifiedImageError

# Default legacy keys for backward compatibility and benchmarking
DEFAULT_AES_KEY = hashlib.sha256(b"assignment-1-aes-key").digest()
DEFAULT_DES_KEY = hashlib.md5(b"assignment-1-des-key").digest()[:8]
DEFAULT_RC4_KEY = hashlib.sha256(b"assignment-1-rc4-key").digest()

AES_KEY = DEFAULT_AES_KEY
DES_KEY = DEFAULT_DES_KEY
RC4_KEY = DEFAULT_RC4_KEY

DEFAULT_KEYS = {
    "aes": DEFAULT_AES_KEY,
    "des": DEFAULT_DES_KEY,
    "rc4": DEFAULT_RC4_KEY,
}

ALGORITHMS = {"aes", "des", "rc4"}
IMAGE_FORMATS = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP"}
PACKAGE_MAGIC = b"VAULTENC1\n"
IMAGE_TRAILER = b"VAULTIMG1"
PACKAGE_MAC_KEY = hashlib.sha256(AES_KEY + b"vault-export-v1").digest()


def generate_keys():
    """Generate cryptographically secure random keys for each algorithm."""
    return {
        "aes": get_random_bytes(32),
        "des": get_random_bytes(8),
        "rc4": get_random_bytes(32),
    }


def derive_mac_key(key):
    """Derive HMAC integrity key from cipher key."""
    return hashlib.sha256(key + b"vault-export-v1-mac").digest()


def pack_encrypted_file(ciphertext, algorithm, original_name, mime_type, iv=b"", key=None):
    """Portable ciphertext, metadata and integrity tag derived from the item's key."""
    if algorithm not in ALGORITHMS:
        raise ValueError("Algoritma tidak valid.")
    if key is None:
        key = DEFAULT_KEYS.get(algorithm)
    payload = json.dumps({
        "version": 1,
        "algorithm": algorithm,
        "original_name": original_name,
        "mime_type": mime_type or "application/octet-stream",
        "iv": encode_bytes(iv),
        "ciphertext": encode_bytes(ciphertext),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(derive_mac_key(key), payload, hashlib.sha256).digest()
    return PACKAGE_MAGIC + signature + payload


def extract_package_bytes(data):
    """Extract raw package bytes from .enc export or encrypted image trailer."""
    if data.endswith(IMAGE_TRAILER):
        footer_size = 8 + len(IMAGE_TRAILER)
        if len(data) < footer_size:
            raise ValueError("File gambar terenkripsi tidak lengkap.")
        length = struct.unpack(">Q", data[-footer_size:-len(IMAGE_TRAILER)])[0]
        if length > len(data) - footer_size or length == 0:
            raise ValueError("Payload gambar terenkripsi tidak valid.")
        data = data[-footer_size-length:-footer_size]
    if not data.startswith(PACKAGE_MAGIC):
        raise ValueError("Gunakan file .enc atau gambar hasil enkripsi dari aplikasi ini.")
    return data


def unpack_encrypted_file(data, key=None):
    """Read either an .enc export or an unchanged exported encrypted image with key verification."""
    data = extract_package_bytes(data)
    start = len(PACKAGE_MAGIC)
    signature, payload = data[start:start+32], data[start+32:]

    try:
        item = json.loads(payload)
        algorithm = item["algorithm"]
        if item["version"] != 1 or algorithm not in ALGORITHMS:
            raise ValueError("Versi atau algoritma tidak didukung.")
        if not isinstance(item["original_name"], str) or not item["original_name"]:
            raise ValueError("Nama file tidak valid.")
        if not isinstance(item["mime_type"], str):
            raise ValueError("Tipe file tidak valid.")
        item["ciphertext"] = base64.b64decode(item["ciphertext"], validate=True)
        item["iv"] = base64.b64decode(item["iv"], validate=True)
        required_iv = {"aes": AES.block_size, "des": DES.block_size, "rc4": 0}[algorithm]
        if len(item["iv"]) != required_iv:
            raise ValueError("IV tidak valid.")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Metadata file terenkripsi tidak valid.") from exc

    # Validate HMAC signature
    if key is not None:
        expected = hmac.new(derive_mac_key(key), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Kunci dekripsi salah atau berkas rusak.")
    else:
        # Fallback for legacy packages without specified key
        expected_def = hmac.new(derive_mac_key(DEFAULT_KEYS[algorithm]), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_def) and not hmac.compare_digest(signature, PACKAGE_MAC_KEY):
            raise ValueError("File terenkripsi rusak, telah berubah, atau memakai kunci berbeda.")

    return item


def decrypt_export(data, key=None):
    data = extract_package_bytes(data)
    start = len(PACKAGE_MAGIC)
    payload = data[start+32:]
    try:
        temp_item = json.loads(payload)
        algorithm = temp_item.get("algorithm")
    except Exception:
        algorithm = None

    if key is None and algorithm in DEFAULT_KEYS:
        key = DEFAULT_KEYS[algorithm]

    item = unpack_encrypted_file(data, key=key)
    alg = item["algorithm"]
    if alg == "aes":
        plaintext = decrypt_aes(item["ciphertext"], item["iv"], key=key)
    elif alg == "des":
        plaintext = decrypt_des(item["ciphertext"], item["iv"], key=key)
    else:
        plaintext = decrypt_rc4(item["ciphertext"], key=key)
    return plaintext, item["original_name"], item["mime_type"]


def encrypted_image(ciphertext, original_data, extension, package):
    """Render ciphertext as RGB noise and append the exact portable ciphertext."""
    if extension not in IMAGE_FORMATS:
        raise ValueError("Pratinjau tersedia untuk PNG, JPG, JPEG, dan WEBP.")
    try:
        with Image.open(io.BytesIO(original_data)) as source:
            source.load()
            width, height = source.size
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Isi file bukan gambar yang valid.") from exc
    if width * height > 4_000_000:
        scale = math.sqrt(4_000_000 / (width * height))
        width, height = max(1, int(width * scale)), max(1, int(height * scale))
    size = width * height * 3
    pixels = (ciphertext + hashlib.shake_256(ciphertext).digest(max(0, size-len(ciphertext))))[:size]
    preview = Image.frombytes("RGB", (width, height), pixels)
    output = io.BytesIO()
    preview.save(output, format=IMAGE_FORMATS[extension])
    return output.getvalue() + package + struct.pack(">Q", len(package)) + IMAGE_TRAILER


def encrypt_aes(data, key=None):
    if key is None:
        key = DEFAULT_AES_KEY
    if len(key) != 32:
        raise ValueError("Kunci AES-256 harus berukuran 32 byte.")
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)), iv


def decrypt_aes(ciphertext, iv, key=None):
    if key is None:
        key = DEFAULT_AES_KEY
    if len(key) != 32:
        raise ValueError("Kunci AES-256 harus berukuran 32 byte.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def encrypt_des(data, key=None):
    if key is None:
        key = DEFAULT_DES_KEY
    if len(key) != 8:
        raise ValueError("Kunci DES harus berukuran 8 byte.")
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, DES.block_size)), iv


def decrypt_des(ciphertext, iv, key=None):
    if key is None:
        key = DEFAULT_DES_KEY
    if len(key) != 8:
        raise ValueError("Kunci DES harus berukuran 8 byte.")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)


def encrypt_rc4(data, key=None):
    if key is None:
        key = DEFAULT_RC4_KEY
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def decrypt_rc4(ciphertext, key=None):
    if key is None:
        key = DEFAULT_RC4_KEY
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)


def encrypt_all(data, keys=None):
    if keys is None:
        keys = generate_keys()
    aes, aes_iv = encrypt_aes(data, key=keys["aes"])
    des, des_iv = encrypt_des(data, key=keys["des"])
    rc4 = encrypt_rc4(data, key=keys["rc4"])

    return {
        "aes": aes,
        "des": des,
        "rc4": rc4,
        "aes_iv": aes_iv,
        "des_iv": des_iv,
        "aes_key": keys["aes"],
        "des_key": keys["des"],
        "rc4_key": keys["rc4"],
    }


def decrypt_all(item, keys=None):
    if keys is None:
        keys = {
            "aes": item.get("aes_key") or DEFAULT_AES_KEY,
            "des": item.get("des_key") or DEFAULT_DES_KEY,
            "rc4": item.get("rc4_key") or DEFAULT_RC4_KEY,
        }
    return {
        "aes": decrypt_aes(item["aes"], item["aes_iv"], key=keys["aes"]),
        "des": decrypt_des(item["des"], item["des_iv"], key=keys["des"]),
        "rc4": decrypt_rc4(item["rc4"], key=keys["rc4"]),
    }


def benchmark(data, repeats=10):
    results = {}

    for name, encrypt_fn, decrypt_fn in [
        ("AES", lambda x: encrypt_aes(x), lambda c, iv: decrypt_aes(c, iv)),
        ("DES", lambda x: encrypt_des(x), lambda c, iv: decrypt_des(c, iv)),
    ]:
        enc_times = []
        dec_times = []
        ciphertext = None
        iv = None

        for _ in range(repeats):
            start = time.perf_counter()
            ciphertext, iv = encrypt_fn(data)
            enc_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            decrypt_fn(ciphertext, iv)
            dec_times.append(time.perf_counter() - start)

        results[name] = {
            "encryption_avg_ms": sum(enc_times) / repeats * 1000,
            "decryption_avg_ms": sum(dec_times) / repeats * 1000,
            "ciphertext_size": len(ciphertext),
        }

    enc_times = []
    dec_times = []
    ciphertext = None

    for _ in range(repeats):
        start = time.perf_counter()
        ciphertext = encrypt_rc4(data)
        enc_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        decrypt_rc4(ciphertext)
        dec_times.append(time.perf_counter() - start)

    results["RC4"] = {
        "encryption_avg_ms": sum(enc_times) / repeats * 1000,
        "decryption_avg_ms": sum(dec_times) / repeats * 1000,
        "ciphertext_size": len(ciphertext),
    }

    return results


def serialize_personal_data(data):
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def encode_bytes(data):
    return base64.b64encode(data).decode("ascii")


def decode_bytes(data):
    return base64.b64decode(data)
