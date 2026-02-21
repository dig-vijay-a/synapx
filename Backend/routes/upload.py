"""
Upload route — POST /api/upload
Receives a file from the frontend, encrypts it with AES-256-GCM,
saves the ciphertext to uploads/<uuid>.enc and records metadata.
"""
import json
import os
import uuid
import base64

from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import config

upload_bp = Blueprint("upload", __name__)


def _derive_file_key(salt: bytes) -> bytes:
    """Derive a unique AES-256 key per file using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ciphersearch-file-key",
    )
    return hkdf.derive(config.MASTER_KEY)


def _load_index() -> dict:
    if not os.path.exists(config.INDEX_FILE):
        return {}
    with open(config.INDEX_FILE, "r") as f:
        return json.load(f)


def _save_index(index: dict):
    with open(config.INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)


@upload_bp.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Read plaintext bytes
    plaintext: bytes = f.read()
    if len(plaintext) == 0:
        return jsonify({"error": "Empty file"}), 400

    # Generate identifiers and key material
    file_id   = str(uuid.uuid4())
    salt      = os.urandom(16)   # HKDF salt
    nonce     = os.urandom(12)   # AES-GCM nonce (96-bit)
    file_key  = _derive_file_key(salt)

    # Encrypt with AES-256-GCM
    aesgcm    = AESGCM(file_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)  # no AAD

    # Persist encrypted file
    enc_path = os.path.join(config.UPLOAD_FOLDER, f"{file_id}.enc")
    with open(enc_path, "wb") as ef:
        ef.write(ciphertext_with_tag)

    # Record metadata (key-material encoded as base64; key itself is NOT stored)
    index = _load_index()
    index[file_id] = {
        "original_name": f.filename,
        "salt_b64":      base64.b64encode(salt).decode(),
        "nonce_b64":     base64.b64encode(nonce).decode(),
        "enc_path":      enc_path,
        "size_bytes":    len(plaintext),
    }
    _save_index(index)

    return jsonify({
        "file_id":       file_id,
        "original_name": f.filename,
        "size_bytes":    len(plaintext),
    }), 200
