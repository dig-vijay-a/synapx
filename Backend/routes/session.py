"""
Session route — GET /api/session?file_id=<id>
Generates a fresh RSA-2048 keypair per request.
The frontend uses the returned public key to encrypt its search query (RSA-OAEP).
The private key is held server-side only, associated with the session_id.
"""
import base64
import time
import uuid

from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import config
from routes.upload import _load_index

session_bp = Blueprint("session", __name__)


# ── In-memory session registry
# { session_id: { private_key, file_id, created_at, used } }
_sessions: dict = {}


def get_session(session_id: str) -> dict | None:
    return _sessions.get(session_id)


def mark_session_used(session_id: str):
    if session_id in _sessions:
        _sessions[session_id]["used"] = True


def delete_session(session_id: str):
    _sessions.pop(session_id, None)


def purge_expired_sessions():
    """Watchdog helper: remove sessions older than SESSION_TTL_SECONDS."""
    now = time.time()
    expired = [
        sid for sid, s in _sessions.items()
        if (now - s["created_at"]) > config.SESSION_TTL_SECONDS
    ]
    for sid in expired:
        _sessions.pop(sid, None)
    return len(expired)


@session_bp.route("/api/session", methods=["GET"])
def create_session():
    file_id = request.args.get("file_id", "").strip()
    if not file_id:
        return jsonify({"error": "file_id is required"}), 400

    # Verify the file exists in the index
    index = _load_index()
    if file_id not in index:
        return jsonify({"error": "Unknown file_id"}), 404

    # Generate fresh RSA-2048 keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_BITS,
    )
    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    session_id = str(uuid.uuid4())

    _sessions[session_id] = {
        "private_key": private_key,
        "file_id":     file_id,
        "created_at":  time.time(),
        "used":        False,
    }

    return jsonify({
        "session_id":    session_id,
        "public_key_pem": public_key_pem,
    }), 200
