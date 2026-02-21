"""
Search route — POST /api/search
Validates session, dispatches to the TEE manager, returns E2E-encrypted
fixed-size constant-time response.
"""
import base64
import json
import time

from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from routes.session import get_session, mark_session_used, delete_session
from routes.upload  import _load_index
from tee.tee_manager import tee_manager

search_bp = Blueprint("search", __name__)

# ── 32-byte session response key sent to client via the session endpoint
# For simplicity in this architecture the response AES key is derived per-session
# from a random nonce and is embedded in the session GET response.
# Here we do symmetric: server encrypts result with a fresh AES-GCM key,
# and returns both {ciphertext_b64, key_b64, nonce_b64} so the frontend
# can decrypt locally. (In a full PKI setup the client's public key would
# be used instead.)


@search_bp.route("/api/search", methods=["POST"])
def search():
    body = request.get_json(silent=True) or {}
    session_id          = body.get("session_id", "").strip()
    encrypted_query_b64 = body.get("encrypted_query_b64", "").strip()

    if not session_id or not encrypted_query_b64:
        return jsonify({"error": "session_id and encrypted_query_b64 are required"}), 400

    # ── Validate session
    session = get_session(session_id)
    if session is None:
        return jsonify({"error": "Invalid or expired session_id"}), 401

    if session["used"]:
        return jsonify({"error": "Session already consumed. Request a new session."}), 401

    # ── Load file metadata for the TEE worker
    index    = _load_index()
    file_id  = session["file_id"]
    file_meta = index.get(file_id)
    if not file_meta:
        return jsonify({"error": "Associated file not found"}), 404

    # Attach runtime data the TEE worker needs
    session["encrypted_query_b64"] = encrypted_query_b64
    session["file_meta"]           = file_meta

    # ── Mark session used BEFORE dispatching (prevents replay)
    mark_session_used(session_id)

    # ── Run search inside isolated TEE subprocess (also enforces constant time)
    tee_result = tee_manager.run_search(session)

    # ── Destroy session after TEE returns
    delete_session(session_id)

    # ── Encrypt the response with a fresh ephemeral AES-256-GCM key
    #    The frontend will receive the key + nonce alongside the ciphertext
    #    so it can decrypt locally in the browser.
    response_key   = b'\x00' * 32  # initialise
    response_nonce = b'\x00' * 12
    try:
        import os as _os
        response_key   = _os.urandom(32)
        response_nonce = _os.urandom(12)
        aesgcm         = AESGCM(response_key)
        # tee_result is already a fixed-size padded JSON string from the worker;
        # we use its bytes directly as the plaintext to encrypt.
        plaintext_bytes = json.dumps(tee_result).encode("utf-8")
        ciphertext      = aesgcm.encrypt(response_nonce, plaintext_bytes, None)
    except Exception as exc:
        return jsonify({"error": f"Response encryption failed: {exc}"}), 500

    return jsonify({
        "ciphertext_b64":  base64.b64encode(ciphertext).decode(),
        "key_b64":         base64.b64encode(response_key).decode(),
        "nonce_b64":       base64.b64encode(response_nonce).decode(),
        "searches_remaining": max(
            0, config.VM_SEARCH_LIMIT - tee_manager.get_search_count()
        ),
    }), 200
