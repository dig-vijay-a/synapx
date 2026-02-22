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
from utils.phonetics import encode_word
import re
import io
import pypdf
import docx

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


def extract_text_content(file_bytes: bytes, filename: str) -> str:
    """Extracts text from PDF, DOCX, or plain text files."""
    ext = filename.lower().split(".")[-1]
    
    if ext == "pdf":
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        # Extract text from each page and join with form feed
        # (This aligns with Phase 3 Dynamic Page Detection)
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
        return config.PAGE_DELIMITER.join(pages)
        
    elif ext == "docx":
        doc = docx.Document(io.BytesIO(file_bytes))
        # Docx is harder to map to "physical" pages without rendering,
        # so we join paragraphs with double newlines.
        return "\n\n".join([p.text for p in doc.paragraphs])
        
    else:
        # Fallback to plain text
        try:
            return file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return file_bytes.decode("latin-1")


def _split_into_pages(text: str) -> list[str]:
    """
    Splits text into pages.
    1. If PAGE_DELIMITER is present, split by it.
    2. Otherwise, fall back to character-based slicing using PAGE_SIZE.
    """
    if config.PAGE_DELIMITER in text:
        return [p for p in text.split(config.PAGE_DELIMITER) if p.strip()]
    
    # Fallback to static slicing
    return [text[i:i + config.PAGE_SIZE] for i in range(0, len(text), config.PAGE_SIZE)]


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

    # Persist encrypted file to Cloud Vault
    enc_path = os.path.join(config.CLOUD_VAULT_DIR, f"{file_id}.enc")
    with open(enc_path, "wb") as ef:
        ef.write(ciphertext_with_tag)
        
    # --- Generate Index ---
    # Smart extraction based on file type
    text = extract_text_content(plaintext, f.filename)
        
    pages = _split_into_pages(text)
    
    # Inverted index structures
    exact_index = {}      # word -> set of page numbers
    soundex_index = {}    # soundex -> set of page numbers
    metaphone_index = {}  # metaphone -> set of page numbers
    
    for page_num, page_text in enumerate(pages, start=1):
        # Extract words from page, stripping common punctuation
        words = [w.strip(".,!?;:\"'()[]") for w in page_text.split()]
        words = [w for w in words if w]
        
        seen_words_page = set()
        for w in words:
            w_lower = w.lower()
            if w_lower in seen_words_page:
                continue
            seen_words_page.add(w_lower)
            
            # Exact mapping
            if w_lower not in exact_index:
                exact_index[w_lower] = []
            exact_index[w_lower].append(page_num)
            
            # Phonetic mappings
            codes = encode_word(w)
            sx = codes.get("soundex")
            if sx:
                if sx not in soundex_index:
                    soundex_index[sx] = []
                if page_num not in soundex_index[sx]:
                    soundex_index[sx].append(page_num)
                    
            mt = codes.get("metaphone")
            if mt:
                if mt not in metaphone_index:
                    metaphone_index[mt] = []
                if page_num not in metaphone_index[mt]:
                    metaphone_index[mt].append(page_num)

    index_payload = {
        "exact": exact_index,
        "soundex": soundex_index,
        "metaphone": metaphone_index
    }
    index_json_bytes = json.dumps(index_payload, separators=(",", ":")).encode("utf-8")
    
    # Encrypt the index using the SAME derived file key, but a NEW nonce
    idx_nonce = os.urandom(12)
    idx_ciphertext_with_tag = aesgcm.encrypt(idx_nonce, index_json_bytes, None)
    
    enc_idx_path = os.path.join(config.CLOUD_VAULT_DIR, f"{file_id}.idx.enc")
    with open(enc_idx_path, "wb") as ef:
        ef.write(idx_ciphertext_with_tag)

    # Record metadata (key-material encoded as base64; key itself is NOT stored)
    index = _load_index()
    index[file_id] = {
        "original_name": f.filename,
        "extension":     f.filename.lower().split(".")[-1] if "." in f.filename else "txt",
        "salt_b64":      base64.b64encode(salt).decode(),
        "nonce_b64":     base64.b64encode(nonce).decode(),
        "enc_path":      enc_path,
        "idx_nonce_b64": base64.b64encode(idx_nonce).decode(),
        "enc_idx_path":  enc_idx_path,
        "size_bytes":    len(plaintext),
        "cloud_metadata": {
            "provider": config.CLOUD_PROVIDER,
            "bucket": config.CLOUD_BUCKET,
            "region": config.CLOUD_REGION,
            "storage_class": "STANDARD",
            "encryption": "AES-256-GCM-SERVER-SIDE"
        }
    }
    _save_index(index)

    return jsonify({
        "file_id":       file_id,
        "original_name": f.filename,
        "size_bytes":    len(plaintext),
    }), 200
