"""
TEE Worker — runs as an isolated subprocess.

Receives a single JSON line on stdin, processes the search inside this
isolated process (simulating a Trusted Execution Environment), writes a
single JSON line on stdout, then exits immediately.

stdin JSON schema:
{
  "encrypted_query_b64": "<base64 RSA-OAEP ciphertext>",
  "private_key_pem":     "<PEM string of session RSA private key>",
  "enc_file_path":       "<path to .enc file>",
  "salt_b64":            "<base64 HKDF salt>",
  "nonce_b64":           "<base64 AES-GCM nonce>",
  "master_key_hex":      "<hex of master key>"
}

stdout JSON schema (padded to RESPONSE_PAD_SIZE bytes):
{
  "results": [{"page": int, "priority": str, "score": float, "excerpt": str,
               "match_type": "EXACT" | "PHONETIC"}],
  "match_count": int,
  "pad": "<random padding to constant size>"
}

All stdout outside this JSON is suppressed — stderr is used for errors.
"""

import sys
import json
import base64
import os
import math
import secrets

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── Fixed response size in bytes (must match config.RESPONSE_PAD_SIZE)
RESPONSE_PAD_SIZE = 4096
EXCERPT_MAX_LEN   = 220   # characters per excerpt snippet
PAGE_SIZE         = 500   # characters per "page" for pagination

# ── Priority thresholds by keyword frequency
PRIORITY_HIGH   = 5
PRIORITY_MEDIUM = 2


def _derive_file_key(master_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ciphersearch-file-key",
    )
    return hkdf.derive(master_key)


def _decrypt_query(private_key_pem: str, encrypted_query_b64: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    ciphertext = base64.b64decode(encrypted_query_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def _decrypt_file(enc_path: str, master_key: bytes, salt: bytes, nonce: bytes) -> str:
    with open(enc_path, "rb") as f:
        ciphertext_with_tag = f.read()

    file_key = _derive_file_key(master_key, salt)
    aesgcm   = AESGCM(file_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8", errors="replace")


def _search(text: str, keyword: str) -> list[dict]:
    """
    Two-pass search:
      Pass 1 — Exact (case-insensitive substring): match_type = EXACT
      Pass 2 — Phonetic (Soundex + Double Metaphone word-level): match_type = PHONETIC

    Phonetic pass finds words that *sound like* the keyword even if spelled
    differently. Results are merged and sorted by priority then score.
    """
    # Late import — phonetics.py lives in the same tee/ package
    import sys as _sys
    import os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(__file__)))
    from tee.phonetics import phonetic_match

    keyword_lower = keyword.lower()
    pages = [text[i:i + PAGE_SIZE] for i in range(0, len(text), PAGE_SIZE)]
    results = []
    seen_pages = set()  # avoid duplicate page entries

    # ── Pass 1: Exact matching
    for page_num, page_text in enumerate(pages, start=1):
        count = page_text.lower().count(keyword_lower)
        if count == 0:
            continue

        priority = (
            "HIGH"   if count >= PRIORITY_HIGH   else
            "MEDIUM" if count >= PRIORITY_MEDIUM else
            "LOW"
        )
        score = round(min(count / PRIORITY_HIGH, 1.0), 4)

        idx   = page_text.lower().find(keyword_lower)
        start = max(0, idx - 60)
        end   = min(len(page_text), idx + len(keyword) + 100)
        raw   = page_text[start:end].strip()
        highlighted = raw.replace(
            raw[idx - start: idx - start + len(keyword)],
            f"**{keyword}**", 1
        )
        excerpt = f"...{highlighted[:EXCERPT_MAX_LEN]}..."

        results.append({
            "page":       page_num,
            "priority":   priority,
            "score":      score,
            "excerpt":    excerpt,
            "count":      count,
            "match_type": "EXACT",
        })
        seen_pages.add(page_num)

    # ── Pass 2: Phonetic matching (only on pages not already matched exactly)
    for page_num, page_text in enumerate(pages, start=1):
        if page_num in seen_pages:
            continue

        # Tokenise page into words, strip punctuation
        words = [w.strip(".,!?;:\"'()[]") for w in page_text.split()]
        words = [w for w in words if w]

        # Find words that sound like the keyword but aren't exact matches
        phonetic_hits = [
            w for w in words
            if w.lower() != keyword_lower and phonetic_match(keyword, w)
        ]

        if not phonetic_hits:
            continue

        count = len(phonetic_hits)
        priority = (
            "HIGH"   if count >= PRIORITY_HIGH   else
            "MEDIUM" if count >= PRIORITY_MEDIUM else
            "LOW"
        )
        # Phonetic matches score 65% of their raw count score (slight penalty)
        score = round(min(count / PRIORITY_HIGH, 1.0) * 0.65, 4)

        # Build excerpt around the first phonetic hit
        first_hit = phonetic_hits[0]
        idx   = page_text.lower().find(first_hit.lower())
        start = max(0, idx - 60)
        end   = min(len(page_text), idx + len(first_hit) + 100)
        raw   = page_text[start:end].strip()
        highlighted = raw.replace(first_hit, f"**{first_hit}**", 1)

        unique_variants = list(dict.fromkeys(w.lower() for w in phonetic_hits))[:3]
        excerpt = (
            f"...{highlighted[:EXCERPT_MAX_LEN]}... "
            f"[phonetic variants: {', '.join(unique_variants)}]"
        )

        results.append({
            "page":       page_num,
            "priority":   priority,
            "score":      score,
            "excerpt":    excerpt,
            "count":      count,
            "match_type": "PHONETIC",
        })

    # Sort: EXACT before PHONETIC, then HIGH→MEDIUM→LOW, then score desc
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    match_order    = {"EXACT": 0, "PHONETIC": 1}
    results.sort(key=lambda r: (
        match_order[r["match_type"]],
        priority_order[r["priority"]],
        -r["score"]
    ))

    return results


def _pad_response(payload: dict) -> str:
    """
    Serialise payload to JSON and pad with random base64 chars to exactly
    RESPONSE_PAD_SIZE bytes. This prevents size-based side-channel leakage.
    """
    payload["pad"] = ""
    base_json   = json.dumps(payload, separators=(",", ":"))
    base_bytes  = base_json.encode("utf-8")
    overhead    = len(base_json.encode()) - len('""')  # account for closing }
    padding_len = RESPONSE_PAD_SIZE - len(base_bytes)

    if padding_len < 0:
        # Truncate excerpts to fit if payload exceeds pad size (edge case)
        for r in payload.get("results", []):
            r["excerpt"] = r["excerpt"][:80] + "..."
        base_json   = json.dumps(payload, separators=(",", ":"))
        base_bytes  = base_json.encode("utf-8")
        padding_len = RESPONSE_PAD_SIZE - len(base_bytes)

    pad_str = secrets.token_urlsafe(math.ceil(padding_len * 6 / 8))[:max(0, padding_len)]
    payload["pad"] = pad_str
    final = json.dumps(payload, separators=(",", ":"))

    # Ensure exact byte length
    final_bytes = final.encode("utf-8")
    if len(final_bytes) < RESPONSE_PAD_SIZE:
        # Shouldn't happen, but top-up with spaces inside pad value
        diff = RESPONSE_PAD_SIZE - len(final_bytes)
        payload["pad"] = pad_str + ("0" * diff)
        final = json.dumps(payload, separators=(",", ":"))
    elif len(final_bytes) > RESPONSE_PAD_SIZE:
        final = final[:RESPONSE_PAD_SIZE]

    return final


def main():
    try:
        raw = sys.stdin.readline()
        req = json.loads(raw)

        master_key = bytes.fromhex(req["master_key_hex"])
        salt       = base64.b64decode(req["salt_b64"])
        nonce      = base64.b64decode(req["nonce_b64"])

        # Step 1: Decrypt the search query using the RSA session private key
        keyword = _decrypt_query(req["private_key_pem"], req["encrypted_query_b64"])

        # Step 2: Decrypt the document inside this TEE process
        plaintext = _decrypt_file(req["enc_file_path"], master_key, salt, nonce)

        # Step 3: Search
        results = _search(plaintext, keyword)

        # Step 4: Build fixed-size padded response
        payload = {
            "ok":          True,
            "match_count": len(results),
            "results":     results,
        }
        output = _pad_response(payload)
        sys.stdout.write(output + "\n")
        sys.stdout.flush()

    except Exception as exc:
        error_payload = {
            "ok":          False,
            "match_count": 0,
            "results":     [],
            "error":       str(exc),
            "pad":         "",
        }
        output = _pad_response(error_payload)
        sys.stdout.write(output + "\n")
        sys.stdout.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
