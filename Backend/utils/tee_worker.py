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
  "enc_idx_path":        "<path to .idx.enc file>",
  "idx_nonce_b64":       "<base64 AES-GCM index nonce>",
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
import io
# Deferred imports for pypdf and docx moved to extract_text_content

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── Fixed response size in bytes (must match config.RESPONSE_PAD_SIZE)
RESPONSE_PAD_SIZE = 4096
EXCERPT_MAX_LEN   = 220   # characters per excerpt snippet
PAGE_SIZE         = 2000   # characters per "page" for pagination

# ── Priority thresholds by keyword frequency
PRIORITY_HIGH   = 5
PRIORITY_MEDIUM = 2


def _split_into_pages(text: str) -> list[str]:
    """
    Dynamic page splitting logic (mirrors upload.py).
    Splits by PAGE_DELIMITER if present, otherwise uses PAGE_SIZE.
    """
    # Import config-like constants defined locally or passed in
    # For the worker, we use the local constants or we could pass them in.
    # To keep it simple and consistent, we'll check for the delimiter locally.
    
    # Note: PAGE_DELIMITER from config is '\x0c'
    DELIM = "\x0c" 
    if DELIM in text:
        return [p for p in text.split(DELIM) if p.strip()]
    
    return [text[i:i + PAGE_SIZE] for i in range(0, len(text), PAGE_SIZE)]


def _derive_file_key(master_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ciphersearch-file-key",
    )
    return hkdf.derive(master_key)


def _levenshtein(s1, s2):
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


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


def _decrypt_file(enc_path: str, master_key: bytes, salt: bytes, nonce: bytes) -> bytes:
    with open(enc_path, "rb") as f:
        ciphertext_with_tag = f.read()

    file_key = _derive_file_key(master_key, salt)
    aesgcm   = AESGCM(file_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes


def extract_text_content(file_bytes: bytes, ext: str) -> str:
    """Extracts text from PDF, DOCX, or plain text bytes inside the TEE."""
    try:
        if ext == "pdf":
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            return "\x0c".join(pages)
            
        elif ext == "docx":
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            return "\n\n".join([p.text for p in doc.paragraphs])
            
        else:
            try:
                return file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return file_bytes.decode("latin-1")
    except Exception as e:
        sys.stderr.write(f"Extraction failed for {ext}: {e}\n")
        # Fallback to raw decoding if extraction fails
        try:
            return file_bytes.decode("utf-8")
        except:
            return file_bytes.decode("latin-1")


def _search(text: str, keyword: str, index: dict | None) -> list[dict]:
    """
    Two-pass search:
      Pass 1 — Exact (case-insensitive substring): match_type = EXACT
      Pass 2 — Phonetic (Soundex + Double Metaphone word-level): match_type = PHONETIC

    If `index` is provided, it drastically speeds up page discovery.
    """
    import sys as _sys
    import os as _os
    import re as _re
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(__file__)))
    from utils.phonetics import encode_word
    
    keyword_lower = keyword.lower()
    pages = _split_into_pages(text)
    results = []
    seen_pages = set()

    # Determine which pages to scan based on the index (if available)
    pages_to_scan_exact = set(range(1, len(pages) + 1))
    pages_to_scan_phonetic = set(range(1, len(pages) + 1))
    
    encoded_kw = encode_word(keyword)
    sx = encoded_kw.get("soundex")
    mt = encoded_kw.get("metaphone")

    if index:
        exact_pages = set()
        kw_tokens = keyword_lower.split()
        
        if len(kw_tokens) > 1:
            # Phrase search: find pages containing ALL words in the phrase
            token_page_sets = []
            for token in kw_tokens:
                # STRIP punctuation from search token to match index keys!
                token_clean = token.strip(".,!?;:\"'()[]")
                if not token_clean: continue
                
                t_pages = set()
                for idx_word, pgs in index.get("exact", {}).items():
                    if token_clean in idx_word:
                        t_pages.update(pgs)
                token_page_sets.append(t_pages)
            
            if token_page_sets:
                exact_pages = token_page_sets[0]
                for s in token_page_sets[1:]:
                    exact_pages &= s
        else:
            # Single word search
            # STRIP punctuation from search token to match index keys!
            token_clean = keyword_lower.strip(".,!?;:\"'()[]")
            for idx_word, pgs in index.get("exact", {}).items():
                if token_clean in idx_word:
                    exact_pages.update(pgs)
                
        # SAFETY FALLBACK: If index-based search found nothing but document has content,
        # we might have a stale index or parsing mismatch. Perform a full scan if results are 0.
        if not exact_pages and len(pages) < 200: # limit fallback to small-mid docs for perf
             pages_to_scan_exact = set(range(1, len(pages) + 1))
        else:
             pages_to_scan_exact = exact_pages
        
        ph_pages = set()
        if sx:
            ph_pages.update(index.get("soundex", {}).get(sx, []))
        if mt:
            ph_pages.update(index.get("metaphone", {}).get(mt, []))
            
        pages_to_scan_phonetic = ph_pages
        
    # ── Pass 1: Exact matching
    for page_num in sorted(pages_to_scan_exact):
        if page_num > len(pages):
            continue
        page_text = pages[page_num - 1]
        
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
    for page_num in sorted(pages_to_scan_phonetic):
        if page_num in seen_pages or page_num > len(pages):
            continue
            
        page_text = pages[page_num - 1]

        # Tokenise page into words, strip punctuation
        words = [w.strip(".,!?;:\"'()[]") for w in page_text.split()]
        words = [w for w in words if w]

        # Find words that sound like the keyword but aren't exact matches
        phonetic_hits = []
        for w in words:
            if w.lower() == keyword_lower:
                continue
            cw = encode_word(w)
            if (sx and cw.get("soundex") == sx) or (mt and cw.get("metaphone") == mt):
                phonetic_hits.append(w)

        if not phonetic_hits:
            continue

        count = len(phonetic_hits)
        priority = (
            "HIGH"   if count >= PRIORITY_HIGH   else
            "MEDIUM" if count >= PRIORITY_MEDIUM else
            "LOW"
        )
        # Phonetic matches score 65% of their raw count score
        score = round(min(count / PRIORITY_HIGH, 1.0) * 0.65, 4)

        # Build excerpt around the first phonetic hit
        first_hit = phonetic_hits[0]
        idx   = page_text.lower().find(first_hit.lower())
        start = max(0, idx - 60)
        end   = min(len(page_text), idx + len(first_hit) + 100)
        raw   = page_text[start:end].strip()
        
        # safely replace first hit ignoring case
        orig = raw[idx - start: idx - start + len(first_hit)]
        if orig.lower() == first_hit.lower():
            highlighted = raw.replace(orig, f"**{orig}**", 1)
        else:
            highlighted = raw

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
        seen_pages.add(page_num)

    # ── Pass 3: Fuzzy matching (only on pages not already matched)
    # Only applicable for single-word keywords
    if len(keyword.split()) == 1 and len(keyword) >= 4:
        # We scan all pages not yet seen
        for page_num, page_text in enumerate(pages, start=1):
            if page_num in seen_pages:
                continue
            
            # Tokenise page into words
            words = [w.strip(".,!?;:\"'()[]") for w in page_text.split()]
            words = [w for w in words if w]
            
            fuzzy_hits = []
            for w in words:
                w_lower = w.lower()
                if w_lower == keyword_lower:
                    continue
                
                # Distance of 1 for words of length 4-7, distance of 2 for 8+
                max_dist = 1 if len(keyword) < 8 else 2
                if _levenshtein(w_lower, keyword_lower) <= max_dist:
                    fuzzy_hits.append(w)
            
            if not fuzzy_hits:
                continue
                
            count = len(fuzzy_hits)
            priority = "LOW" # Fuzzy always LOW priority
            # Fuzzy matches score 40% of their raw count score
            score = round(min(count / PRIORITY_HIGH, 1.0) * 0.4, 4)

            first_hit = fuzzy_hits[0]
            idx   = page_text.lower().find(first_hit.lower())
            start = max(0, idx - 60)
            end   = min(len(page_text), idx + len(first_hit) + 100)
            raw   = page_text[start:end].strip()
            
            orig = raw[idx - start: idx - start + len(first_hit)]
            highlighted = raw.replace(orig, f"**{orig}**", 1)

            unique_variants = list(dict.fromkeys(w.lower() for w in fuzzy_hits))[:3]
            excerpt = (
                f"...{highlighted[:EXCERPT_MAX_LEN]}... "
                f"[fuzzy matches: {', '.join(unique_variants)}]"
            )

            results.append({
                "page":       page_num,
                "priority":   priority,
                "score":      score,
                "excerpt":    excerpt,
                "count":      count,
                "match_type": "FUZZY",
            })
            seen_pages.add(page_num)

    # Sort: EXACT before PHONETIC before FUZZY, then HIGH→MEDIUM→LOW, then score desc
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    match_order    = {"EXACT": 0, "PHONETIC": 1, "FUZZY": 2}
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
        # Support input via command-line argument OR stdin
        if len(sys.argv) > 1:
            raw = sys.argv[1]
        else:
            raw = sys.stdin.readline()
            
        if not raw or not raw.strip():
            return

        req = json.loads(raw)

        master_key = bytes.fromhex(req["master_key_hex"])
        salt       = base64.b64decode(req["salt_b64"])
        nonce      = base64.b64decode(req["nonce_b64"])

        # Step 1: Decrypt the search query using the RSA session private key
        keyword = _decrypt_query(req["private_key_pem"], req["encrypted_query_b64"])

        # Step 2: Decrypt the document inside this TEE process
        raw_bytes = _decrypt_file(req["enc_file_path"], master_key, salt, nonce)
        extension = req.get("extension", "txt")
        plaintext = extract_text_content(raw_bytes, extension)
        
        # Step 2.5: Decrypt the index if available
        index = None
        enc_idx_path = req.get("enc_idx_path")
        idx_nonce_b64 = req.get("idx_nonce_b64")
        if enc_idx_path and idx_nonce_b64 and os.path.exists(enc_idx_path):
            idx_nonce = base64.b64decode(idx_nonce_b64)
            idx_plaintext_bytes = _decrypt_file(enc_idx_path, master_key, salt, idx_nonce)
            index = json.loads(idx_plaintext_bytes.decode("utf-8"))

        # Step 3: Search using the index
        results = _search(plaintext, keyword, index)

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
