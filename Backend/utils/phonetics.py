"""
Phonetics utility for CipherSearch.

Provides sound-alike matching using two algorithms:
  - Soundex       : classic 4-char code (NIST standard)
  - Double Metaphone : more accurate, handles English phoneme variations

Usage:
    from utils.phonetics import phonetic_match, encode_word

    if phonetic_match("encryption", "inkription"):
        ...  # True — same Soundex or Metaphone code
"""

import re

try:
    import jellyfish
    _HAS_JELLYFISH = True
except ImportError:
    _HAS_JELLYFISH = False


# ─────────────────────────────────────────────────────────────
# Fallback: Pure-Python Soundex (if jellyfish not installed)
# ─────────────────────────────────────────────────────────────

_CLEAN_RE = re.compile(r"[^A-Za-z]")

_SOUNDEX_TABLE = str.maketrans(
    "BFPVCGJKQSXZDTLMNR",
    "111122222222334556"
)
_SOUNDEX_IGNORE = str.maketrans("", "", "AEHIOUWY")


def _soundex(word: str) -> str:
    """Return the 4-character Soundex code for a word."""
    if not word:
        return "0000"
    word = _CLEAN_RE.sub("", word).upper()
    if not word:
        return "0000"
    first = word[0]
    coded = word.translate(_SOUNDEX_TABLE)
    # Remove non-digit chars (A,E,H,I,O,U,W,Y become 0 in translation table)
    # Build code: keep first letter, then digits, collapse adjacent duplicates
    result = first
    prev = coded[0] if coded[0].isdigit() else ""
    for ch in coded[1:]:
        if ch.isdigit() and ch != prev:
            result += ch
            prev = ch
        elif not ch.isdigit():
            prev = ""
        if len(result) == 4:
            break
    return result.ljust(4, "0")


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def soundex(word: str) -> str:
    if _HAS_JELLYFISH:
        return jellyfish.soundex(word)
    return _soundex(word)


def metaphone(word: str) -> str | None:
    """Return the primary Double Metaphone code, or None if unavailable."""
    if _HAS_JELLYFISH:
        try:
            codes = jellyfish.double_metaphone(word)
            return codes[0] if codes else None
        except Exception:
            return None
    return None


def encode_word(word: str) -> dict:
    """
    Return all phonetic codes for a word.
    { "soundex": str, "metaphone": str | None }
    """
    clean = _CLEAN_RE.sub("", word)
    return {
        "soundex":   soundex(clean) if clean else None,
        "metaphone": metaphone(clean) if clean else None,
    }


def phonetic_match(keyword: str, candidate: str) -> bool:
    """
    Return True if keyword and candidate sound alike under either algorithm.
    Both words must be non-trivially long (≥ 2 chars) to avoid false positives.
    """
    kw = _CLEAN_RE.sub("", keyword).strip()
    cd = _CLEAN_RE.sub("", candidate).strip()

    if len(kw) < 2 or len(cd) < 2:
        return False

    # Soundex match
    if soundex(kw) == soundex(cd):
        return True

    # Double Metaphone match (primary codes)
    mkw = metaphone(kw)
    mcd = metaphone(cd)
    if mkw and mcd and mkw == mcd:
        return True

    # Double Metaphone alternate codes match
    if _HAS_JELLYFISH:
        try:
            kw_codes = set(c for c in jellyfish.double_metaphone(kw) if c)
            cd_codes = set(c for c in jellyfish.double_metaphone(cd) if c)
            if kw_codes & cd_codes:
                return True
        except Exception:
            pass

    return False


def phonetic_variants_in_text(keyword: str, text_words: list[str]) -> list[str]:
    """
    Return words from text_words that are phonetically similar to keyword
    but NOT exact matches (case-insensitive).
    """
    kw_lower = keyword.lower()
    return [
        w for w in text_words
        if w.lower() != kw_lower and phonetic_match(keyword, w)
    ]
