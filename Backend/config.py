import os
import secrets

# ── Master encryption key (32 bytes = AES-256)
# Load from env in production; generate a stable dev key if not set.
_MASTER_KEY_HEX = os.environ.get("CIPHERSEARCH_MASTER_KEY")
if _MASTER_KEY_HEX:
    MASTER_KEY: bytes = bytes.fromhex(_MASTER_KEY_HEX)
else:
    # Stable dev key written to .devkey so it persists across restarts
    _dev_key_path = os.path.join(os.path.dirname(__file__), ".devkey")
    if os.path.exists(_dev_key_path):
        with open(_dev_key_path, "r") as f:
            MASTER_KEY = bytes.fromhex(f.read().strip())
    else:
        MASTER_KEY = secrets.token_bytes(32)
        with open(_dev_key_path, "w") as f:
            f.write(MASTER_KEY.hex())

# ── Paths
BASE_DIR        = os.path.dirname(__file__)
UPLOAD_FOLDER   = os.path.join(BASE_DIR, "uploads")
INDEX_FILE      = os.path.join(UPLOAD_FOLDER, "index.json")

# ── TEE / VM lifecycle
VM_SEARCH_LIMIT     = 10       # total searches before VM state reset
SESSION_TTL_SECONDS = 120      # seconds before an unused session expires
WATCHDOG_INTERVAL   = 30       # seconds between watchdog sweeps

# ── Constant-time response settings
RESPONSE_DEADLINE_MS = 500     # total ms budget for each search response
RESPONSE_PAD_SIZE    = 4096    # every response is padded to exactly this many bytes

# ── RSA session key size
RSA_KEY_BITS = 2048

# ── CORS
ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
