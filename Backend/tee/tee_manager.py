"""
TEE Manager — orchestrates isolated TEE worker subprocesses.

Responsibilities:
- Spawn a fresh subprocess per search (session isolation)
- Enforce VM_SEARCH_LIMIT: after N total searches, reset all state
- Background watchdog: periodically purge expired sessions
- Enforce a constant-time response window (RESPONSE_DEADLINE_MS)
"""

import sys
import json
import os
import subprocess
import threading
import time
import base64
import logging

import config
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# Path to the TEE worker script
_WORKER_SCRIPT = os.path.join(os.path.dirname(__file__), "tee_worker.py")


class TEEManager:
    def __init__(self):
        self._lock         = threading.Lock()
        self._search_count = 0     # total searches since last VM reset
        self._vm_gen       = 0     # incremented on each VM reset (for logging)
        self._watchdog: threading.Thread | None = None
        self._running      = True

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def start_watchdog(self):
        """Start the background thread that cleans up expired sessions."""
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="tee-watchdog"
        )
        self._watchdog.start()
        logger.info("[TEE] Watchdog started (interval=%ds)", config.WATCHDOG_INTERVAL)

    def run_search(self, session: dict) -> dict:
        """
        Spawn an isolated TEE worker subprocess for this session.
        Returns the parsed JSON result from the worker.
        Always enforces a minimum RESPONSE_DEADLINE_MS response time.
        """
        t_start = time.monotonic()

        # Build the stdin payload for the worker
        private_key_pem = session["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        file_meta = session["file_meta"]

        worker_input = json.dumps({
            "encrypted_query_b64": session["encrypted_query_b64"],
            "private_key_pem":     private_key_pem,
            "enc_file_path":       file_meta["enc_path"],
            "salt_b64":            file_meta["salt_b64"],
            "nonce_b64":           file_meta["nonce_b64"],
            "master_key_hex":      config.MASTER_KEY.hex(),
        })

        # Spawn completely isolated subprocess (TEE simulation)
        result_json = self._spawn_worker(worker_input)

        # Increment global search counter; reset VM if limit reached
        with self._lock:
            self._search_count += 1
            count_now = self._search_count
            if self._search_count >= config.VM_SEARCH_LIMIT:
                self._reset_vm()

        logger.info(
            "[TEE] Search #%d complete (VM gen %d). VM reset in %d searches.",
            count_now, self._vm_gen,
            max(0, config.VM_SEARCH_LIMIT - count_now)
        )

        # Constant-time enforcement: pad elapsed time to RESPONSE_DEADLINE_MS
        elapsed_ms = (time.monotonic() - t_start) * 1000
        sleep_ms   = config.RESPONSE_DEADLINE_MS - elapsed_ms
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000)

        return result_json

    def get_search_count(self) -> int:
        with self._lock:
            return self._search_count

    def shutdown(self):
        self._running = False

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _spawn_worker(self, worker_input: str) -> dict:
        """
        Launch tee_worker.py as a fresh isolated subprocess.
        Communication is strictly via stdin/stdout — no shared state.
        The process is killed immediately after reading stdout.
        """
        try:
            proc = subprocess.Popen(
                [sys.executable, _WORKER_SCRIPT],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Isolated environment — no inherited file descriptors beyond stdio
                close_fds=True,
            )
            stdout_data, stderr_data = proc.communicate(
                input=worker_input.encode("utf-8"),
                timeout=5,  # hard timeout per search
            )

            if stderr_data:
                logger.warning("[TEE Worker] stderr: %s", stderr_data.decode(errors="replace"))

            if not stdout_data.strip():
                return {"ok": False, "results": [], "match_count": 0,
                        "error": "Worker produced no output"}

            return json.loads(stdout_data.decode("utf-8").strip())

        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            return {"ok": False, "results": [], "match_count": 0,
                    "error": "TEE worker timed out"}

        except Exception as exc:
            return {"ok": False, "results": [], "match_count": 0,
                    "error": str(exc)}

    def _reset_vm(self):
        """
        Simulates killing and restarting the VM:
        - Resets search counter
        - Increments VM generation ID
        - Purges all active sessions (forces fresh key exchange)
        """
        self._search_count = 0
        self._vm_gen      += 1
        logger.warning(
            "[TEE] VM_SEARCH_LIMIT reached. VM reset initiated. "
            "Starting VM generation %d.", self._vm_gen
        )
        # Import here to avoid circular dependency
        from routes.session import _sessions
        count = len(_sessions)
        _sessions.clear()
        logger.info("[TEE] Cleared %d active sessions from registry.", count)

    def _watchdog_loop(self):
        """Background thread: purge expired sessions every WATCHDOG_INTERVAL seconds."""
        while self._running:
            time.sleep(config.WATCHDOG_INTERVAL)
            try:
                from routes.session import purge_expired_sessions
                purged = purge_expired_sessions()
                if purged:
                    logger.info("[TEE Watchdog] Purged %d expired sessions.", purged)
            except Exception as exc:
                logger.error("[TEE Watchdog] Error: %s", exc)


# Singleton instance
tee_manager = TEEManager()
