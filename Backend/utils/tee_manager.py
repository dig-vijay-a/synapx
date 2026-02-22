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

try:
    import docker
    from docker.errors import DockerException, ContainerError, ImageNotFound
    _HAS_DOCKER = True
except ImportError:
    _HAS_DOCKER = False
    DockerException = Exception
    ContainerError = Exception
    ImageNotFound = Exception

import config
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# Path to the TEE worker script (host-side)
_WORKER_SCRIPT = os.path.join(os.path.dirname(__file__), "tee_worker.py")


class TEEManager:
    def __init__(self):
        self._lock         = threading.Lock()
        self._search_count = 0     # total searches since last VM reset
        self._vm_gen       = 0     # incremented on each VM reset (for logging)
        self._watchdog: threading.Thread | None = None
        self._running      = True
        
        # Docker state
        self._docker_client = None
        self._container = None
        self._container_lock = threading.Lock()
        self._use_docker = False

        if _HAS_DOCKER:
            try:
                self._docker_client = docker.from_env()
                self._docker_client.ping()
                self._use_docker = True
                logger.info("[TEE] Docker initialized. Running in real TEE isolation mode (Docker).")
            except Exception as e:
                logger.warning("[TEE] Docker not accessible (%s). Falling back to simulation.", e)
        else:
            logger.warning("[TEE] docker SDK not found. Falling back to simulation.")

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
        Spawn an isolated search execution.
        If Docker is enabled, uses a persistent container + exec.
        Returns the parsed JSON result.
        """
        t_start = time.monotonic()
        session_id = session.get("session_id", "unknown")[:8]

        # Build the stdin payload for the worker
        private_key_pem = session["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        file_meta = session["file_meta"]

        # Deduce extension from name if missing (for legacy files)
        ext = file_meta.get("extension")
        if not ext:
            name = file_meta.get("original_name", "")
            ext = name.lower().split(".")[-1] if "." in name else "txt"

        # Prepare input for worker
        enc_path = file_meta["enc_path"]
        idx_path = file_meta.get("enc_idx_path", "")

        # If using Docker, we must translate Host absolute paths to Container paths
        if self._use_docker:
            vault_host_base = os.path.abspath(config.CLOUD_VAULT_DIR)
            if enc_path.startswith(vault_host_base):
                enc_path = enc_path.replace(vault_host_base, "/app/CloudVault").replace("\\", "/")
            if idx_path and idx_path.startswith(vault_host_base):
                idx_path = idx_path.replace(vault_host_base, "/app/CloudVault").replace("\\", "/")

        worker_input = json.dumps({
            "encrypted_query_b64": session["encrypted_query_b64"],
            "private_key_pem":     private_key_pem,
            "enc_file_path":       enc_path,
            "salt_b64":            file_meta["salt_b64"],
            "nonce_b64":           file_meta["nonce_b64"],
            "enc_idx_path":        idx_path,
            "idx_nonce_b64":       file_meta.get("idx_nonce_b64", ""),
            "extension":           ext,
            "master_key_hex":      config.MASTER_KEY.hex(),
        })

        # Spawn isolated execution
        if self._use_docker:
            result_json = self._spawn_worker_docker(worker_input, session_id)
        else:
            result_json = self._spawn_worker_subprocess(worker_input, session_id)

        # Increment global search counter; reset VM if limit reached
        with self._lock:
            self._search_count += 1
            count_now = self._search_count
            if self._search_count >= config.VM_SEARCH_LIMIT:
                self._reset_vm()

        logger.info(
            "[TEE] Search #%d complete (session_id=%s, VM gen %d). VM reset in %d searches.",
            count_now, session_id, self._vm_gen,
            max(0, config.VM_SEARCH_LIMIT - count_now)
        )

        # Constant-time enforcement
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
        self._cleanup_container()

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _ensure_container(self):
        """Ensure the TEE VM container is running. Spawns if missing."""
        with self._container_lock:
            if self._container:
                try:
                    self._container.reload()
                    if self._container.status == 'running':
                        return
                except:
                    self._container = None

            logger.info("[TEE] Starting fresh TEE VM Container (Generation %d)...", self._vm_gen)
            container_name = f"synapx-tee-vm-gen-{self._vm_gen}"
            
            # Cleanup any zombie container with same name
            try:
                old = self._docker_client.containers.get(container_name)
                old.remove(force=True)
            except:
                pass

            try:
                # Mount CloudVault for the worker
                # We mount it as read-only for security
                vault_path = os.path.abspath(config.CLOUD_VAULT_DIR)
                
                self._container = self._docker_client.containers.run(
                    config.DOCKER_IMAGE_NAME,
                    name=container_name,
                    detach=True,
                    remove=True,
                    network_mode="none",  # HARD ISOLATION
                    mem_limit=config.DOCKER_MEMORY_LIMIT,
                    cpu_quota=config.DOCKER_CPU_QUOTA,
                    volumes={
                        vault_path:   {'bind': '/app/CloudVault', 'mode': 'ro'}
                    }
                )
                logger.info("[TEE] TEE VM Container started: %s", self._container.short_id)
            except ImageNotFound:
                self._use_docker = False
                logger.error("[TEE] Docker image %s not found. Falling back to simulation.", config.DOCKER_IMAGE_NAME)
            except Exception as e:
                self._use_docker = False
                logger.error("[TEE] Failed to start Docker container: %s. Falling back to simulation.", e)

    def _spawn_worker_docker(self, worker_input: str, session_id: str) -> dict:
        """Execute the worker inside the persistent TEE container via 'docker exec'."""
        self._ensure_container()
        if not self._container:
            return self._spawn_worker_subprocess(worker_input, session_id)

        try:
            # We pass the JSON input as a direct argument for simplicity and speed
            # Since the container is isolated and we control the host, this is safe.
            cmd = ["python", "utils/tee_worker.py", worker_input]
            
            # exec_run returns (exit_code, output)
            response = self._container.exec_run(cmd, workdir="/app")
            
            if response.exit_code != 0:
                logger.error("[TEE] Docker Worker Error (Session %s): %s", session_id, response.output.decode(errors="replace"))
            
            output_str = response.output.decode("utf-8").strip()
            if not output_str:
                return {"ok": False, "results": [], "match_count": 0, "error": "No output from container worker"}
            
            return json.loads(output_str)

        except Exception as e:
            logger.error("[TEE] Docker Search Failed: %s", e)
            return {"ok": False, "results": [], "match_count": 0, "error": str(e)}

    def _spawn_worker_subprocess(self, worker_input: str, session_id: str) -> dict:
        """Fallback simulation logic (subprocess)."""
        try:
            proc = subprocess.Popen(
                [sys.executable, _WORKER_SCRIPT],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            stdout_data, stderr_data = proc.communicate(
                input=worker_input.encode("utf-8"),
                timeout=config.DOCKER_TIMEOUT,
            )
            if not stdout_data.strip():
                return {"ok": False, "results": [], "match_count": 0, "error": "No output from worker"}
            return json.loads(stdout_data.decode("utf-8").strip())
        except Exception as exc:
            return {"ok": False, "results": [], "match_count": 0, "error": str(exc)}

    def _reset_vm(self):
        """Reset the VM state after VM_SEARCH_LIMIT."""
        self._search_count = 0
        self._vm_gen      += 1
        logger.warning("[TEE] VM generation reset. Transitioning to Generation %d.", self._vm_gen)
        
        # Kill the persistent container
        self._cleanup_container()
        
        # Clear sessions (forces fresh key exchange)
        from controllers.session import _sessions
        _sessions.clear()

    def _cleanup_container(self):
        with self._container_lock:
            if self._container:
                try:
                    self._container.remove(force=True)
                except:
                    pass
                self._container = None

    def _watchdog_loop(self):
        while self._running:
            time.sleep(config.WATCHDOG_INTERVAL)
            try:
                from controllers.session import purge_expired_sessions
                purged = purge_expired_sessions()
                if purged:
                    logger.info("[TEE Watchdog] Purged %d expired sessions.", purged)
            except Exception as exc:
                logger.error("[TEE Watchdog] Error: %s", exc)


# Singleton instance
tee_manager = TEEManager()
