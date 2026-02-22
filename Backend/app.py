"""
CipherSearch Flask Application
"""
import logging
import os

from flask import Flask
from flask_cors import CORS

import config
from controllers.upload  import upload_bp
from controllers.session import session_bp
from controllers.search  import search_bp
from utils.tee_manager import tee_manager


def create_app() -> Flask:
    app = Flask(__name__)

    # Allow requests from the Vite dev server
    CORS(app, resources={r"/api/*": {"origins": config.ALLOWED_ORIGINS}})

    # Ensure cloud vault directory exists
    os.makedirs(config.CLOUD_VAULT_DIR, exist_ok=True)

    # Register blueprints
    app.register_blueprint(upload_bp)
    app.register_blueprint(session_bp)
    app.register_blueprint(search_bp)

    # Health check
    @app.route("/api/health")
    def health():
        return {
            "status":  "ok",
            "project": "CipherSearch",
            "vm_gen":   tee_manager._vm_gen,
            "searches_this_gen": tee_manager.get_search_count(),
            "vm_limit": config.VM_SEARCH_LIMIT,
        }

    return app


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    cert_path = os.path.abspath(os.path.join(config.BASE_DIR, "..", "cert.pem"))
    key_path  = os.path.abspath(os.path.join(config.BASE_DIR, "..", "key.pem"))

    app = create_app()
    # Start TEE watchdog background thread
    tee_manager.start_watchdog()

    if os.path.exists(cert_path) and os.path.exists(key_path):
        logging.info(f"[SSL] Starting server in HTTPS mode using {cert_path}")
        ssl_context = (cert_path, key_path)
    else:
        logging.warning("[SSL] Certificates not found. Falling back to HTTP.")
        ssl_context = None

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,
        ssl_context=ssl_context
    )
