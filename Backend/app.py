"""
CipherSearch Flask Application
"""
import logging
import os

from flask import Flask
from flask_cors import CORS

import config
from routes.upload  import upload_bp
from routes.session import session_bp
from routes.search  import search_bp
from tee.tee_manager import tee_manager


def create_app() -> Flask:
    app = Flask(__name__)

    # Allow requests from the Vite dev server
    CORS(app, resources={r"/api/*": {"origins": config.ALLOWED_ORIGINS}})

    # Ensure upload folder exists
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)

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

    app = create_app()
    # Start TEE watchdog background thread
    tee_manager.start_watchdog()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,  # reloader would spawn duplicate watchdog threads
    )
