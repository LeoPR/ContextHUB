"""
app.py com Blueprints (sem rota legada)
- Registra blueprints de auth (/auth) e admin (/admin).
- Mantém rota "/" (index).
- auth.init_auth() é chamado aqui.
"""
from flask import Flask, render_template
import os
import logging
import auth

# Configurações
PORT = int(os.environ.get("PORT", 8080))
SECRET_KEY = os.environ.get("SECRET_KEY", None) or os.urandom(24).hex()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
REMEMBER_DAYS = int(os.environ.get("REMEMBER_DAYS", "30"))

# Logging básico
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(level=numeric_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app")
logger.setLevel(numeric_level)


def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    app.logger.setLevel(numeric_level)
    app.config["REMEMBER_DAYS"] = REMEMBER_DAYS

    # Inicializa auth (DB users/tokens)
    auth.init_auth()

    # Registra Blueprints
    from blueprints.auth import auth_bp
    from blueprints.admin import admin_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    @app.route("/")
    def index():
        return render_template("index.html")

    return app


app = create_app()

if __name__ == "__main__":
    logger.info("Starting app on port %s with LOG_LEVEL=%s", PORT, LOG_LEVEL)
    app.run(host="0.0.0.0", port=PORT)