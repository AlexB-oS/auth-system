"""Servidor de autenticación (Flask) — contraseña + TOTP.

Ejecuta una app local (no desplegada) que demuestra autenticación de dos factores
con todas las defensas descritas en el informe. Punto de entrada: `flask --app app run`
o `python app.py`.
"""

from __future__ import annotations

import base64
import io

import qrcode
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth import accounts, db, sessions
from auth.ratelimit import IPThrottle
from config import Config


def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)
    cfg = config or Config()
    app.config.update(cfg.as_flask_dict())
    app.config["APP_CONFIG"] = cfg
    app.config["IP_THROTTLE"] = IPThrottle(max_hits=20, window_seconds=60)

    db.init_db(cfg.DB_PATH)

    # ----------------------------------------------------------------- #
    # Conexión por request
    # ----------------------------------------------------------------- #
    def get_db():
        if "db" not in g:
            g.db = db.connect(cfg.DB_PATH)
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    # ----------------------------------------------------------------- #
    # CSRF: validar token en todos los POST
    # ----------------------------------------------------------------- #
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            if not sessions.validate_csrf(request.form.get("csrf_token")):
                abort(400, "Token CSRF inválido o ausente.")

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": sessions.get_csrf_token}

    # ----------------------------------------------------------------- #
    # Cabeceras de seguridad en todas las respuestas
    # ----------------------------------------------------------------- #
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return resp

    def client_ip() -> str:
        return request.remote_addr or "0.0.0.0"

    def throttle_or_429():
        if not app.config["IP_THROTTLE"].allow(client_ip()):
            abort(429, "Demasiadas solicitudes. Inténtalo más tarde.")

    # ----------------------------------------------------------------- #
    # Rutas
    # ----------------------------------------------------------------- #
    @app.route("/")
    def index():
        uid = sessions.current_user_id()
        if uid is None:
            return redirect(url_for("login"))
        user = db.get_user_by_id(get_db(), uid)
        if user is None:
            sessions.logout()
            return redirect(url_for("login"))
        return render_template("dashboard.html", username=user["username"])

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            res = accounts.register(get_db(), username, password, cfg)
            if not res.ok:
                flash(res.message, "error")
                return render_template("register.html", username=username)
            # Tras registrar, obligamos a configurar el segundo factor.
            enroll = accounts.start_enrollment(get_db(), res.user_id, cfg)
            session["enrolling"] = res.user_id
            session["enroll_uri"] = enroll["uri"]
            session["enroll_secret"] = enroll["secret_b32"]
            return redirect(url_for("enroll"))
        return render_template("register.html", username="")

    @app.route("/enroll", methods=["GET", "POST"])
    def enroll():
        user_id = session.get("enrolling") or sessions.current_user_id()
        if user_id is None:
            return redirect(url_for("login"))

        if request.method == "POST":
            code = (request.form.get("code") or "").strip()
            res = accounts.confirm_enrollment(get_db(), user_id, code, cfg)
            if not res.ok:
                flash(res.message, "error")
                return render_template(
                    "enroll.html",
                    secret=session.get("enroll_secret"),
                    qr=_qr_data_uri(session.get("enroll_uri", "")),
                )
            # 2FA confirmado: mostramos los códigos de respaldo UNA sola vez.
            session.pop("enrolling", None)
            session.pop("enroll_uri", None)
            session.pop("enroll_secret", None)
            sessions.complete_login(user_id)
            return render_template("backup_codes.html", codes=res.backup_codes or [])

        return render_template(
            "enroll.html",
            secret=session.get("enroll_secret"),
            qr=_qr_data_uri(session.get("enroll_uri", "")),
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            throttle_or_429()
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            res = accounts.verify_password_step(get_db(), username, password, client_ip(), cfg)
            if not res.ok:
                flash(res.message, "error")
                return render_template("login.html", username=username)
            user = db.get_user_by_id(get_db(), res.user_id)
            sessions.start_pending_2fa(res.user_id)
            if not user["totp_confirmed"]:
                # Registrado pero sin 2FA: forzamos a completar el enrolamiento.
                enroll_data = accounts.start_enrollment(get_db(), res.user_id, cfg)
                session["enrolling"] = res.user_id
                session["enroll_uri"] = enroll_data["uri"]
                session["enroll_secret"] = enroll_data["secret_b32"]
                return redirect(url_for("enroll"))
            return redirect(url_for("two_factor"))
        return render_template("login.html", username="")

    @app.route("/2fa", methods=["GET", "POST"])
    def two_factor():
        user_id = sessions.pending_user_id()
        if user_id is None:
            return redirect(url_for("login"))
        if request.method == "POST":
            throttle_or_429()
            code = (request.form.get("code") or "").strip()
            res = accounts.verify_totp_step(get_db(), user_id, code, client_ip(), cfg)
            if not res.ok:
                flash(res.message, "error")
                return render_template("twofa.html")
            sessions.complete_login(user_id)
            flash("Sesión iniciada correctamente.", "success")
            return redirect(url_for("index"))
        return render_template("twofa.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        sessions.logout()
        flash("Sesión cerrada.", "success")
        return redirect(url_for("login"))

    return app


def _qr_data_uri(text: str) -> str:
    """Genera el QR del otpauth:// en el servidor y lo embebe como data URI PNG."""
    if not text:
        return ""
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
