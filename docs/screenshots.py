"""Captura screenshots de la interfaz para el informe y las slides.

Levanta una app Flask de *vista previa* (rutas /p/*) que renderiza las MISMAS
plantillas reales con datos de ejemplo (sin requerir login), y usa Chrome headless
para capturar cada página. Si no encuentra un Chrome utilizable, genera al menos el
código QR real (sin navegador) para tener un recurso visual del 2FA.

Salida: docs/figuras/shot_*.png
"""

from __future__ import annotations

import base64
import glob
import io
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qrcode  # noqa: E402
from PIL import Image  # noqa: E402
from flask import Flask, render_template  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from auth import totp  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "docs", "figuras")
os.makedirs(FIG, exist_ok=True)

SAMPLE_SECRET_B32 = totp.b32encode(b"ProyectoIIC2531-demo")  # secreto de ejemplo
SAMPLE_URI = totp.provisioning_uri(SAMPLE_SECRET_B32, "alex", "IIC2531-AuthDemo")
SAMPLE_CODES = ["AB7KD-MN3PQ", "R9X2T-7HJKL", "ZQ4MW-N8B3C", "K2P7D-XR9TY", "M5H8J-LQ2WZ",
                "T3N6B-VK9XR", "P8L2M-DH7QJ", "W4R9K-2BNXT", "Y7Q3Z-MK8PL", "C9V5X-RT2HN"]


def _qr_data_uri(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def build_preview_app() -> Flask:
    app = Flask(
        "preview",
        template_folder=os.path.join(ROOT, "templates"),
        static_folder=os.path.join(ROOT, "static"),
    )
    app.secret_key = "preview"

    @app.context_processor
    def inject():
        return {"csrf_token": lambda: "preview-csrf-token"}

    # Endpoints con los nombres que esperan las plantillas (url_for).
    @app.route("/")
    def index():
        return render_template("dashboard.html", username="alex")

    @app.route("/login", endpoint="login")
    def login():
        return render_template("login.html", username="")

    @app.route("/register", endpoint="register")
    def register():
        return render_template("register.html", username="")

    @app.route("/2fa", endpoint="two_factor")
    def two_factor():
        return render_template("twofa.html")

    @app.route("/logout", endpoint="logout")
    def logout():
        return render_template("login.html", username="")

    @app.route("/enroll", endpoint="enroll")
    def enroll():
        return render_template("enroll.html", secret=SAMPLE_SECRET_B32, qr=_qr_data_uri(SAMPLE_URI))

    @app.route("/backup")
    def backup():
        return render_template("backup_codes.html", codes=SAMPLE_CODES)

    return app


def autocrop(path: str, pad: int = 18) -> None:
    """Recorta los márgenes oscuros dejando la tarjeta de la UI (recurso denso)."""
    try:
        im = Image.open(path).convert("RGB")
    except Exception:
        return
    gray = im.convert("L")
    # La tarjeta es blanca y el texto de cabecera es claro; el fondo es azul oscuro.
    mask = gray.point(lambda p: 255 if p > 170 else 0)
    bbox = mask.getbbox()
    if not bbox:
        return
    l, t, r, b = bbox
    l = max(0, l - pad); t = max(0, t - pad)
    r = min(im.width, r + pad); b = min(im.height, b + pad)
    im.crop((l, t, r, b)).save(path)


def find_chrome() -> str | None:
    pats = [
        os.path.join(ROOT, ".cache-browser", "**", "chrome"),
        os.path.expanduser("~/.cache/puppeteer/**/chrome"),
    ]
    for p in pats:
        hits = [h for h in glob.glob(p, recursive=True) if os.path.isfile(h) and os.access(h, os.X_OK)]
        if hits:
            return hits[0]
    for name in ("google-chrome", "chromium", "chromium-browser"):
        from shutil import which

        if which(name):
            return which(name)
    return None


def main():
    chrome = find_chrome()

    # Siempre generamos el QR real como recurso independiente.
    qrcode.make(SAMPLE_URI).save(os.path.join(FIG, "shot_qr.png"))

    if not chrome:
        print("[screenshots] No se encontró Chrome; solo se generó shot_qr.png")
        return

    # Limpia instancias de Chrome colgadas de corridas previas (best-effort).
    # Coincidencia EXACTA por nombre de proceso (-x): no toca este proceso de Python.
    subprocess.run(["pkill", "-9", "-x", "chrome"], capture_output=True)

    app = build_preview_app()
    srv = make_server("127.0.0.1", 0, app, threaded=True)  # puerto efímero; multihilo para assets
    port = srv.socket.getsockname()[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(1.0)

    base = f"http://127.0.0.1:{port}"
    pages = {
        "shot_login": f"{base}/login",
        "shot_register": f"{base}/register",
        "shot_enroll": f"{base}/enroll",
        "shot_2fa": f"{base}/2fa",
        "shot_backup": f"{base}/backup",
        "shot_dashboard": f"{base}/",
    }
    try:
        for name, url in pages.items():
            out = os.path.join(FIG, name + ".png")
            if os.path.exists(out):
                os.remove(out)  # evita falsos "ok" por archivos previos
            try:
                # Conjunto mínimo de flags: es el que funciona de forma fiable aquí.
                # (--user-data-dir / --disable-dev-shm-usage hacían colgar la carga HTTP.)
                # Viewport angosto (tipo móvil) para que la tarjeta llene el ancho.
                subprocess.run(
                    [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                     "--hide-scrollbars", "--force-device-scale-factor=2",
                     "--window-size=470,1250", f"--screenshot={out}", url],
                    check=False, capture_output=True, timeout=40,
                )
            except subprocess.TimeoutExpired:
                pass
            ok = os.path.exists(out)
            if ok:
                autocrop(out)  # recorta márgenes oscuros -> captura densa
            print(f"[screenshots] {name}: {'ok' if ok else 'FALLO'}")
    finally:
        srv.shutdown()
    print(f"[screenshots] Listas en {FIG}")


if __name__ == "__main__":
    main()
