"""Configuración del sistema.

Lee parámetros desde variables de entorno con valores por defecto seguros.
Para facilitar la demo local, si no existen las claves secretas las genera y
persiste en `instance/dev_secrets.json` (solo desarrollo).
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DEV_SECRETS_FILE = INSTANCE_DIR / "dev_secrets.json"


def _load_or_create_dev_secrets() -> dict:
    """Carga (o crea) claves efímeras de desarrollo persistidas en instance/."""
    INSTANCE_DIR.mkdir(exist_ok=True)
    if DEV_SECRETS_FILE.exists():
        return json.loads(DEV_SECRETS_FILE.read_text())
    data = {
        "APP_SECRET_KEY": secrets.token_hex(32),
        "TOTP_MASTER_KEY": Fernet.generate_key().decode("ascii"),
    }
    DEV_SECRETS_FILE.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(DEV_SECRETS_FILE, 0o600)
    except OSError:
        pass
    return data


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    """Configuración resuelta a partir del entorno."""

    def __init__(self) -> None:
        app_key = os.environ.get("APP_SECRET_KEY")
        master_key = os.environ.get("TOTP_MASTER_KEY")

        self.dev_keys_in_use = False
        if not app_key or not master_key:
            self.dev_keys_in_use = True
            dev = _load_or_create_dev_secrets()
            app_key = app_key or dev["APP_SECRET_KEY"]
            master_key = master_key or dev["TOTP_MASTER_KEY"]

        # --- Secretos ---
        self.SECRET_KEY = app_key
        self.TOTP_MASTER_KEY = (
            master_key.encode("ascii") if isinstance(master_key, str) else master_key
        )

        # --- Base de datos ---
        self.DB_PATH = os.environ.get("DB_PATH", str(INSTANCE_DIR / "auth.db"))

        # --- Parámetros TOTP ---
        self.TOTP_DIGITS = _env_int("TOTP_DIGITS", 6)
        self.TOTP_PERIOD = _env_int("TOTP_PERIOD", 30)
        self.TOTP_ALGORITHM = os.environ.get("TOTP_ALGORITHM", "sha1")
        self.TOTP_WINDOW = _env_int("TOTP_WINDOW", 1)  # ±1 paso (±30 s) de tolerancia
        self.ISSUER = os.environ.get("TOTP_ISSUER", "IIC2531-AuthDemo")

        # --- Bloqueo por fuerza bruta (lockout con backoff exponencial) ---
        self.MAX_PASSWORD_ATTEMPTS = _env_int("MAX_PASSWORD_ATTEMPTS", 5)
        self.MAX_TOTP_ATTEMPTS = _env_int("MAX_TOTP_ATTEMPTS", 5)
        self.LOCKOUT_BASE_SECONDS = _env_int("LOCKOUT_BASE_SECONDS", 30)
        self.LOCKOUT_CAP_SECONDS = _env_int("LOCKOUT_CAP_SECONDS", 900)

        # --- Hashing de contraseñas ---
        self.BCRYPT_ROUNDS = _env_int("BCRYPT_ROUNDS", 12)

        # --- Sesión / cookies ---
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        # En HTTP local debe ser False; en HTTPS de producción, True.
        self.SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
        self.PERMANENT_SESSION_LIFETIME = _env_int("SESSION_LIFETIME", 1800)

        # Cantidad de códigos de respaldo a generar al enrolar el TOTP.
        self.BACKUP_CODE_COUNT = _env_int("BACKUP_CODE_COUNT", 10)

    def as_flask_dict(self) -> dict:
        """Subconjunto de claves que Flask reconoce directamente en app.config."""
        return {
            "SECRET_KEY": self.SECRET_KEY,
            "SESSION_COOKIE_HTTPONLY": self.SESSION_COOKIE_HTTPONLY,
            "SESSION_COOKIE_SAMESITE": self.SESSION_COOKIE_SAMESITE,
            "SESSION_COOKIE_SECURE": self.SESSION_COOKIE_SECURE,
            "PERMANENT_SESSION_LIFETIME": self.PERMANENT_SESSION_LIFETIME,
        }
