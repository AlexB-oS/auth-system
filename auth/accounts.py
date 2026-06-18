"""Orquestación del registro y del login en dos pasos.

Flujo de login (defensa en profundidad):
  Paso 1: usuario + contraseña  -> verify_password (bcrypt)
  Paso 2: código TOTP de 6 dígitos -> verify (HMAC-SHA1) con ventana ±1 y ANTI-REPLAY
          (o, alternativamente, un código de respaldo de un solo uso)

Cada paso respeta el lockout por fuerza bruta y registra eventos de auditoría.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from . import crypto, db, ratelimit, recovery, totp

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN = 8


@dataclass
class Result:
    ok: bool
    code: str          # identificador de estado, p.ej. "ok", "bad_credentials", "locked"
    message: str       # mensaje apto para mostrar al usuario (uniforme, sin filtrar info)
    user_id: int | None = None
    retry_after: float = 0.0
    backup_codes: list[str] | None = None  # solo se rellena al confirmar el enrolamiento


# Mensaje uniforme para no revelar si el usuario existe o si fue la contraseña/2FA.
_GENERIC_LOGIN_ERROR = "Credenciales inválidas."


def validate_registration(username: str, password: str) -> str | None:
    """Devuelve un mensaje de error de validación, o None si es válido."""
    if not USERNAME_RE.match(username or ""):
        return "El usuario debe tener 3-32 caracteres: letras, números, '_', '.', '-'."
    if len(password or "") < MIN_PASSWORD_LEN:
        return f"La contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres."
    if len(password.encode("utf-8")) > 72:
        # bcrypt trunca a 72 bytes; lo rechazamos explícitamente para evitar sorpresas.
        return "La contraseña es demasiado larga (máximo 72 bytes)."
    return None


def register(conn, username: str, password: str, config) -> Result:
    """Crea una cuenta nueva (sin TOTP todavía)."""
    err = validate_registration(username, password)
    if err:
        return Result(False, "invalid", err)
    if db.get_user_by_username(conn, username) is not None:
        return Result(False, "exists", "Ese nombre de usuario ya está en uso.")
    pw_hash = crypto.hash_password(password, rounds=config.BCRYPT_ROUNDS)
    user_id = db.create_user(conn, username, pw_hash)
    db.log_event(conn, username, None, "register")
    return Result(True, "ok", "Cuenta creada.", user_id=user_id)


def start_enrollment(conn, user_id: int, config) -> dict:
    """Genera un secreto TOTP, lo cifra, lo guarda y devuelve datos para el QR."""
    user = db.get_user_by_id(conn, user_id)
    vault = crypto.SecretVault(config.TOTP_MASTER_KEY)
    secret = totp.generate_secret()
    db.set_totp_secret(conn, user_id, vault.encrypt(secret))
    secret_b32 = totp.b32encode(secret)
    uri = totp.provisioning_uri(
        secret_b32,
        account_name=user["username"],
        issuer=config.ISSUER,
        digits=config.TOTP_DIGITS,
        period=config.TOTP_PERIOD,
        algorithm=config.TOTP_ALGORITHM,
    )
    return {"secret_b32": secret_b32, "uri": uri}


def confirm_enrollment(conn, user_id: int, code: str, config) -> Result:
    """Confirma que el usuario configuró su app verificando un primer código.

    Solo tras confirmar se generan los códigos de respaldo y se marca el TOTP activo.
    """
    user = db.get_user_by_id(conn, user_id)
    if user is None or user["totp_secret_enc"] is None:
        return Result(False, "no_secret", "No hay un secreto TOTP pendiente.")
    vault = crypto.SecretVault(config.TOTP_MASTER_KEY)
    secret = vault.decrypt(user["totp_secret_enc"])
    matched = totp.verify(
        secret,
        code,
        period=config.TOTP_PERIOD,
        digits=config.TOTP_DIGITS,
        algorithm=config.TOTP_ALGORITHM,
        window=config.TOTP_WINDOW,
    )
    if matched is None:
        return Result(False, "bad_code", "El código no es válido. Intenta de nuevo.")
    db.confirm_totp(conn, user_id)
    db.update_last_counter(conn, user_id, matched)  # anti-replay desde el primer uso
    # Los códigos en claro solo existen aquí; se devuelven para mostrarlos una vez.
    codes = recovery.generate_codes(conn, user_id, count=config.BACKUP_CODE_COUNT)
    db.log_event(conn, user["username"], None, "totp_enrolled")
    return Result(True, "ok", "Segundo factor activado.", user_id=user_id, backup_codes=codes)


def verify_password_step(conn, username: str, password: str, ip: str, config) -> Result:
    """Paso 1 del login: verifica la contraseña."""
    user = db.get_user_by_username(conn, username)

    if user is None:
        # Igualamos el costo/tiempo para no revelar que el usuario no existe.
        crypto.dummy_verify(password)
        db.log_event(conn, username, ip, "login_unknown_user")
        return Result(False, "bad_credentials", _GENERIC_LOGIN_ERROR)

    locked, retry = ratelimit.is_locked(user)
    if locked:
        db.log_event(conn, username, ip, "login_locked")
        return Result(
            False, "locked",
            f"Cuenta temporalmente bloqueada. Reintenta en {int(retry) + 1} s.",
            retry_after=retry,
        )

    if not crypto.verify_password(password, user["password_hash"]):
        ratelimit.register_password_failure(conn, user, config)
        db.log_event(conn, username, ip, "login_bad_password")
        return Result(False, "bad_credentials", _GENERIC_LOGIN_ERROR)

    # Contraseña correcta. No reseteamos contadores aún: el login no termina hasta el 2FA.
    db.log_event(conn, username, ip, "login_password_ok")
    return Result(True, "password_ok", "Contraseña correcta.", user_id=user["id"])


def verify_totp_step(conn, user_id: int, code: str, ip: str, config) -> Result:
    """Paso 2 del login: verifica el código TOTP (con anti-replay) o uno de respaldo."""
    user = db.get_user_by_id(conn, user_id)
    if user is None:
        return Result(False, "bad_credentials", _GENERIC_LOGIN_ERROR)

    locked, retry = ratelimit.is_locked(user)
    if locked:
        db.log_event(conn, user["username"], ip, "totp_locked")
        return Result(
            False, "locked",
            f"Cuenta temporalmente bloqueada. Reintenta en {int(retry) + 1} s.",
            retry_after=retry,
        )

    if not user["totp_confirmed"]:
        return Result(False, "no_totp", "Esta cuenta no tiene segundo factor activo.")

    vault = crypto.SecretVault(config.TOTP_MASTER_KEY)
    secret = vault.decrypt(user["totp_secret_enc"])
    matched = totp.verify(
        secret,
        code,
        period=config.TOTP_PERIOD,
        digits=config.TOTP_DIGITS,
        algorithm=config.TOTP_ALGORITHM,
        window=config.TOTP_WINDOW,
    )

    if matched is not None:
        # --- ANTI-REPLAY: el paso usado debe ser estrictamente mayor al último consumido.
        if matched <= int(user["last_totp_counter"]):
            db.log_event(conn, user["username"], ip, "totp_replay_rejected")
            return Result(False, "replay", "Ese código ya fue utilizado.")
        db.update_last_counter(conn, user_id, matched)
        ratelimit.reset(conn, user_id)
        db.log_event(conn, user["username"], ip, "login_success")
        return Result(True, "ok", "Autenticación completada.", user_id=user_id)

    # ¿Será un código de respaldo?
    if recovery.verify_and_consume(conn, user_id, code):
        ratelimit.reset(conn, user_id)
        db.log_event(conn, user["username"], ip, "login_success_backup")
        return Result(True, "ok", "Autenticación completada (código de respaldo).", user_id=user_id)

    ratelimit.register_totp_failure(conn, user, config)
    db.log_event(conn, user["username"], ip, "totp_bad_code")
    return Result(False, "bad_code", "Código de verificación inválido.")


def current_totp_for_user(conn, user_id: int, config, for_time: float | None = None) -> str | None:
    """Utilidad de demo/test: devuelve el código TOTP actual de un usuario.

    SOLO para los scripts de experimentos y tests locales (necesitan conocer el
    código válido para simular un login legítimo o un replay). No se expone por HTTP.
    """
    user = db.get_user_by_id(conn, user_id)
    if user is None or user["totp_secret_enc"] is None:
        return None
    vault = crypto.SecretVault(config.TOTP_MASTER_KEY)
    secret = vault.decrypt(user["totp_secret_enc"])
    return totp.totp(
        secret,
        for_time=for_time if for_time is not None else time.time(),
        period=config.TOTP_PERIOD,
        digits=config.TOTP_DIGITS,
        algorithm=config.TOTP_ALGORITHM,
    )
