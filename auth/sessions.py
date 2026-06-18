"""Helpers de sesión segura y protección CSRF.

- La sesión de Flask viaja en una cookie FIRMADA (HMAC con SECRET_KEY) marcada como
  HttpOnly y SameSite=Lax (y Secure en HTTPS). El cliente no puede manipularla.
- El login de dos pasos guarda el estado intermedio en el servidor (en la sesión):
  primero `pending_2fa` (contraseña OK) y solo al validar el TOTP se promueve a
  `user_id` (sesión autenticada). Tras autenticar se REGENERA la sesión para evitar
  fijación de sesión (session fixation).
- CSRF: token aleatorio por sesión, exigido en todos los POST.
"""

from __future__ import annotations

import hmac
import secrets

from flask import session


def get_csrf_token() -> str:
    """Devuelve (creando si hace falta) el token CSRF de la sesión actual."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf(submitted: str | None) -> bool:
    """Compara en tiempo constante el token enviado con el de la sesión."""
    expected = session.get("_csrf_token")
    if not expected or not submitted:
        return False
    return hmac.compare_digest(expected, submitted)


def start_pending_2fa(user_id: int) -> None:
    """Marca que la contraseña fue validada y queda pendiente el segundo factor."""
    session["pending_2fa"] = user_id


def complete_login(user_id: int) -> None:
    """Promueve la sesión a autenticada, regenerando el identificador de sesión."""
    csrf = session.get("_csrf_token")
    session.clear()                       # regeneración: descarta el estado anterior
    session["user_id"] = user_id
    session["_csrf_token"] = csrf or secrets.token_urlsafe(32)
    session.permanent = True


def logout() -> None:
    session.clear()


def current_user_id() -> int | None:
    return session.get("user_id")


def pending_user_id() -> int | None:
    return session.get("pending_2fa")
