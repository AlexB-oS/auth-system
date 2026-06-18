"""Bloqueo de cuentas (lockout) con backoff exponencial y throttle por IP.

Mitiga ataques de fuerza bruta online: en lugar de permitir intentos ilimitados a
gran velocidad, tras unos pocos fallos la cuenta queda bloqueada por un tiempo que
crece exponencialmente. Esto reduce drásticamente la tasa efectiva de adivinación.
"""

from __future__ import annotations

import threading
import time

from . import db


def is_locked(user_row, now: float | None = None) -> tuple[bool, float]:
    """Indica si la cuenta está bloqueada y cuántos segundos faltan."""
    if now is None:
        now = time.time()
    locked_until = float(user_row["locked_until"])
    if locked_until > now:
        return True, locked_until - now
    return False, 0.0


def _backoff_seconds(extra_failures: int, base: int, cap: int) -> float:
    """base * 2^(extra_failures); acotado por `cap`."""
    return float(min(base * (2 ** max(0, extra_failures)), cap))


def register_password_failure(conn, user_row, config, now: float | None = None) -> None:
    """Registra un fallo de contraseña y aplica lockout si corresponde."""
    if now is None:
        now = time.time()
    failed = int(user_row["failed_password"]) + 1
    locked_until = float(user_row["locked_until"])
    if failed >= config.MAX_PASSWORD_ATTEMPTS:
        extra = failed - config.MAX_PASSWORD_ATTEMPTS
        locked_until = now + _backoff_seconds(
            extra, config.LOCKOUT_BASE_SECONDS, config.LOCKOUT_CAP_SECONDS
        )
    db.set_lockout(conn, user_row["id"], failed, user_row["failed_totp"], locked_until)


def register_totp_failure(conn, user_row, config, now: float | None = None) -> None:
    """Registra un fallo de segundo factor y aplica lockout si corresponde."""
    if now is None:
        now = time.time()
    failed = int(user_row["failed_totp"]) + 1
    locked_until = float(user_row["locked_until"])
    if failed >= config.MAX_TOTP_ATTEMPTS:
        extra = failed - config.MAX_TOTP_ATTEMPTS
        locked_until = now + _backoff_seconds(
            extra, config.LOCKOUT_BASE_SECONDS, config.LOCKOUT_CAP_SECONDS
        )
    db.set_lockout(conn, user_row["id"], user_row["failed_password"], failed, locked_until)


def reset(conn, user_id: int) -> None:
    """Limpia contadores tras un login exitoso."""
    db.reset_counters(conn, user_id)


class IPThrottle:
    """Throttle simple por IP basado en ventana deslizante (en memoria, por proceso).

    Limitación conocida y documentada: al ser en memoria no sirve en despliegues
    multi-proceso/multi-host; ahí se usaría un store compartido (p.ej. Redis).
    """

    def __init__(self, max_hits: int = 20, window_seconds: int = 60):
        self.max_hits = max_hits
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        with self._lock:
            bucket = [t for t in self._hits.get(ip, []) if now - t < self.window]
            bucket.append(now)
            self._hits[ip] = bucket
            return len(bucket) <= self.max_hits
