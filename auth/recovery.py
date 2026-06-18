"""Códigos de respaldo (recovery codes) de un solo uso.

Permiten recuperar el acceso si el usuario pierde su dispositivo TOTP.

Decisión de diseño sobre el hashing:
  Los códigos de respaldo se generan con alta entropía (10 hex = 40 bits cada uno,
  con un alfabeto sin caracteres ambiguos). Por eso NO necesitan un hash lento tipo
  bcrypt: un atacante no puede montar un diccionario sobre un espacio de 2^40 por
  cada código. Usamos sha256(salt || code), que es suficiente para secretos de alta
  entropía y mucho más barato cuando hay que comparar contra varios códigos.
  (Para contraseñas, que son de baja entropía, SÍ usamos bcrypt: ver crypto.py.)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from . import db

# Alfabeto sin caracteres ambiguos (sin 0/O, 1/I/l).
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_GROUP = 5  # 5 + 5 caracteres -> ~49 bits de entropía por código


def _random_code() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP * 2))
    return f"{raw[:_GROUP]}-{raw[_GROUP:]}"


def _hash_code(code: str, salt: str) -> str:
    normalized = code.strip().upper().replace(" ", "")
    return hashlib.sha256((salt + normalized).encode("utf-8")).hexdigest()


def generate_codes(conn, user_id: int, count: int = 10) -> list[str]:
    """Genera `count` códigos nuevos, los guarda hasheados y devuelve los planos.

    Los códigos en claro solo se muestran una vez (en el enrolamiento).
    Reemplaza cualquier código previo del usuario.
    """
    db.delete_backup_codes(conn, user_id)
    plain_codes = []
    for _ in range(count):
        code = _random_code()
        salt = secrets.token_hex(16)
        db.add_backup_code(conn, user_id, _hash_code(code, salt), salt)
        plain_codes.append(code)
    return plain_codes


def verify_and_consume(conn, user_id: int, code: str) -> bool:
    """Verifica un código de respaldo y lo marca como usado (un solo uso).

    Recorre todos los códigos no usados comparando en tiempo constante.
    """
    rows = db.get_unused_backup_codes(conn, user_id)
    matched_id = None
    for row in rows:
        candidate = _hash_code(code, row["salt"])
        if hmac.compare_digest(candidate, row["code_hash"]):
            matched_id = row["id"]
    if matched_id is not None:
        db.mark_backup_code_used(conn, matched_id)
        return True
    return False
