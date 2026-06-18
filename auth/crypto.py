"""Primitivas criptográficas: hashing de contraseñas y cifrado del secreto TOTP.

Distinción de diseño clave (corrige la propuesta original):

- Las CONTRASEÑAS se almacenan HASHEADAS con bcrypt. Un hash es de una sola vía:
  nunca necesitamos recuperar la contraseña, solo verificarla. bcrypt es lento y
  con sal por hash, lo que encarece los ataques de diccionario/fuerza bruta offline.

- El SECRETO TOTP NO puede hashearse: para verificar un código en cada login hay que
  recomputar HMAC(secreto, T), es decir, necesitamos el secreto en claro en memoria.
  Por eso se CIFRA en reposo con cifrado autenticado (Fernet = AES-128-CBC + HMAC-SHA256)
  bajo una clave maestra que vive fuera de la base de datos. Así, si se filtra solo el
  archivo .db, los secretos siguen protegidos.
"""

from __future__ import annotations

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

DEFAULT_ROUNDS = 12


def hash_password(password: str, rounds: int = DEFAULT_ROUNDS) -> bytes:
    """Hashea una contraseña con bcrypt (sal aleatoria por hash incluida)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))


def verify_password(password: str, hashed: bytes) -> bool:
    """Verifica una contraseña contra su hash bcrypt en tiempo ~constante."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except (ValueError, TypeError):
        return False


# Hash "señuelo" precomputado: cuando alguien intenta loguear un usuario inexistente,
# igual ejecutamos un checkpw contra este hash. Así el costo (y el tiempo) de respuesta
# es similar al de un usuario real -> mitiga la enumeración de usuarios por timing.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt(rounds=DEFAULT_ROUNDS))


def dummy_verify(password: str) -> bool:
    """Ejecuta trabajo bcrypt equivalente y siempre devuelve False."""
    bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
    return False


class SecretVault:
    """Cifra y descifra el secreto TOTP con cifrado autenticado (Fernet)."""

    def __init__(self, master_key: bytes):
        self._fernet = Fernet(master_key)

    def encrypt(self, secret: bytes) -> bytes:
        """Devuelve el ciphertext (token Fernet) listo para guardar en la BD."""
        return self._fernet.encrypt(secret)

    def decrypt(self, token: bytes) -> bytes:
        """Descifra y verifica integridad; lanza InvalidToken si fue manipulado."""
        return self._fernet.decrypt(token)

    @staticmethod
    def generate_key() -> bytes:
        """Genera una clave maestra Fernet (urlsafe base64, 32 bytes)."""
        return Fernet.generate_key()


__all__ = [
    "hash_password",
    "verify_password",
    "dummy_verify",
    "SecretVault",
    "InvalidToken",
]
