"""Implementación de HOTP (RFC 4226) y TOTP (RFC 6238) desde cero.

Se usa solo la librería estándar (`hmac`, `hashlib`, `struct`, `base64`, `secrets`)
para mostrar explícitamente cómo se construye el algoritmo, en lugar de delegar en
una librería de alto nivel como `pyotp`.

Referencias:
- RFC 4226  HOTP: An HMAC-Based One-Time Password Algorithm.
- RFC 6238  TOTP: Time-Based One-Time Password Algorithm.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

# Tamaño recomendado del secreto compartido. RFC 4226 §4 R6 recomienda al menos
# 128 bits y sugiere 160 bits (20 bytes) para HMAC-SHA1.
DEFAULT_SECRET_BYTES = 20


def generate_secret(num_bytes: int = DEFAULT_SECRET_BYTES) -> bytes:
    """Genera un secreto compartido aleatorio con un CSPRNG (`secrets`)."""
    return secrets.token_bytes(num_bytes)


def b32encode(secret: bytes) -> str:
    """Codifica el secreto en Base32 sin relleno (formato que esperan las apps)."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def b32decode(secret_b32: str) -> bytes:
    """Decodifica Base32 tolerando espacios, minúsculas y relleno ausente."""
    cleaned = secret_b32.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding)


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    """HOTP(K, C) según RFC 4226.

    Pasos:
      1. HS = HMAC(K, C)  con C empaquetado como entero big-endian de 8 bytes.
      2. Truncación dinámica: offset = HS[-1] & 0x0F; se toman 4 bytes desde offset
         y se descarta el bit más significativo (máscara 0x7FFFFFFF).
      3. code = (entero de 31 bits) mod 10^digits, con relleno de ceros a la izquierda.
    """
    if counter < 0:
        raise ValueError("El contador HOTP no puede ser negativo")
    msg = struct.pack(">Q", counter)
    digestmod = getattr(hashlib, algorithm)
    mac = hmac.new(secret, msg, digestmod).digest()

    offset = mac[-1] & 0x0F
    truncated = (
        (mac[offset] & 0x7F) << 24
        | (mac[offset + 1] & 0xFF) << 16
        | (mac[offset + 2] & 0xFF) << 8
        | (mac[offset + 3] & 0xFF)
    )
    return str(truncated % (10 ** digits)).zfill(digits)


def timecode(for_time: float | None = None, period: int = 30) -> int:
    """Número de paso de tiempo T = floor((unix_time - T0) / period), con T0 = 0."""
    if for_time is None:
        for_time = time.time()
    return int(for_time // period)


def totp(
    secret: bytes,
    for_time: float | None = None,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """TOTP(K) = HOTP(K, T) según RFC 6238, donde T es el paso de tiempo actual."""
    return hotp(secret, timecode(for_time, period), digits, algorithm)


def verify(
    secret: bytes,
    code: str,
    for_time: float | None = None,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    window: int = 1,
) -> int | None:
    """Verifica un código TOTP tolerando desfase de reloj de ±`window` pasos.

    Devuelve el número de paso (`counter`) que coincidió, o `None` si ninguno coincide.
    Devolver el contador permite al llamador implementar anti-replay (rechazar reuso
    de un código de un paso ya consumido).

    La comparación usa `hmac.compare_digest` para evitar fugas por canal de tiempo
    (timing attack): el tiempo de comparación no depende de en qué dígito difieren.
    """
    if for_time is None:
        for_time = time.time()
    base = timecode(for_time, period)
    code = str(code).strip()
    matched: int | None = None
    # Recorremos TODA la ventana (sin cortar al primer acierto) para que el tiempo
    # total tampoco dependa de la posición del paso correcto.
    for offset in range(-window, window + 1):
        counter = base + offset
        if counter < 0:
            continue
        candidate = hotp(secret, counter, digits, algorithm)
        if hmac.compare_digest(candidate, code):
            matched = counter
    return matched


def provisioning_uri(
    secret_b32: str,
    account_name: str,
    issuer: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """Construye la URI `otpauth://` que consumen Google/Microsoft Authenticator.

    Formato: otpauth://totp/ISSUER:cuenta?secret=...&issuer=...&algorithm=...&digits=...&period=...
    """
    # El separador ":" entre issuer y cuenta se mantiene literal (formato Key URI de
    # Google); cada parte se codifica por separado.
    label = f"{quote(issuer)}:{quote(account_name)}"
    params = {
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": period,
    }
    return f"otpauth://totp/{label}?{urlencode(params)}"
