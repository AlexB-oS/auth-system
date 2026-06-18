"""Paquete de autenticación: contraseña (bcrypt) + segundo factor TOTP (RFC 6238).

Módulos:
- totp:     implementación HOTP/TOTP desde cero (hmac + hashlib).
- crypto:   hashing de contraseñas (bcrypt) y cifrado autenticado del secreto TOTP.
- db:       acceso a SQLite con consultas parametrizadas.
- ratelimit:bloqueo de cuentas con backoff exponencial (anti fuerza bruta).
- recovery: códigos de respaldo de un solo uso.
- accounts: orquestación del registro y del login en dos pasos (con anti-replay).
- sessions: configuración segura de sesión y protección CSRF.
"""
