"""Capa de acceso a datos sobre SQLite.

Todas las consultas usan parámetros enlazados (`?`) en lugar de interpolar strings,
de modo que la entrada del usuario nunca se concatena en el SQL -> defensa contra
inyección SQL.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    UNIQUE NOT NULL,
    password_hash     BLOB    NOT NULL,
    totp_secret_enc   BLOB,                          -- secreto TOTP CIFRADO (NULL hasta enrolar)
    totp_confirmed    INTEGER NOT NULL DEFAULT 0,    -- 1 cuando el usuario confirmó su app
    last_totp_counter INTEGER NOT NULL DEFAULT -1,   -- anti-replay: último paso consumido
    failed_password   INTEGER NOT NULL DEFAULT 0,
    failed_totp       INTEGER NOT NULL DEFAULT 0,
    locked_until      REAL    NOT NULL DEFAULT 0,     -- timestamp unix hasta el que está bloqueada
    created_at        REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    code_hash TEXT    NOT NULL,                       -- sha256(salt || code) en hex
    salt      TEXT    NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS login_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip       TEXT,
    event    TEXT NOT NULL,
    ts       REAL NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    """Abre una conexión con row_factory y claves foráneas activadas."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str) -> None:
    """Crea las tablas si no existen."""
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Usuarios
# --------------------------------------------------------------------------- #
def create_user(conn: sqlite3.Connection, username: str, password_hash: bytes) -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, time.time()),
    )
    conn.commit()
    return int(cur.lastrowid)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def set_totp_secret(conn: sqlite3.Connection, user_id: int, secret_enc: bytes) -> None:
    conn.execute(
        "UPDATE users SET totp_secret_enc = ?, totp_confirmed = 0 WHERE id = ?",
        (secret_enc, user_id),
    )
    conn.commit()


def confirm_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET totp_confirmed = 1 WHERE id = ?", (user_id,))
    conn.commit()


def update_last_counter(conn: sqlite3.Connection, user_id: int, counter: int) -> None:
    conn.execute(
        "UPDATE users SET last_totp_counter = ? WHERE id = ?", (counter, user_id)
    )
    conn.commit()


def set_lockout(
    conn: sqlite3.Connection,
    user_id: int,
    failed_password: int,
    failed_totp: int,
    locked_until: float,
) -> None:
    conn.execute(
        "UPDATE users SET failed_password = ?, failed_totp = ?, locked_until = ? WHERE id = ?",
        (failed_password, failed_totp, locked_until, user_id),
    )
    conn.commit()


def reset_counters(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE users SET failed_password = 0, failed_totp = 0, locked_until = 0 WHERE id = ?",
        (user_id,),
    )
    conn.commit()


# --------------------------------------------------------------------------- #
# Códigos de respaldo
# --------------------------------------------------------------------------- #
def add_backup_code(
    conn: sqlite3.Connection, user_id: int, code_hash: str, salt: str
) -> None:
    conn.execute(
        "INSERT INTO backup_codes (user_id, code_hash, salt) VALUES (?, ?, ?)",
        (user_id, code_hash, salt),
    )
    conn.commit()


def delete_backup_codes(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    conn.commit()


def get_unused_backup_codes(
    conn: sqlite3.Connection, user_id: int
) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM backup_codes WHERE user_id = ? AND used = 0", (user_id,)
    ).fetchall()


def mark_backup_code_used(conn: sqlite3.Connection, code_id: int) -> None:
    conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (code_id,))
    conn.commit()


# --------------------------------------------------------------------------- #
# Auditoría
# --------------------------------------------------------------------------- #
def log_event(
    conn: sqlite3.Connection, username: str | None, ip: str | None, event: str
) -> None:
    conn.execute(
        "INSERT INTO login_events (username, ip, event, ts) VALUES (?, ?, ?, ?)",
        (username, ip, event, time.time()),
    )
    conn.commit()
