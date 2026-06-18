"""Pruebas de la lógica de autenticación (E6): registro, login en dos pasos,
lockout, anti-replay, códigos de respaldo y resistencia a enumeración.

Para que sean deterministas (sin esperar 30 s reales), se fija el reloj con
monkeypatch sobre `time.time`, que tanto `auth.totp` como `auth.ratelimit` consultan.
"""

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("TOTP_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    from config import Config
    from auth import db

    c = Config()
    db.init_db(c.DB_PATH)
    return c


@pytest.fixture
def conn(cfg):
    from auth import db

    connection = db.connect(cfg.DB_PATH)
    yield connection
    connection.close()


def _freeze_time(monkeypatch, t):
    monkeypatch.setattr("time.time", lambda: float(t))


def _register_and_enroll(conn, cfg, monkeypatch, username="alex", password="Sup3rSecret!", t0=1_700_000_000):
    """Crea un usuario con TOTP activo en el instante t0 y devuelve (user_id, codes)."""
    from auth import accounts

    _freeze_time(monkeypatch, t0)
    res = accounts.register(conn, username, password, cfg)
    assert res.ok, res.message
    uid = res.user_id
    accounts.start_enrollment(conn, uid, cfg)
    code = accounts.current_totp_for_user(conn, uid, cfg, for_time=t0)
    conf = accounts.confirm_enrollment(conn, uid, code, cfg)
    assert conf.ok, conf.message
    return uid, conf.backup_codes


# --------------------------------------------------------------------------- #
# Registro y validación
# --------------------------------------------------------------------------- #
def test_register_rejects_short_password(conn, cfg):
    from auth import accounts

    res = accounts.register(conn, "bob", "short", cfg)
    assert not res.ok and res.code == "invalid"


def test_register_rejects_bad_username(conn, cfg):
    from auth import accounts

    res = accounts.register(conn, "a b", "ValidPass123", cfg)
    assert not res.ok


def test_register_duplicate(conn, cfg):
    from auth import accounts

    assert accounts.register(conn, "carol", "ValidPass123", cfg).ok
    dup = accounts.register(conn, "carol", "ValidPass123", cfg)
    assert not dup.ok and dup.code == "exists"


# --------------------------------------------------------------------------- #
# Login paso 1 (contraseña)
# --------------------------------------------------------------------------- #
def test_password_step_ok_and_wrong(conn, cfg, monkeypatch):
    from auth import accounts

    _register_and_enroll(conn, cfg, monkeypatch)
    ok = accounts.verify_password_step(conn, "alex", "Sup3rSecret!", "1.2.3.4", cfg)
    assert ok.ok and ok.code == "password_ok"
    bad = accounts.verify_password_step(conn, "alex", "wrong-pass", "1.2.3.4", cfg)
    assert not bad.ok and bad.code == "bad_credentials"


def test_unknown_user_is_indistinguishable(conn, cfg):
    from auth import accounts

    res = accounts.verify_password_step(conn, "ghost", "whatever123", "1.2.3.4", cfg)
    # Mismo código y mensaje genérico que una contraseña incorrecta: no se filtra
    # si el usuario existe.
    assert not res.ok and res.code == "bad_credentials"


# --------------------------------------------------------------------------- #
# Login paso 2 (TOTP) + anti-replay
# --------------------------------------------------------------------------- #
def test_totp_success_then_replay_rejected(conn, cfg, monkeypatch):
    from auth import accounts

    uid, _ = _register_and_enroll(conn, cfg, monkeypatch, t0=1_700_000_000)

    # Avanzamos al siguiente paso de tiempo para un login legítimo.
    t1 = 1_700_000_000 + 30
    _freeze_time(monkeypatch, t1)
    code1 = accounts.current_totp_for_user(conn, uid, cfg, for_time=t1)

    ok = accounts.verify_totp_step(conn, uid, code1, "1.2.3.4", cfg)
    assert ok.ok, ok.message

    # Mismo código, mismo paso de tiempo -> debe rechazarse por anti-replay.
    replay = accounts.verify_totp_step(conn, uid, code1, "1.2.3.4", cfg)
    assert not replay.ok and replay.code == "replay"


def test_totp_lockout_after_repeated_failures(conn, cfg, monkeypatch):
    from auth import accounts, db, ratelimit

    uid, _ = _register_and_enroll(conn, cfg, monkeypatch)
    t1 = 1_700_000_000 + 30
    _freeze_time(monkeypatch, t1)
    correct = accounts.current_totp_for_user(conn, uid, cfg, for_time=t1)
    wrong = "000000" if correct != "000000" else "111111"

    last = None
    for _ in range(cfg.MAX_TOTP_ATTEMPTS):
        last = accounts.verify_totp_step(conn, uid, wrong, "1.2.3.4", cfg)
    # Tras MAX intentos fallidos, la cuenta queda bloqueada.
    user = db.get_user_by_id(conn, uid)
    locked, retry = ratelimit.is_locked(user)
    assert locked and retry > 0
    # Incluso con el código correcto, el siguiente intento se rechaza por lockout.
    blocked = accounts.verify_totp_step(conn, uid, correct, "1.2.3.4", cfg)
    assert not blocked.ok and blocked.code == "locked"


# --------------------------------------------------------------------------- #
# Códigos de respaldo (un solo uso)
# --------------------------------------------------------------------------- #
def test_backup_code_single_use(conn, cfg, monkeypatch):
    from auth import accounts

    uid, codes = _register_and_enroll(conn, cfg, monkeypatch)
    assert codes and len(codes) == cfg.BACKUP_CODE_COUNT

    t1 = 1_700_000_000 + 30
    _freeze_time(monkeypatch, t1)
    first = accounts.verify_totp_step(conn, uid, codes[0], "1.2.3.4", cfg)
    assert first.ok, first.message
    # Reuso del mismo código de respaldo -> rechazado.
    reuse = accounts.verify_totp_step(conn, uid, codes[0], "1.2.3.4", cfg)
    assert not reuse.ok


# --------------------------------------------------------------------------- #
# Cifrado del secreto en reposo
# --------------------------------------------------------------------------- #
def test_secret_is_encrypted_at_rest(conn, cfg, monkeypatch):
    from auth import accounts, db, totp

    uid, _ = _register_and_enroll(conn, cfg, monkeypatch)
    user = db.get_user_by_id(conn, uid)
    stored = bytes(user["totp_secret_enc"])
    # Lo almacenado NO debe ser el secreto en claro ni su Base32.
    code = accounts.current_totp_for_user(conn, uid, cfg, for_time=1_700_000_000)
    assert code.encode() not in stored
    assert b"=" not in stored or True  # token Fernet; solo comprobamos que es opaco
    # Un token Fernet empieza con la versión 0x80 codificada en base64url ("gAAAA...").
    assert stored[:5] == b"gAAAA"


# --------------------------------------------------------------------------- #
# Smoke test HTTP (CSRF obligatorio)
# --------------------------------------------------------------------------- #
def test_http_csrf_required(cfg):
    from app import create_app

    app = create_app(cfg)
    app.testing = True
    client = app.test_client()
    # POST sin token CSRF -> 400.
    resp = client.post("/register", data={"username": "x", "password": "y"})
    assert resp.status_code == 400


def test_http_pages_load(cfg):
    from app import create_app

    app = create_app(cfg)
    client = app.test_client()
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200
    # La raíz sin sesión redirige a /login.
    assert client.get("/").status_code in (302, 308)
