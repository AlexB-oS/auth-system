"""E5 — Ataque de repetición (replay) del código TOTP.

Un código TOTP es válido durante toda su ventana (~30-90 s). Si un atacante observa
un código válido (p.ej. por encima del hombro, o un proxy malicioso) podría reusarlo
mientras siga vigente. Mitigación: recordar el último paso de tiempo consumido por
usuario y rechazar cualquier código de un paso <= al último usado.

Este script demuestra:
  1. Un login legítimo con un código válido -> ÉXITO.
  2. La REPETICIÓN del mismo código en la misma ventana -> RECHAZADO (anti-replay).

Salida: experiments/results/replay.log
"""

from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.fernet import Fernet  # noqa: E402

RESULTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results"
)
os.makedirs(RESULTS, exist_ok=True)


def main():
    os.environ.setdefault("APP_SECRET_KEY", "replay-demo")
    os.environ["TOTP_MASTER_KEY"] = Fernet.generate_key().decode()
    os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "replay.db")
    from config import Config
    from auth import accounts, db

    cfg = Config()
    db.init_db(cfg.DB_PATH)
    conn = db.connect(cfg.DB_PATH)

    lines = []

    def log(msg):
        print(msg)
        lines.append(msg)

    t0 = 1_700_000_000
    uid = accounts.register(conn, "alex", "PasswordSegura1", cfg).user_id
    accounts.start_enrollment(conn, uid, cfg)
    enroll_code = accounts.current_totp_for_user(conn, uid, cfg, for_time=t0)
    with mock.patch("time.time", return_value=float(t0)):
        accounts.confirm_enrollment(conn, uid, enroll_code, cfg)
    log(f"[setup] Usuario 'alex' enrolado en t0={t0} (paso {t0 // cfg.TOTP_PERIOD}).")

    # Login legítimo en el siguiente paso de tiempo.
    t1 = t0 + cfg.TOTP_PERIOD
    code = accounts.current_totp_for_user(conn, uid, cfg, for_time=t1)
    log(f"\n[1] Login legítimo en t1={t1} con código {code} (paso {t1 // cfg.TOTP_PERIOD}):")
    with mock.patch("time.time", return_value=float(t1)):
        res1 = accounts.verify_totp_step(conn, uid, code, "1.2.3.4", cfg)
    log(f"    -> ok={res1.ok}  code={res1.code}  msg={res1.message!r}")
    assert res1.ok

    # Replay: el MISMO código, en la MISMA ventana de tiempo.
    log(f"\n[2] Replay del MISMO código {code} en la misma ventana (t1+5s):")
    with mock.patch("time.time", return_value=float(t1 + 5)):
        res2 = accounts.verify_totp_step(conn, uid, code, "9.9.9.9", cfg)
    log(f"    -> ok={res2.ok}  code={res2.code}  msg={res2.message!r}")
    assert (not res2.ok) and res2.code == "replay"

    log("\n[RESULTADO] El replay fue rechazado por el control anti-replay "
        "(last_totp_counter). ✔")

    conn.close()
    with open(os.path.join(RESULTS, "replay.log"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
