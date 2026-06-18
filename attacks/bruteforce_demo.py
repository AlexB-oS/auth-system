"""E4 — Fuerza bruta online del segundo factor vs. bloqueo (lockout).

Un código TOTP de 6 dígitos tiene 10^6 valores; con ventana ±1 paso, en cada
instante hay (2*window+1) códigos aceptados. La probabilidad de acertar un código
al azar es p = (2*window+1)/10^6.

Lo que decide la seguridad real NO es solo p, sino CUÁNTOS intentos por unidad de
tiempo permite el sistema. Simulamos tres escenarios usando la política de lockout
real del proyecto (auth/ratelimit.py):

  1. Sin protección       (solo límite de red, ~50 req/s)
  2. Solo throttle por IP  (20 intentos/min)
  3. Lockout con backoff   (5 intentos, luego 30s,60s,120s,... hasta 900s)

Salida: experiments/results/fig_bruteforce.png, bruteforce.log
"""

from __future__ import annotations

import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

RESULTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results"
)
os.makedirs(RESULTS, exist_ok=True)

HORIZON = 3600.0  # 1 hora
REQUEST_TIME = 0.2  # s por intento (latencia de red simulada)


def _make_config():
    os.environ.setdefault("APP_SECRET_KEY", "bruteforce-demo")
    os.environ["TOTP_MASTER_KEY"] = Fernet.generate_key().decode()
    os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "bf.db")
    from config import Config

    return Config()


def simulate_lockout(cfg) -> list[tuple[float, int]]:
    """Simula al atacante usando la política de lockout REAL (auth/ratelimit.py)."""
    from auth import accounts, db, ratelimit

    db.init_db(cfg.DB_PATH)
    conn = db.connect(cfg.DB_PATH)
    uid = accounts.register(conn, "victima", "PasswordSegura1", cfg).user_id

    now = 0.0
    guesses = 0
    timeline = [(0.0, 0)]
    while now <= HORIZON:
        user = db.get_user_by_id(conn, uid)
        locked, _ = ratelimit.is_locked(user, now)
        if locked:
            now = float(user["locked_until"])  # el atacante espera a que expire
            continue
        guesses += 1
        now += REQUEST_TIME
        timeline.append((now, guesses))
        ratelimit.register_totp_failure(conn, user, cfg, now)
    conn.close()
    return timeline


def simulate_rate(rate_per_hour: float) -> list[tuple[float, int]]:
    """Escenario lineal: `rate_per_hour` intentos uniformemente en la hora."""
    pts = [(0.0, 0)]
    n = int(rate_per_hour)
    for i in range(1, n + 1):
        pts.append((HORIZON * i / n, i))
    return pts


def success_probability(guesses: int, p: float) -> float:
    return 1.0 - (1.0 - p) ** guesses


def main():
    cfg = _make_config()
    window = cfg.TOTP_WINDOW
    digits = cfg.TOTP_DIGITS
    p = (2 * window + 1) / (10 ** digits)

    lockout = simulate_lockout(cfg)
    throttle = simulate_rate(20 * 60)        # 20/min -> 1200/h
    unprotected = simulate_rate(50 * 3600)   # ~50 req/s -> 180000/h

    scenarios = {
        "Sin protección (~50 req/s)": (unprotected, "#dc2626"),
        "Throttle IP (20/min)": (throttle, "#d97706"),
        "Lockout con backoff": (lockout, "#16a34a"),
    }

    fig, ax = plt.subplots(figsize=(8.5, 5))
    log_lines = []
    log_lines.append(f"p (prob. de acierto por intento) = (2*{window}+1)/10^{digits} = {p:.2e}")
    g50 = math.log(2) / p  # intentos para 50% de probabilidad acumulada
    log_lines.append(f"Intentos para 50% de probabilidad de éxito: {g50:,.0f}")
    log_lines.append("")

    for name, (pts, color) in scenarios.items():
        xs = [t / 60 for t, _ in pts]  # minutos
        ys = [g for _, g in pts]
        ax.plot(xs, ys, color=color, label=name, linewidth=2)
        total = ys[-1]
        prob = success_probability(total, p)
        days_to_50 = (g50 / total) * (HORIZON / 86400) if total else float("inf")
        log_lines.append(
            f"{name:32s} intentos/h = {total:8d} | P(éxito en 1h) = {prob:.2e} | "
            f"tiempo esperado a 50% ≈ {days_to_50:,.1f} días"
        )

    ax.set_yscale("log")
    ax.set_xlabel("Tiempo [min]")
    ax.set_ylabel("Intentos acumulados (escala log)")
    ax.set_title("Fuerza bruta online del TOTP: efecto del lockout", fontweight="bold")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    fig.tight_layout()
    out_png = os.path.join(RESULTS, "fig_bruteforce.png")
    fig.savefig(out_png, dpi=140)

    log_text = "\n".join(log_lines)
    with open(os.path.join(RESULTS, "bruteforce.log"), "w") as fh:
        fh.write(log_text + "\n")
    print("[E4] Figura guardada en", out_png)
    print(log_text)


if __name__ == "__main__":
    main()
