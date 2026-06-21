"""Genera los diagramas conceptuales del informe y las slides (matplotlib).

Salidas en docs/figuras/:
  fig_arquitectura.png      arquitectura de componentes
  fig_totp_flujo.png        pipeline del algoritmo TOTP
  fig_login_secuencia.png   diagrama de secuencia del login en dos pasos
  fig_modelo_amenaza.png    modelo de amenaza / fronteras de confianza
"""

from __future__ import annotations

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

FIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figuras")
os.makedirs(FIG, exist_ok=True)

INK = "#1e293b"
EDGE = "#334155"


def rbox(ax, cx, cy, w, h, text, fc="#e0e7ff", ec="#4338ca", fs=10, tc=INK, weight="normal"):
    x, y = cx - w / 2, cy - h / 2
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
            fc=fc, ec=ec, lw=1.6,
        )
    )
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs, color=tc, fontweight=weight)


def arr(ax, x1, y1, x2, y2, text="", color="#475569", style="-|>", off=0.25, fs=8.5):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, lw=1.6, color=color))
    if text:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + off, text, ha="center", va="center",
                fontsize=fs, color="#334155",
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"))


def fig_arquitectura():
    fig, ax = plt.subplots(figsize=(9.5, 6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
    rbox(ax, 5, 9, 5.2, 1.1, "Navegador / Cliente\n(login · QR · código 2FA)", fc="#dbeafe", ec="#1d4ed8")
    rbox(ax, 5, 6.4, 6.2, 1.2, "Servidor Flask  (app.py)\nrutas · CSRF · cabeceras de seguridad",
         fc="#ede9fe", ec="#6d28d9", weight="bold")
    arr(ax, 5, 8.45, 5, 7.05, "HTTP local", off=0.0)
    arr(ax, 5, 7.0, 5, 8.4, "", color="#94a3b8")

    comps = [
        (1.9, "TOTP\n(totp.py)\nHMAC-SHA1", "#dcfce7", "#15803d"),
        (4.0, "Crypto\n(crypto.py)\nbcrypt + Vault", "#fef9c3", "#a16207"),
        (6.0, "RateLimiter\n(ratelimit.py)\nlockout", "#ffe4e6", "#be123c"),
        (8.1, "Sesión/CSRF\n(sessions.py)", "#cffafe", "#0e7490"),
    ]
    for cx, txt, fc, ec in comps:
        rbox(ax, cx, 4.0, 1.8, 1.3, txt, fc=fc, ec=ec, fs=9)
        arr(ax, 5, 5.78, cx, 4.7, "", color="#94a3b8")

    rbox(ax, 5, 1.4, 8.6, 1.3,
         "SQLite  (db.py) — consultas parametrizadas\n"
         "password_hash · totp_secret_enc (cifrado) · backup_hash · login_events",
         fc="#f1f5f9", ec="#475569", fs=9)
    for cx in (1.9, 4.0, 6.0, 8.1):
        arr(ax, cx, 3.34, cx, 2.08, "", color="#94a3b8")

    ax.set_title("Arquitectura de componentes", fontweight="bold", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig_arquitectura.png"), dpi=140)
    plt.close(fig)


def fig_totp_flujo():
    fig, ax = plt.subplots(figsize=(11, 3.4))
    ax.set_xlim(0, 14); ax.set_ylim(0, 4); ax.axis("off")
    steps = [
        (1.3, "Secreto K\n(Base32)", "#dcfce7", "#15803d"),
        (3.5, "T = ⌊unix/30⌋\n(contador)", "#dbeafe", "#1d4ed8"),
        (6.0, "HMAC-SHA1(K, T)\n→ MAC 20 bytes", "#ede9fe", "#6d28d9"),
        (8.7, "Truncación\ndinámica (RFC 4226)\n→ entero 31 bits", "#fef9c3", "#a16207"),
        (11.3, "mod 10^6", "#ffe4e6", "#be123c"),
        (13.1, "Código\n123456", "#cffafe", "#0e7490"),
    ]
    for cx, txt, fc, ec in steps:
        w = 2.0 if cx not in (11.3, 13.1) else 1.5
        rbox(ax, cx, 2, w, 1.5, txt, fc=fc, ec=ec, fs=8.5)
    xs = [s[0] for s in steps]
    for a, b in zip(xs[:-1], xs[1:]):
        arr(ax, a + 1.0, 2, b - 1.0, 2, "", off=0.0)
    ax.set_title("Cómo se genera un código TOTP (RFC 6238 / RFC 4226)", fontweight="bold", fontsize=12)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig_totp_flujo.png"), dpi=140)
    plt.close(fig)


def fig_login_secuencia():
    # Formato apaisado y tipografía grande: el diagrama es protagonista de la lámina,
    # así que debe leerse bien incluso proyectado.
    fig, ax = plt.subplots(figsize=(12.5, 6.4))
    ax.set_xlim(0, 14); ax.set_ylim(0, 11); ax.axis("off")
    lanes = {"Usuario": 2.3, "Servidor Flask": 7.0, "Base de datos": 11.7}
    for name, x in lanes.items():
        rbox(ax, x, 10.4, 3.3, 1.0, name, fc="#1e293b", ec="#0f172a", tc="white", fs=15, weight="bold")
        ax.plot([x, x], [0.5, 9.85], color="#cbd5e1", lw=1.8, ls="--")

    U, S, D = lanes["Usuario"], lanes["Servidor Flask"], lanes["Base de datos"]
    steps = [
        (9.0, U, S, "1) usuario + contraseña"),
        (7.8, S, D, "2) SELECT user · verify bcrypt"),
        (6.6, S, U, "3) pedir código TOTP (paso 2)"),
        (5.4, U, S, "4) código de 6 dígitos"),
        (4.0, S, S, "5) verify HMAC-SHA1 · ventana ±1\nanti-replay · compare_digest"),
        (2.6, S, D, "6) UPDATE last_totp_counter"),
        (1.4, S, U, "7) sesión iniciada (cookie HttpOnly+SameSite)"),
    ]
    for y, x1, x2, label in steps:
        if x1 == x2:  # auto-mensaje (procesamiento interno del servidor)
            ax.add_patch(
                FancyBboxPatch(
                    (x1 - 3.6, y - 0.62), 7.2, 1.24,
                    boxstyle="round,pad=0.02,rounding_size=0.08",
                    fc="#fef9c3", ec="#a16207", lw=1.8,
                )
            )
            ax.text(x1, y, label, ha="center", va="center", fontsize=12.5, color=INK, fontweight="bold")
        else:
            ax.annotate("", xy=(x2, y), xytext=(x1, y),
                        arrowprops=dict(arrowstyle="-|>", lw=2.2, color="#475569",
                                        mutation_scale=22))
            ax.text((x1 + x2) / 2, y + 0.24, label, ha="center", va="bottom", fontsize=12.5, color=INK)
    ax.set_title("Login en dos pasos (secuencia)", fontweight="bold", fontsize=17)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig_login_secuencia.png"), dpi=160)
    plt.close(fig)


def fig_modelo_amenaza():
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_xlim(0, 12); ax.set_ylim(0, 9); ax.axis("off")

    # Zonas / fronteras de confianza
    zones = [
        (0.3, 3.4, "Cliente\n(navegador + teléfono)", "#eff6ff"),
        (4.1, 3.4, "Red\n(canal HTTP/HTTPS)", "#f5f3ff"),
        (8.0, 3.6, "Servidor + Almacén\n(Flask · SQLite · clave maestra)", "#ecfeff"),
    ]
    for x, w, label, fc in zones:
        ax.add_patch(Rectangle((x, 1.2), w, 6.4, fc=fc, ec="#64748b", lw=1.4, ls="--"))
        ax.text(x + w / 2, 7.2, label, ha="center", va="center", fontsize=9.5, fontweight="bold", color=INK)

    mitigated = [
        "Fuerza bruta online → lockout",
        "Replay de código → anti-replay",
        "Timing → compare_digest",
        "Fuga de .db → secreto cifrado",
        "CSRF / SQLi / fijación sesión",
    ]
    residual = [
        "Phishing/MITM en tiempo real",
        "Endpoint comprometido (malware)",
        "Fuga de la CLAVE MAESTRA",
        "Sin HTTPS en demo local",
    ]
    ax.text(2.0, 6.2, "Mitigado (en alcance)", ha="center", fontsize=10, fontweight="bold", color="#15803d")
    for i, t in enumerate(mitigated):
        ax.text(0.55, 5.6 - i * 0.62, "✔ " + t, fontsize=8.6, color="#166534")
    ax.text(5.8, 4.4, "El código solo transita\npor aquí.\nTLS recomendado\n(no en la demo local).",
            ha="center", va="center", fontsize=9, color="#6d28d9", style="italic")
    ax.text(9.8, 6.2, "Riesgo residual (fuera de alcance)", ha="center", fontsize=10, fontweight="bold", color="#b91c1c")
    for i, t in enumerate(residual):
        ax.text(8.2, 5.6 - i * 0.62, "⚠ " + t, fontsize=8.6, color="#991b1b")

    ax.set_title("Modelo de amenaza y fronteras de confianza", fontweight="bold", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig_modelo_amenaza.png"), dpi=140)
    plt.close(fig)


def main():
    fig_arquitectura()
    fig_totp_flujo()
    fig_login_secuencia()
    fig_modelo_amenaza()
    print(f"[figuras] Diagramas generados en {FIG}")


if __name__ == "__main__":
    main()
