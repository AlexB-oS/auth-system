"""E1 — Tabla de conformidad con los vectores oficiales RFC 4226 / RFC 6238.

Genera evidencia legible (texto + CSV + figura) de que nuestra implementación produce
exactamente los valores de los apéndices de prueba de los RFC. Es la base de la
interoperabilidad: cualquier app autenticadora estándar generará los mismos códigos.

Salida: experiments/results/rfc_conformance.txt, .csv, fig_conformance.png
"""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from auth import totp  # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(RESULTS, exist_ok=True)

SECRET = b"12345678901234567890"

HOTP = [
    (0, "755224"), (1, "287082"), (2, "359152"), (3, "969429"), (4, "338314"),
    (5, "254676"), (6, "287922"), (7, "162583"), (8, "399871"), (9, "520489"),
]
TOTP6238 = [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]


def main():
    rows = []  # (rfc, parametro, esperado, obtenido, ok)
    for counter, expected in HOTP:
        got = totp.hotp(SECRET, counter, digits=6, algorithm="sha1")
        rows.append(("RFC 4226 (HOTP)", f"C={counter}", expected, got, got == expected))
    for t, expected in TOTP6238:
        got = totp.totp(SECRET, for_time=t, period=30, digits=8, algorithm="sha1")
        rows.append(("RFC 6238 (TOTP-SHA1)", f"T={t}", expected, got, got == expected))

    all_ok = all(r[4] for r in rows)

    # --- Texto ---
    lines = ["Conformidad RFC 4226 / RFC 6238", "=" * 64]
    header = f"{'RFC':24s} {'Parámetro':14s} {'Esperado':10s} {'Obtenido':10s} OK"
    lines.append(header)
    lines.append("-" * 64)
    for rfc, param, exp, got, ok in rows:
        lines.append(f"{rfc:24s} {param:14s} {exp:10s} {got:10s} {'OK' if ok else 'XX'}")
    lines.append("-" * 64)
    lines.append(f"TOTAL: {sum(r[4] for r in rows)}/{len(rows)} vectores correctos "
                 f"-> {'CONFORME' if all_ok else 'FALLA'}")
    text = "\n".join(lines)
    print(text)
    with open(os.path.join(RESULTS, "rfc_conformance.txt"), "w") as fh:
        fh.write(text + "\n")

    # --- CSV ---
    with open(os.path.join(RESULTS, "rfc_conformance.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rfc", "parametro", "esperado", "obtenido", "ok"])
        for r in rows:
            w.writerow([r[0], r[1], r[2], r[3], r[4]])

    # --- Figura (tabla) ---
    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.axis("off")
    table_data = [[r[0], r[1], r[2], r[3], "✔" if r[4] else "✗"] for r in rows]
    table = ax.table(
        cellText=table_data,
        colLabels=["RFC", "Parámetro", "Esperado", "Obtenido", "OK"],
        cellLoc="center",
        loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.4)
    for j in range(5):
        table[0, j].set_facecolor("#4f46e5")
        table[0, j].set_text_props(color="white", fontweight="bold")
    for i in range(1, len(rows) + 1):
        table[i, 4].set_facecolor("#dcfce7")
    ax.set_title(
        f"Conformidad con vectores oficiales: {sum(r[4] for r in rows)}/{len(rows)} ✔",
        fontweight="bold", pad=16,
    )
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig_conformance.png"), dpi=140)
    print(f"\n[E1] Artefactos en {RESULTS}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
