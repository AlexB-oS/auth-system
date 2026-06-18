"""E3 — Ataque de canal lateral por tiempo (timing attack) sobre la comparación.

Pregunta: ¿importa CÓMO se comparan los códigos? Comparamos dos funciones:

  * naive_compare: recorre carácter a carácter y CORTA al primer desajuste.
    El tiempo de ejecución depende de cuántos caracteres iniciales coinciden,
    así que filtra información al atacante (puede adivinar prefijo por prefijo).

  * hmac.compare_digest: tiempo (casi) independiente del contenido -> no filtra.

Medimos el tiempo medio de comparación en función del número de caracteres
iniciales que coinciden (k) y lo graficamos. La curva creciente de naive_compare
es la "fuga"; la curva plana de compare_digest es la mitigación.

Salida: experiments/results/fig_timing.png y timing_table.csv
"""

from __future__ import annotations

import csv
import hmac
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results"
)
os.makedirs(RESULTS, exist_ok=True)


def naive_compare(a: str, b: str) -> bool:
    """Comparación vulnerable: corta al primer carácter distinto."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _guess_with_prefix(secret: str, k: int) -> str:
    """Construye un intento que coincide en los primeros k caracteres y difiere en el k-ésimo."""
    g = list(secret)
    if k < len(secret):
        g[k] = "0" if secret[k] != "0" else "1"
    return "".join(g)


def measure(compare, secret: str, k: int, inner: int = 500, reps: int = 2000) -> float:
    """Tiempo mediano (ns) de una comparación con k caracteres iniciales coincidentes."""
    guess = _guess_with_prefix(secret, k)
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        for _ in range(inner):
            compare(guess, secret)
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / inner)
    return statistics.median(samples)


def run_case(ax, secret: str, title: str):
    ks = list(range(len(secret) + 1))
    naive = [measure(naive_compare, secret, k) for k in ks]
    secure = [measure(secure_compare, secret, k) for k in ks]
    ax.plot(ks, naive, "o-", color="#dc2626", label="naive (corta al 1.er fallo)")
    ax.plot(ks, secure, "s-", color="#16a34a", label="hmac.compare_digest")
    ax.set_title(title)
    ax.set_xlabel("Caracteres iniciales correctos (k)")
    ax.set_ylabel("Tiempo por comparación [ns]")
    ax.grid(True, alpha=0.3)
    ax.legend()
    return ks, naive, secure


def main():
    # Calentamiento del intérprete.
    for _ in range(3):
        measure(naive_compare, "123456", 3, inner=200, reps=200)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    code_secret = "284655"  # un código TOTP de 6 dígitos cualquiera
    token_secret = "a3f1c0d9e8b7461529ac0d3f7b1e44a2"  # 32 hex (p.ej. un MAC) para amplificar
    k6, n6, s6 = run_case(axes[0], code_secret, "Código TOTP de 6 dígitos")
    k32, n32, s32 = run_case(axes[1], token_secret, "Token de 32 caracteres (magnificado)")

    fig.suptitle(
        "Fuga por tiempo: naive vs hmac.compare_digest", fontsize=13, fontweight="bold"
    )
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    out_png = os.path.join(RESULTS, "fig_timing.png")
    fig.savefig(out_png, dpi=140)

    with open(os.path.join(RESULTS, "timing_table.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["caso", "k", "naive_ns", "compare_digest_ns"])
        for k, n, s in zip(k6, n6, s6):
            w.writerow(["totp6", k, f"{n:.1f}", f"{s:.1f}"])
        for k, n, s in zip(k32, n32, s32):
            w.writerow(["token32", k, f"{n:.1f}", f"{s:.1f}"])

    # Métrica resumen: pendiente (correlación tiempo~k). Cuanto mayor, más fuga.
    slope_naive = (n32[-1] - n32[0]) / (len(token_secret))
    slope_secure = (s32[-1] - s32[0]) / (len(token_secret))
    print(f"[E3] Figura guardada en {out_png}")
    print(f"[E3] Token32 naive:  {n32[0]:.0f} ns (k=0) -> {n32[-1]:.0f} ns (k=L)  | pendiente ~{slope_naive:.2f} ns/char")
    print(f"[E3] Token32 secure: {s32[0]:.0f} ns (k=0) -> {s32[-1]:.0f} ns (k=L)  | pendiente ~{slope_secure:.2f} ns/char")
    print("[E3] La pendiente de naive es la fuga; la de compare_digest es ~0 (plana).")


if __name__ == "__main__":
    main()
