# Arnés de auto-evaluación adversarial

Estos scripts **atacan nuestra propia implementación** para verificar empíricamente
que las defensas funcionan. Son la evidencia de los experimentos E3–E5 del informe.

| Script | Experimento | Qué demuestra |
|--------|-------------|---------------|
| `timing_attack.py`  | E3 | La comparación con `hmac.compare_digest` no filtra por tiempo; una comparación ingenua sí. |
| `bruteforce_demo.py`| E4 | El lockout con backoff reduce los intentos/hora en varios órdenes de magnitud. |
| `replay_demo.py`    | E5 | Un código TOTP reusado en su ventana es rechazado por el control anti-replay. |

(El experimento E1, conformidad con los vectores RFC, está en `../experiments/conformance.py`.)

## Consideraciones éticas

- Todos los ataques se ejecutan **localmente, contra cuentas sintéticas creadas por el
  propio script**. No se contactan servicios de terceros ni se usan datos reales.
- No hay denegación de servicio ni recolección de credenciales.
- El objetivo es **medir y mejorar** nuestras propias defensas (security testing
  responsable), no atacar sistemas ajenos.

## Declaración de uso de IA

El andamiaje de estos scripts de ataque y sus mediciones (`timing_attack.py`,
`bruteforce_demo.py`, `replay_demo.py`) se desarrolló con asistencia de IA (Claude).
La lógica de seguridad, los parámetros de cada experimento y la interpretación de los
resultados fueron revisados y validados por los autores.

## Cómo ejecutarlos

```bash
make experiments        # corre E1, E3, E4, E5 y deja la evidencia en experiments/results/
# o individualmente:
.venv/bin/python attacks/timing_attack.py
.venv/bin/python attacks/bruteforce_demo.py
.venv/bin/python attacks/replay_demo.py
.venv/bin/python experiments/conformance.py
```
