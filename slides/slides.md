---
marp: true
theme: default
paginate: true
size: 16:9
header: 'IIC2531 · Autenticación Contraseña + TOTP'
footer: 'M. Ulloa · A. Burgos · 2026'
style: |
  section { font-size: 27px; }
  h1 { color: #4338ca; }
  h2 { color: #5b21b6; }
  section.lead { text-align: center; }
  table { font-size: 22px; }
  code { background: #eef2ff; }
  .small { font-size: 20px; color: #475569; }
  .big { font-size: 40px; font-weight: 700; color: #4338ca; }
---

<!-- _class: lead -->

# Autenticación: contraseña + **TOTP**
## construida desde cero y **atacada por nosotros mismos**

**Miguel Ulloa Wood · Alexander Burgos Quezada**

IIC2531 — Seguridad Computacional · 2026

<!-- Hola, somos Miguel y Alexander. Nuestro proyecto es un sistema de autenticación de dos factores. La idea central: no solo construirlo, sino tratarlo como objeto de estudio de seguridad y medir si sus defensas realmente funcionan. -->

---

## El problema

- Las **contraseñas solas** son un factor débil: se reutilizan, se filtran, se phishean.
- **2FA**: aunque roben la contraseña, falta el segundo factor.
- **TOTP** es el 2FA más usado: solo un secreto + un reloj.
- Pero **implementarlo bien es sutil**: un detalle mal hecho rompe la garantía.

<!-- Las contraseñas se filtran en brechas masivas y se reutilizan. El segundo factor mitiga esto. TOTP domina porque no necesita SMS ni hardware. El mensaje clave de la charla: que "funcione" no basta; los detalles deciden si resiste un ataque. -->

---

## Qué construimos (alcance)

- Servidor **Flask local** con login en **dos pasos**: contraseña + TOTP.
- **TOTP desde cero** (HMAC-SHA1, RFC 6238) — interopera con Google/Microsoft Authenticator.
- Enrolamiento por **QR**, **códigos de respaldo**, panel.
- **Defensas**: cifrado del secreto, `compare_digest`, lockout, anti-replay, CSRF.
- **Arnés adversarial** que ataca y **mide** nuestras propias defensas.

![bg right:38% fit](../docs/figuras/shot_login.png)

<!-- Construimos un servidor Flask con login en dos pasos. El núcleo TOTP está hecho a mano con la librería estándar para controlar cada paso. Lo novedoso, y lo que más pesa en un curso de seguridad, es el arnés que ataca nuestra propia implementación. -->

---

## Conexión con el curso

| Tema | Dónde aparece |
|---|---|
| Criptografía aplicada | HMAC, bcrypt, cifrado autenticado |
| Autenticación / 2FA | login en dos pasos |
| Modelo de amenaza | qué atacante consideramos |
| Canal lateral (timing) | `compare_digest` |
| Defensa en profundidad | lockout + throttle + anti-replay |
| Seguridad web | CSRF, sesión, SQLi, headers |

<!-- El proyecto toca de forma transversal los temas del curso. No es solo cripto: es modelo de amenaza, canales laterales, defensa en profundidad y seguridad web. -->

---

## Modelo de amenaza

![w:880](../docs/figuras/fig_modelo_amenaza.png)

<!-- Definimos explícitamente el atacante: remoto, sin credenciales, que adivina, mide tiempos, reenvía peticiones y puede obtener una copia de la base de datos. A la izquierda lo mitigado; a la derecha el riesgo residual que dejamos fuera de alcance y que discutiremos al final. -->

---

## Arquitectura

![w:760](../docs/figuras/fig_arquitectura.png)

<!-- Módulos con responsabilidades acotadas (privilegio mínimo y separación). El servidor coordina TOTP, crypto, rate-limiter y sesiones; la base de datos guarda hashes y el secreto cifrado. -->

---

## Cómo funciona TOTP

![w:1000](../docs/figuras/fig_totp_flujo.png)

- `T = ⌊unix/30⌋` → `HMAC-SHA1(secreto, T)` → truncación dinámica → `mod 10⁶`
- El mismo secreto en el teléfono y en el servidor ⇒ mismo código.

<!-- TOTP es HOTP aplicado al tiempo. Se hace HMAC del secreto con el número de paso de 30 segundos, se trunca dinámicamente según el RFC 4226 y se toma módulo un millón. Como teléfono y servidor comparten secreto y reloj, generan el mismo código. -->

---

## Login en dos pasos

![w:680](../docs/figuras/fig_login_secuencia.png)

<!-- El estado intermedio vive en el servidor: tras la contraseña la sesión queda "pendiente de 2FA"; solo al validar el TOTP se promueve a autenticada, regenerando la sesión. La verificación incluye ventana, anti-replay y comparación en tiempo constante. -->

---

## Decisiones de seguridad clave

| Riesgo | Defensa |
|---|---|
| Fuga del `.db` | bcrypt (contraseña) + secreto **cifrado** |
| Fuerza bruta | **lockout** con backoff + throttle IP |
| Canal lateral por tiempo | `hmac.compare_digest` |
| Replay de código | último paso consumido |
| Enumeración de usuarios | mensaje uniforme + bcrypt señuelo |
| CSRF / SQLi / fijación | token CSRF · queries parametrizadas · regen. sesión |

<!-- Esta tabla es el corazón técnico. Cada fila es una amenaza concreta con su defensa. En las próximas láminas mostramos evidencia medida de las cuatro más interesantes. -->

---

## El error… ¡de nuestra propia propuesta!

> La propuesta original decía: **"secretos hasheados con Bcrypt"**

- Un secreto TOTP **no se puede hashear**: para verificar hay que **recalcular** `HMAC(secreto, T)`.
- Un hash es de **una sola vía** ⇒ jamás podríamos verificar.
- **Solución:** lo **ciframos** (Fernet = AES + HMAC) con clave maestra fuera de la BD.

<!-- Este fue nuestro mayor aprendizaje. La propuesta decía hashear el secreto. Al implementarlo vimos que es imposible verificar desde un hash. La contraseña sí se hashea, pero el secreto TOTP hay que cifrarlo de forma reversible. Distinguir hashing de cifrado según el caso de uso fue clave. -->

---

## Demo

![h:400](../docs/figuras/shot_enroll.png) ![h:400](../docs/figuras/shot_2fa.png) ![h:400](../docs/figuras/shot_dashboard.png)

*Enrolamiento (QR) → verificación 2FA → sesión protegida*

<!-- Demostración: el usuario escanea el QR, la app genera códigos, ingresa el de 6 dígitos y entra. Si hay tiempo lo mostramos en vivo en localhost. -->

---

## Resultado E1 — Conformidad RFC

![w:760](../docs/figuras/fig_conformance.png)

**16/16** vectores oficiales (RFC 4226 + RFC 6238) ⇒ correcto e **interoperable**.

<!-- Validamos contra los vectores de prueba oficiales de los RFC. 16 de 16 correctos. Esto prueba que el algoritmo es correcto y, por construcción, interoperable con cualquier app estándar. -->

---

## Resultado E3 — Canal lateral por tiempo

![w:820](../docs/figuras/fig_timing.png)

Comparación ingenua: **+16 ns/carácter** correcto (fuga). `compare_digest`: **plana**.

<!-- Medimos el tiempo de comparación según cuántos caracteres iniciales aciertan. La comparación ingenua sube linealmente: esa pendiente es la fuga que permite adivinar carácter a carácter. compare_digest es plana. Honestidad: amplificamos con un token de 32 caracteres para verlo; el principio vale igual. -->

---

## Resultado E4 — Fuerza bruta vs. lockout

| Escenario | Intentos/h | Tiempo a 50% |
|---|---:|---:|
| Sin protección | 180.000 | ~0,1 días |
| Throttle IP | 1.200 | ~8 días |
| **Lockout** | **12** | **~802 días** |

![bg right:46% fit](../docs/figuras/fig_bruteforce.png)

<!-- Un código de 6 dígitos tiene un millón de valores. Lo decisivo es cuántos intentos por hora se permiten. El lockout baja de 180 mil a 12 intentos por hora: el tiempo esperado de un ataque exitoso pasa de horas a más de dos años. Cuatro órdenes de magnitud. -->

---

## Resultado E5 + E6

**E5 — Replay**
```
[1] login con código 495104  -> ok
[2] MISMO código (misma ventana) -> RECHAZADO (replay)
```

**E6 — Pruebas:** `33 passed` (vectores RFC, lockout, replay, backup, cifrado, CSRF…)

<!-- El replay: un código vale una vez; reusarlo en su ventana se rechaza por el registro del último paso consumido. Y las 33 pruebas automatizadas pasan, cubriendo desde los vectores RFC hasta CSRF. -->

---

## Limitaciones y riesgo residual

- **TOTP es phishable**: un MITM en tiempo real reusa el código al instante. ⇒ **WebAuthn/passkeys**.
- **Clave maestra**: si se filtra con la BD, se pierden los secretos. ⇒ KMS/HSM.
- **Sin HTTPS** en demo local; throttle por IP **en memoria** (un proceso).
- Ninguna 2FA protege un **endpoint comprometido**.

<!-- Somos honestos sobre los límites. TOTP no resiste phishing en tiempo real; la defensa real es WebAuthn. La seguridad del secreto cifrado depende de proteger la clave maestra. Y nada protege un dispositivo con malware. -->

---

## Aprendizajes y trabajo futuro

- Lo difícil **no** es el happy path; son los **detalles** (comparar, guardar, limitar, repetir).
- **Hashing ≠ cifrado**: el caso de uso decide.
- **Medir** una defensa (no solo afirmarla) cambia la confianza.
- **Futuro:** WebAuthn/passkeys, throttle distribuido, KMS, TOTP SHA-256/512.

<!-- El gran aprendizaje: la dificultad está en los detalles que deciden si resiste un ataque. Distinguir hashing de cifrado. Y sobre todo, que medir una defensa es muy distinto de suponer que funciona. -->

---

<!-- _class: lead -->

# ¿Preguntas?

**Gracias.**

*Código, informe y experimentos reproducibles con* `make all`

<!-- Gracias. Todo es reproducible con make all. Quedamos atentos a sus preguntas. -->
