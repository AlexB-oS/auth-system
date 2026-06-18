# Guía del repositorio (cómo entender el código)

> Este documento explica **cómo está construido** el proyecto, pensado para alguien que
> abre el repo por primera vez (o para repasar antes de presentar). Es una guía de
> lectura del código; la discusión formal de diseño, resultados y seguridad está en
> [`Informe.md`](Informe.md).

## 1. La idea en una frase

Un servidor web local que exige **contraseña + un código de 6 dígitos que cambia cada
30 s (TOTP)**. Lo distintivo: el algoritmo TOTP está implementado **desde cero** (no con
una librería) y el proyecto **se ataca a sí mismo** para *medir* que sus defensas
funcionan.

## 2. Los dos flujos de usuario (modelo mental)

**A. Enrolamiento (una sola vez).** Te registras → el servidor genera un **secreto**
aleatorio → te lo muestra como **QR** → lo escaneas con Google/Microsoft Authenticator →
escribes un código para confirmar → te entrega **códigos de respaldo**. Desde ahí, tu
teléfono y el servidor comparten el mismo secreto y el mismo reloj, así que ambos
calculan el mismo código sin comunicarse.

**B. Login (cada vez, en dos pasos).** Paso 1: usuario + contraseña. Paso 2: código de
6 dígitos (o un código de respaldo). Solo si pasas **ambos** quedas autenticado.

Ver `figuras/fig_login_secuencia.png` y `figuras/fig_totp_flujo.png`: son estos flujos
dibujados.

## 3. Estructura del repositorio

```
auth-system/
├── app.py          ← servidor Flask: define las URLs (/register, /login, /2fa…)
├── config.py       ← parámetros (claves, período 30s, intentos antes de bloquear…)
├── auth/           ← TODA la lógica de seguridad (el cerebro)
│   ├── totp.py        algoritmo HOTP/TOTP desde cero (hmac + hashlib)
│   ├── crypto.py      bcrypt (contraseña) + cifrado del secreto (Fernet)
│   ├── db.py          base de datos SQLite (consultas parametrizadas)
│   ├── ratelimit.py   bloqueo por fuerza bruta (lockout con backoff)
│   ├── recovery.py    códigos de respaldo de un solo uso
│   ├── accounts.py    "orquesta" registro y login usando los módulos de arriba
│   └── sessions.py    cookies seguras + protección CSRF
├── templates/      ← el HTML que ve el usuario
├── static/         ← CSS y un poco de JS
├── tests/          ← pruebas automáticas (¿el código es correcto?)
├── attacks/        ← scripts que ATACAN el sistema (timing, fuerza bruta, replay)
├── experiments/    ← conformidad RFC + carpeta results/ (la evidencia)
├── docs/           ← Informe, esta guía, figuras y scripts de render
└── slides/         ← presentación (Marp) y guion del orador
```

**Idea clave:** `app.py` casi no "piensa". Solo recibe peticiones HTTP y delega el
trabajo a `auth/accounts.py`, que a su vez usa los módulos especializados (`totp`,
`crypto`, `ratelimit`, …). Esa separación es *responsabilidades acotadas / privilegio
mínimo*.

## 4. Cómo viaja una petición de login (la traza importante)

Cuando alguien envía el formulario de contraseña a `/login`:

1. **`app.py`** (ruta `login`) recibe el POST. Primero, el guardia `csrf_protect`
   (un `before_request`) valida el **token CSRF**.
2. Llama a **`accounts.verify_password_step(...)`**:
   - Si el usuario **no existe**, igual ejecuta `crypto.dummy_verify()` (un bcrypt
     "señuelo") y devuelve el **mismo** mensaje genérico → no se nota si el usuario
     existe (anti-enumeración).
   - Revisa si la cuenta está **bloqueada** (`ratelimit.is_locked`).
   - Verifica la contraseña con **`crypto.verify_password`** (bcrypt).
   - Si falla, registra el fallo (`ratelimit.register_password_failure`, que puede
     disparar el bloqueo).
3. Si la contraseña es correcta, **`sessions.start_pending_2fa(uid)`** marca la sesión
   como *"contraseña OK, falta el 2FA"* y redirige a `/2fa`. **Aún no estás logueado.**
4. En `/2fa` envías el código → **`accounts.verify_totp_step(...)`**:
   - Descifra el secreto con **`crypto.SecretVault`** y verifica con **`totp.verify`**
     (tolerancia ±1 paso de tiempo).
   - **Anti-replay**: el paso del código debe ser *mayor* al último usado
     (`last_totp_counter`); si no, se rechaza.
   - Si no era un código TOTP, prueba si es un **código de respaldo**
     (`recovery.verify_and_consume`, de un solo uso).
5. Si todo bien, **`sessions.complete_login(uid)`** **regenera** la sesión y recién ahí
   fija `user_id` → estás autenticado (defensa contra *fijación de sesión*).

El registro/enrolamiento sigue la misma lógica: `accounts.register` → `start_enrollment`
(genera y **cifra** el secreto) → `confirm_enrollment` (verifica el primer código,
activa el 2FA y crea los códigos de respaldo).

## 5. Dónde vive cada decisión de seguridad

Chuleta para responder "¿dónde está X?":

| Concepto de seguridad | Archivo | Función / detalle |
|---|---|---|
| Contraseña hasheada | `auth/crypto.py` | `hash_password` / `verify_password` (bcrypt, costo 12) |
| **Secreto TOTP cifrado** (no hasheado) | `auth/crypto.py` | clase `SecretVault` (Fernet = AES-128-CBC + HMAC) |
| TOTP desde cero | `auth/totp.py` | `hotp`, `totp`, `verify` |
| Comparación en tiempo constante | `auth/totp.py`, `auth/recovery.py` | `hmac.compare_digest` |
| Anti-replay | `auth/accounts.py` | chequeo `matched <= last_totp_counter` |
| Bloqueo por fuerza bruta | `auth/ratelimit.py` | `register_*_failure` + `is_locked` (backoff exponencial) |
| Throttle por IP | `auth/ratelimit.py` | clase `IPThrottle` |
| Anti-enumeración de usuarios | `auth/crypto.py` + `auth/accounts.py` | `dummy_verify` + mensaje genérico |
| Códigos de respaldo (un solo uso) | `auth/recovery.py` | `generate_codes` / `verify_and_consume` (sha256+sal) |
| CSRF + sesión segura | `auth/sessions.py` + `app.py` | token CSRF, cookie HttpOnly/SameSite, `complete_login` regenera |
| Anti-SQL injection | `auth/db.py` | todas las consultas usan parámetros `?` |
| Cabeceras (CSP, X-Frame-Options…) | `app.py` | `after_request` |

## 6. El corazón: TOTP desde cero (`auth/totp.py`)

Es lo que más conviene dominar. En cuatro pasos:

1. `T = floor(unix_time / 30)` → el "número de paso" actual (`timecode`).
2. `MAC = HMAC-SHA1(secreto, T)` → 20 bytes (`hotp`).
3. **Truncación dinámica** (RFC 4226): el último medio-byte del MAC indica desde qué
   posición tomar 4 bytes → un entero de 31 bits.
4. `código = entero mod 1.000.000` → 6 dígitos.

`verify(secret, code, window=1)` repite el cálculo para el paso actual y los vecinos
(±1), compara con `hmac.compare_digest`, y **devuelve el número de paso que coincidió**
— ese valor es justo lo que usa el anti-replay.

`provisioning_uri(...)` arma la URI `otpauth://totp/...` que se vuelve el QR; cualquier
app autenticadora estándar la entiende.

## 7. Las pruebas y los experimentos (la evidencia)

- **`tests/`** responde *"¿es correcto?"*. `test_totp.py` compara contra los **16
  vectores oficiales** de RFC 4226/6238; `test_auth.py` prueba lockout, anti-replay,
  códigos de respaldo, cifrado en reposo, CSRF, etc. Se corre con `make test`
  (33 pruebas).
- **`attacks/` + `experiments/`** responden *"¿las defensas sirven?"*. Cada script ataca
  el sistema y deja evidencia en `experiments/results/`:
  - `attacks/timing_attack.py` → fuga por tiempo (`fig_timing.png`).
  - `attacks/bruteforce_demo.py` → cuánto frena el lockout (`fig_bruteforce.png`,
    `bruteforce.log`).
  - `attacks/replay_demo.py` → un código repetido se rechaza (`replay.log`).
  - `experiments/conformance.py` → la tabla 16/16 de los RFC (`fig_conformance.png`).

## 8. Cómo correrlo

```bash
cd auth-system
make setup   # instala dependencias en .venv
make test    # corre las 33 pruebas (incluye vectores RFC)
make run     # abre http://127.0.0.1:5000 y prueba el flujo completo
make experiments   # regenera la evidencia
make docs          # regenera slides / informe / guion
```

## 9. Notas y advertencias para leer el código

- **`auth/accounts.py` → `current_totp_for_user(...)`** calcula el código válido de un
  usuario. **No se expone por HTTP**: existe solo para que los scripts de pruebas y
  experimentos puedan simular un login legítimo o un replay. Es esperable y seguro.
- **`config.py`** genera claves de desarrollo en `instance/dev_secrets.json` si no se
  definen por entorno. Eso es **solo para la demo local**; en producción las claves van
  por variables de entorno (ver `.env.example`).
- La carpeta `instance/` (base de datos y claves de dev) y los documentos renderizados
  (`*.pptx/*.pdf/*.docx`) están en `.gitignore`: son regenerables. Las **fuentes**
  (`.md`) y las **figuras** (`docs/figuras/`) sí se versionan.
- El flujo de dos pasos guarda su estado intermedio **en el servidor** (la sesión pasa
  por `pending_2fa` antes de `user_id`): nunca se confía en que el cliente diga
  "ya pasé la contraseña".

## 10. Orden sugerido de lectura

1. `auth/totp.py` (el algoritmo) → `tests/test_totp.py` (qué garantiza).
2. `auth/crypto.py` (hashing vs cifrado, la distinción clave del proyecto).
3. `auth/accounts.py` (cómo se arma el login de dos pasos con todo lo anterior).
4. `app.py` (cómo se exponen esas funciones como rutas HTTP).
5. `attacks/` (cómo demostramos que las defensas funcionan).
