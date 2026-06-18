# Autenticación contraseña + TOTP (con auto-evaluación adversarial)

Proyecto Final — **IIC2531 Seguridad Computacional**
Miguel Ulloa Wood · Alexander Burgos Quezada

Servidor local de autenticación de dos factores (contraseña + TOTP) implementado
**desde cero** en Python/Flask, con defensas de seguridad concretas y un **arnés que
ataca y mide** esas defensas. Ver el detalle en [`docs/Informe.md`](docs/Informe.md).

## ¿Qué incluye?

- **TOTP desde cero** (HMAC-SHA1, RFC 4226/6238), interoperable con Google/Microsoft
  Authenticator (validado contra los vectores oficiales de los RFC).
- **Defensas**: contraseñas con bcrypt, **secreto TOTP cifrado en reposo** (Fernet),
  comparación en tiempo constante (`hmac.compare_digest`), **lockout** con backoff,
  **anti-replay**, códigos de respaldo de un solo uso, sesión segura + CSRF, anti-SQLi.
- **Arnés adversarial** (`attacks/`, `experiments/`) que demuestra empíricamente el
  efecto de cada defensa (timing, fuerza bruta, replay) y genera figuras y logs.

## Estructura del repositorio

```
auth-system/
├── app.py                 # Servidor Flask (rutas, CSRF, cabeceras, QR)
├── config.py              # Configuración desde entorno (defaults seguros)
├── auth/                  # Lógica de seguridad
│   ├── totp.py            #   HOTP/TOTP desde cero (hmac + hashlib)
│   ├── crypto.py          #   bcrypt (password) + cifrado del secreto (Fernet)
│   ├── db.py              #   SQLite con consultas parametrizadas
│   ├── ratelimit.py       #   lockout con backoff + throttle por IP
│   ├── recovery.py        #   códigos de respaldo de un solo uso
│   ├── accounts.py        #   registro y login en dos pasos (anti-replay)
│   └── sessions.py        #   sesión segura + CSRF
├── templates/  static/    # Interfaz web
├── tests/                 # 33 pruebas (vectores RFC + lógica de auth)
├── attacks/               # E3 timing · E4 fuerza bruta · E5 replay
├── experiments/           # E1 conformidad RFC + carpeta results/ (evidencia)
├── docs/                  # Informe.md, figuras/, scripts de figuras y render
├── slides/                # slides.md (Marp) y guion.md
├── Makefile · setup.sh    # automatización
└── requirements.txt
```

## Requisitos

- Python 3.10+ (probado en 3.12).
- Para renderizar slides/PDF: Node + Marp (en `../node_modules`) y un Chrome headless
  (el `Makefile`/`build_docs.sh` lo detectan; si falta, igual se generan HTML/DOCX/PPTX
  por otras vías). Pandoc para DOCX/PPTX.

## Instalación

```bash
make setup        # crea .venv e instala dependencias (requirements.txt)
```
`setup.sh` maneja el caso de Debian/Ubuntu sin `ensurepip` (hace bootstrap de pip).

## Uso

```bash
make run          # http://127.0.0.1:5000
```
Flujo: **Registrarse** → escanear el **QR** con tu app autenticadora → confirmar el
código → guardar los **códigos de respaldo** → en adelante, login en dos pasos
(contraseña + código de 6 dígitos). Si pierdes el teléfono, usa un código de respaldo.

## Pruebas

```bash
make test         # 33 pruebas, incluye los vectores oficiales RFC 4226/6238
```

## Reproducir los experimentos (evidencia)

```bash
make experiments  # genera experiments/results/: figuras, tablas y logs
```
Produce: `rfc_conformance.{txt,csv}` y `fig_conformance.png` (E1),
`fig_timing.png` (E3), `fig_bruteforce.png` + `bruteforce.log` (E4) y `replay.log` (E5).

## Generar los documentos

```bash
make docs         # diagramas + capturas + render
```
Genera:

| Entregable | Ruta |
|---|---|
| Presentación (PowerPoint) | `slides/slides.pptx` |
| Presentación (PDF) | `slides/slides.pdf` |
| Presentación (HTML) | `slides/slides.html` |
| Informe (Word) | `docs/Informe.docx` |
| Informe (PDF) | `docs/Informe.pdf` |

> Nota: los `.pptx/.pdf/.docx` son artefactos de build (en `.gitignore`); se regeneran
> con `make docs`. Las fuentes (`docs/Informe.md`, `slides/slides.md`)
> y las figuras (`docs/figuras/`) sí están versionadas.

## Todo de una vez

```bash
make all          # setup + test + experiments + docs
```

## Seguridad y ética

Todos los ataques del arnés se ejecutan **localmente contra cuentas sintéticas** creadas
por los propios scripts; no involucran terceros ni datos reales. El modelo de amenaza,
las limitaciones y el riesgo residual (p. ej. phishing en tiempo real, gestión de la
clave maestra) se discuten en el informe.
