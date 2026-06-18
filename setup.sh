#!/usr/bin/env bash
# Crea el entorno virtual e instala dependencias.
# Maneja el caso (Debian/Ubuntu) en que `ensurepip` no está disponible.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="$HERE/.venv"
PY="${PYTHON:-python3}"

if [ ! -x "$VENV/bin/python" ]; then
  echo "[setup] Creando entorno virtual en .venv ..."
  "$PY" -m venv "$VENV" 2>/dev/null || "$PY" -m venv --without-pip "$VENV"
fi

if [ ! -x "$VENV/bin/pip" ]; then
  echo "[setup] pip no disponible en el venv; haciendo bootstrap con get-pip.py ..."
  curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
  "$VENV/bin/python" /tmp/get-pip.py -q
fi

"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
echo "[setup] Listo. Activa con: source .venv/bin/activate"
