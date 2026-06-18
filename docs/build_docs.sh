#!/usr/bin/env bash
# Renderiza los entregables: slides (html/pdf/pptx), informe (docx/pdf) y guion (docx).
# Estrategia robusta con fallbacks y timeouts; no cuelga ni falla si falta el navegador.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"     # .../auth-system
DOCS="$ROOT/docs"
SLIDES="$ROOT/slides"
FIG="$DOCS/figuras"
RES="$ROOT/experiments/results"

mkdir -p "$FIG"
# Reunir las figuras de experimentos junto a las del informe.
cp -f "$RES"/fig_timing.png "$RES"/fig_bruteforce.png "$RES"/fig_conformance.png "$FIG/" 2>/dev/null || true

# --- Localizar herramientas ---
CHROME="$(find "$ROOT/.cache-browser" -name chrome -type f 2>/dev/null | head -1)"
if [ -z "$CHROME" ]; then
  for c in google-chrome chromium chromium-browser; do
    command -v "$c" >/dev/null 2>&1 && CHROME="$(command -v "$c")" && break
  done
fi
MARP="$ROOT/../node_modules/.bin/marp"
[ -x "$MARP" ] || MARP="npx --yes @marp-team/marp-cli@3"
PANDOC="$(command -v pandoc || true)"

# Conjunto mínimo de flags (fiable en este entorno).
CFLAGS="--headless=new --no-sandbox --disable-gpu"

echo "== Chrome: ${CHROME:-NO ENCONTRADO}"
echo "== Marp:   $MARP"
echo "== Pandoc: ${PANDOC:-NO ENCONTRADO}"

# =====================================================================
# 1) SLIDES
# =====================================================================
echo "--- Slides: HTML ---"
timeout 180 $MARP "$SLIDES/slides.md" -o "$SLIDES/slides.html" --html --allow-local-files \
  || echo "WARN: marp html falló"

if [ -n "$CHROME" ] && [ -f "$SLIDES/slides.html" ]; then
  echo "--- Slides: PDF (chrome imprime el HTML de Marp) ---"
  rm -f "$SLIDES/slides.pdf"
  timeout 120 "$CHROME" $CFLAGS --no-pdf-header-footer \
    --print-to-pdf="$SLIDES/slides.pdf" "file://$SLIDES/slides.html" 2>/dev/null
  [ -f "$SLIDES/slides.pdf" ] && echo "OK slides.pdf" || echo "WARN: no se generó slides.pdf"
fi

echo "--- Slides: PPTX ---"
rm -f "$SLIDES/slides.pptx"
# Intento 1: Marp nativo (mejor estética; usa su propio navegador).
if [ -n "$CHROME" ]; then
  CHROME_PATH="$CHROME" timeout 150 $MARP "$SLIDES/slides.md" -o "$SLIDES/slides.pptx" \
    --pptx --html --allow-local-files 2>/dev/null || true
fi
# Fallback: pandoc (pptx real sin navegador).
if [ ! -f "$SLIDES/slides.pptx" ] && [ -n "$PANDOC" ]; then
  echo "   (fallback pandoc para pptx)"
  tmp_md="$(mktemp --suffix=.md)"
  awk 'BEGIN{fm=0} NR==1 && $0=="---"{fm=1; next} fm==1 && $0=="---"{fm=0; next} fm==1{next} {print}' \
    "$SLIDES/slides.md" | sed '/^---$/d' | perl -0777 -pe 's/<!--.*?-->//gs' > "$tmp_md"
  ( cd "$SLIDES" && "$PANDOC" "$tmp_md" -t pptx --slide-level=2 \
      --resource-path="$SLIDES:$DOCS" -o "$SLIDES/slides.pptx" ) \
      && echo "OK slides.pptx (pandoc)" || echo "WARN: pandoc pptx falló"
  rm -f "$tmp_md"
elif [ -f "$SLIDES/slides.pptx" ]; then
  echo "OK slides.pptx (marp)"
fi

# =====================================================================
# 2) INFORME
# =====================================================================
if [ -n "$PANDOC" ]; then
  echo "--- Informe: DOCX ---"
  ( cd "$DOCS" && "$PANDOC" Informe.md -o Informe.docx --resource-path="$DOCS" ) \
    && echo "OK Informe.docx" || echo "WARN: docx falló"

  echo "--- Informe: HTML autocontenido ---"
  ( cd "$DOCS" && "$PANDOC" Informe.md -s --embed-resources --toc -c report.css \
      --metadata title="Informe — Autenticación contraseña + TOTP" \
      --resource-path="$DOCS" -o Informe.html ) || echo "WARN: html falló"

  if [ -n "$CHROME" ] && [ -f "$DOCS/Informe.html" ]; then
    echo "--- Informe: PDF (chrome imprime el HTML) ---"
    rm -f "$DOCS/Informe.pdf"
    timeout 120 "$CHROME" $CFLAGS --no-pdf-header-footer \
      --print-to-pdf="$DOCS/Informe.pdf" "file://$DOCS/Informe.html" 2>/dev/null
    [ -f "$DOCS/Informe.pdf" ] && echo "OK Informe.pdf" || echo "WARN: no se generó Informe.pdf"
  fi
fi

# =====================================================================
# 3) GUION
# =====================================================================
if [ -n "$PANDOC" ]; then
  echo "--- Guion: DOCX ---"
  ( cd "$SLIDES" && "$PANDOC" guion.md -o guion.docx ) \
    && echo "OK guion.docx" || echo "WARN: guion docx falló"
fi

echo ""
echo "=== Entregables generados ==="
for f in "$SLIDES/slides.html" "$SLIDES/slides.pdf" "$SLIDES/slides.pptx" \
         "$DOCS/Informe.docx" "$DOCS/Informe.pdf" "$SLIDES/guion.docx"; do
  if [ -f "$f" ]; then printf "  [OK] %s (%s)\n" "${f#$ROOT/}" "$(du -h "$f" | cut -f1)"; \
  else printf "  [--] %s (no generado)\n" "${f#$ROOT/}"; fi
done
