# Proyecto Final IIC2531 — Autenticación contraseña + TOTP
PY := .venv/bin/python

.PHONY: all setup test run experiments figuras docs clean

all: setup test experiments docs ## Setup + pruebas + experimentos + documentos

setup: ## Crea venv e instala dependencias
	bash setup.sh

test: ## Corre las 33 pruebas (incluye vectores RFC)
	$(PY) -m pytest -q

run: ## Levanta el servidor en http://127.0.0.1:5000
	$(PY) app.py

experiments: ## Genera la evidencia (E1, E3, E4, E5) en experiments/results/
	$(PY) experiments/conformance.py
	$(PY) attacks/timing_attack.py
	$(PY) attacks/bruteforce_demo.py
	$(PY) attacks/replay_demo.py

figuras: ## Genera diagramas y capturas de la interfaz
	$(PY) docs/make_figures.py
	$(PY) docs/screenshots.py

docs: figuras ## Renderiza slides (pptx/pdf/html), informe (docx/pdf) y guion
	bash docs/build_docs.sh

clean: ## Borra artefactos regenerables
	rm -rf experiments/results/*.png experiments/results/*.log experiments/results/*.csv
	rm -f slides/slides.html slides/slides.pdf slides/slides.pptx
	rm -f docs/*.pdf docs/*.docx docs/Informe.html slides/guion.docx
	rm -rf instance __pycache__ auth/__pycache__ tests/__pycache__
