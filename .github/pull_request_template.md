## Descripción del Cambio

Breve resumen de los cambios implementados y su motivación.

## Tipo de Cambio

- [ ] Corrección de Bug / Falso Positivo (`fix`)
- [ ] Nueva Característica / Módulo de Escaneo (`feat`)
- [ ] Optimización de Rendimiento (`perf`)
- [ ] Refactorización / Tipado Estricto (`refactor`)
- [ ] Documentación / Arquitectura (`docs`)
- [ ] Pruebas Unitarias / Contratos (`test`)

## Quality Gate Checklist

- [ ] `python -m ruff check .` pasa al 100% sin advertencias.
- [ ] `python -m mypy scanner utils api.py main.py` pasa en limpio sin errores de tipos.
- [ ] `bandit -r scanner api.py main.py -c bandit.yaml -ll` reporta 0 vulnerabilidades High/Medium.
- [ ] `pip-audit` no encuentra dependencias vulnerables.
- [ ] `pytest tests -q` pasa con 0 fallos.
- [ ] `python tests/benchmark_accuracy.py` mantiene métricas de precisión >= 95%.
