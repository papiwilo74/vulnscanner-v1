# Guía de Contribución a VulnScanner

¡Gracias por tu interés en contribuir a **VulnScanner**! Toda ayuda para fortalecer la precisión, rendimiento y seguridad de la herramienta es bienvenida.

---

## Proceso de Desarrollo

### 1. Clonar y Configurar el Entorno

```bash
git clone https://github.com/papiwilo74/vulnscanner-v1.git
cd vulnscanner-v1
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate

# Instalar dependencias de producción y desarrollo
pip install -r requirements.txt
pip install pytest pytest-mock responses pytest-cov mypy types-requests types-urllib3 types-colorama bandit pip-audit httpx ruff
```

### 2. Estándar de Calidad Local (Quality Gate)

Antes de abrir un Pull Request, debes asegurar que todas las siguientes comprobaciones pasen limpias:

```bash
# 1. Linting y orden de imports
python -m ruff check .

# 2. Type Checking estricto
python -m mypy scanner utils api.py main.py

# 3. Análisis estático de seguridad (SAST)
python -m bandit -r scanner api.py main.py -c bandit.yaml -ll

# 4. Auditoría de dependencias (SCA)
python -m pip_audit

# 5. Suite de pruebas unitarias y de integración
python -m pytest tests -q

# 6. Benchmark de detección y falsos positivos
python tests/benchmark_accuracy.py
```

### 3. Convención de Commits

Seguimos la convención de [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` Nuevas características o módulos de escaneo.
- `fix:` Correcciones de bugs o reducción de falsos positivos.
- `perf:` Mejoras de rendimiento o concurrencia.
- `refactor:` Mejoras en la estructura de código o type safety.
- `test:` Nuevos tests unitarios o contratos.
- `docs:` Mejoras en la documentación o especificaciones.

---

## Reportar Problemas o Sugerir Mejoras

- Utiliza las plantillas de Issues provistas en el repositorio (`Bug report` o `Feature request`).
- Para reportes de seguridad, consulta [SECURITY.md](SECURITY.md).
