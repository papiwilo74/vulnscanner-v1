# VulnScanner v2.0 (Enterprise Edition)

<p align="center">
  <img src="https://img.shields.io/badge/VulnScanner-v2.0.0%20Enterprise-blue?style=for-the-badge&logo=shield" alt="VulnScanner v2.0 Enterprise" />
</p>

<p align="center">
  <a href="https://github.com/papiwilo74/vulnscanner-v1/releases/tag/v2.0.0"><img src="https://img.shields.io/badge/Release-v2.0.0-007EC6.svg?logo=github" alt="Release v2.0.0" /></a>
  <a href="https://github.com/papiwilo74/vulnscanner-v1/actions/workflows/ci.yml"><img src="https://github.com/papiwilo74/vulnscanner-v1/actions/workflows/ci.yml/badge.svg" alt="CI Pipeline" /></a>
  <a href="https://mypy-lang.org/"><img src="https://img.shields.io/badge/Type%20Checked-mypy%20strict-blue.svg" alt="Mypy" /></a>
  <a href="https://github.com/PyCQA/bandit"><img src="https://img.shields.io/badge/Security-Bandit%20Pass-green.svg" alt="Bandit" /></a>
  <a href="https://pypi.org/project/pip-audit/"><img src="https://img.shields.io/badge/Dependencies-pip--audit%20clean-brightgreen.svg" alt="pip-audit" /></a>
  <a href="tests/benchmark_accuracy.py"><img src="https://img.shields.io/badge/F1--Score-100%25-success.svg" alt="Accuracy Benchmark" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white" alt="Python 3.10+" /></a>
</p>

> **VulnScanner v2.0** es un escáner de vulnerabilidades web de nivel empresarial (DAST + SAST + IA), modular, con soporte de auto-remediación, análisis asíncrono y reportes ejecutivos en HTML, JSON y SARIF v2.1.0.

---

## Tabla de Contenidos

- [Que es VulnScanner?](#que-es-vulnscanner)
- [Arquitectura y Diseno Tecnico](docs/architecture.md)
- [Especificacion OpenAPI](docs/openapi.json)
- [Caracteristicas](#caracteristicas)
- [Instalacion](#instalacion)
- [Uso Rapido](#uso-rapido)
- [Opciones Avanzadas](#opciones-avanzadas)
- [Modulos de Deteccion](#modulos-de-deteccion)
- [Reportes Generados](#reportes-generados)
- [Validacion de Calidad](#validacion-de-calidad)
- [Entrenamiento del Modelo de IA](#entrenamiento-del-modelo-de-ia)
- [Ejecutar Pruebas](#ejecutar-pruebas)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Etica y Uso Responsable](#etica-y-uso-responsable)

---

## Que es VulnScanner?

**VulnScanner** es una herramienta de analisis de seguridad web de codigo abierto escrita en Python, que combina:

- **DAST** (Dynamic Application Security Testing): escaneo activo de endpoints en vivo
- **SAST** (Static Application Security Testing): analisis estatico de codigo JavaScript
- **ML**: un modelo de Inteligencia Artificial (TF-IDF + Regresion Logistica) que clasifica parametros sospechosos

Disenada con enfoque **defensivo y educativo**. El modo `--stealth` aplica rate-limiting con User-Agent rotativo y retardos aleatorios para reducir la carga en el servidor objetivo durante pruebas autorizadas.

---

## Caracteristicas

| Modulo | Descripcion |
|---|---|
| **SSL/TLS** | Validez y expiracion de certificados, soporte a protocolos obsoletos |
| **Headers HTTP** | Detecta ausencia de CSP, HSTS, X-Frame-Options, Referrer-Policy |
| **Cookies** | Verifica flags `Secure`, `HttpOnly` y `SameSite` |
| **CORS** | Detecta origenes reflejados, wildcards con credenciales |
| **CSRF** | Detecta ausencia de tokens anti-CSRF en formularios POST |
| **XSS** | Detecta XSS reflejado, DOM-based en archivos JS |
| **SQLi** | Deteccion basada en errores y Blind SQLi basada en tiempo |
| **Inyecciones** | OS Command Injection y SSTI (Server-Side Template Injection) |
| **Fuzzing** | Detecta archivos expuestos: `.env`, `.git/config`, `backup.sql`, etc. |
| **Datos Sensibles** | Detecta claves AWS, Google/Firebase, JWT, Stripe, strings de conexion a BD |
| **SCA** | Detecta librerias JS de frontend con versiones vulnerables (jQuery, Lodash...) |
| **Crawler** | Rastrea paginas internas del dominio recursivamente |
| **Subdominios** | Descubrimiento concurrente de subdominios activos via DNS |
| **IA** | Clasificacion de parametros sospechosos con modelo TF-IDF + Regresion Logistica |
| **Stealth** | Rate-limiting con User-Agent rotativo y retardos aleatorios |

---

## Instalacion

### Requisitos
- Python 3.9 o superior
- pip

```bash
git clone https://github.com/papiwilo74/vulnscanner-v1.git
cd vulnscanner-v1
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### Opcional: Usar Docker

```bash
# Construir e iniciar la API
docker compose up -d api

# Escaneo CLI via Docker
docker compose --profile cli run --rm cli https://ejemplo.com/ --stealth
```

### Entrenar el modelo de IA (primera vez)

```bash
python train_ai.py
```

---

## Uso Rapido

```bash
# Escaneo basico de una URL
python main.py https://ejemplo.com/

# Escaneo sin abrir el reporte automaticamente
python main.py https://ejemplo.com/ --no-open

# Modo sigiloso (rate-limiting, recomendado para pruebas autorizadas)
python main.py https://ejemplo.com/ --stealth --no-open
```

---

## Opciones Avanzadas

```bash
python main.py <URL> [OPCIONES]
```

| Opcion | Descripcion | Ejemplo |
|---|---|---|
| `--no-open` | No abre el reporte HTML automaticamente | `--no-open` |
| `--stealth` | Rate-limiting: User-Agent real + retardos aleatorios | `--stealth` |
| `--delay N` | Retardo fijo de N segundos entre peticiones | `--delay 2.0` |
| `--crawl N` | Rastrea hasta N paginas internas del dominio | `--crawl 5` |
| `--subdomains` | Activa busqueda de subdominios activos | `--subdomains` |
| `--cookie "..."` | Cookies de sesion para escaneo autenticado | `--cookie "session=abc123"` |
| `--auth "..."` | Cabecera Authorization para APIs con token | `--auth "Bearer mi_token"` |
| `--passive` | Solo analisis pasivo, sin envio de payloads | `--passive` |
| `--login-url` | URL de endpoint de login para autenticacion dinamica | `--login-url https://api.ejemplo.com/auth` |
| `--login-creds` | Credenciales en formato `campo=valor;campo2=valor2` | `--login-creds "user=admin;pass=sec"` |
| `--profile` | Perfil de escaneo: `passive`, `normal`, `aggressive` | `--profile passive` |
| `--no-oast` | Desactiva pruebas fuera de banda OAST | `--no-oast` |
| `--allow-private` | Permite escanear IPs privadas o localhost | `--allow-private` |
| `--har` | Importa una sesion grabada desde un archivo HTTP Archive | `--har session.har` |
| `--headless-crawl` | Usa Playwright para descubrir rutas SPA y APIs dinamicas | `--headless-crawl` |
| `--headless-login` | Usa navegador headless para login interactivo | `--headless-login` |

### Ejemplos combinados

```bash
# Escaneo completo con rate-limiting, crawling y subdominios
python main.py https://ejemplo.com/ --stealth --crawl 10 --subdomains --no-open

# Escaneo de area autenticada con cookies
python main.py https://ejemplo.com/dashboard/ --cookie "session=abc; user=admin" --stealth

# Escaneo con retardo fijo de 1.5 segundos
python main.py https://ejemplo.com/ --delay 1.5 --no-open
```

---

## Modulos de Deteccion

El escaner esta organizado en modulos independientes dentro de la carpeta `scanner/`. Cada modulo:

- Recibe una URL y una sesion opcional (`requests.Session`)
- Devuelve una lista de hallazgos con los campos: `vuln`, `risk`, `detail`
- Los niveles de riesgo son: `Alto`, `Medio`, `Bajo`

### Lista completa de modulos

| Archivo | Vulnerabilidad detectada | Riesgo tipico |
|---|---|---|
| `headers.py` | Cabeceras HTTP de seguridad ausentes | Alto/Medio/Bajo |
| `https_check.py` | HTTP sin cifrar | Alto |
| `ssl_check.py` | Certificados expirados, TLS obsoleto | Alto/Medio |
| `cookies.py` | Cookies sin flags Secure/HttpOnly | Medio |
| `cors.py` | CORS permisivo (wildcard, origen reflejado) | Alto/Medio/Bajo |
| `xss.py` | XSS Reflejado y DOM-based | Alto/Medio |
| `sqli.py` | SQL Injection (error-based y time-based) | Alto |
| `forms.py` | Formularios sin CSRF, XSS/SQLi en forms | Alto/Medio |
| `injections.py` | Command Injection, SSTI | Alto |
| `sensitive_data.py` | Claves API, JWT, eval(), conexiones a BD | Alto/Medio |
| `directories.py` | Directorios expuestos, SPA fallback | Bajo |
| `ports.py` | Puertos criticos abiertos | Medio |
| `crawler.py` | Rastreo de paginas, sitemap, robots.txt | -- |
| `fuzzer.py` | Archivos sensibles (.env, .git, backups) | Alto/Medio |
| `subdomains.py` | Subdominios activos por DNS | Bajo |
| `sca.py` | Librerias JS vulnerables (jQuery, Bootstrap...) | Medio/Bajo |
| `ai_check.py` | Parametros sospechosos via ML | Medio/Bajo |
| `auth_helper.py` | Autenticacion dinamica (form/JSON/token) | -- |
| `path_traversal.py` | Path Traversal (Unix/Windows) | Alto |
| `xxe.py` | XML External Entity Injection | Alto |
| `open_redirect.py` | Open Redirect en parametros URL | Medio |
| `jwt_attacks.py` | JWT alg=none, secretos debiles | Alto |
| `file_upload.py` | Formularios de subida sin restricciones | Medio |
| `prototype_pollution.py` | Prototype Pollution en JS | Medio |
| `graphql.py` | GraphQL introspection expuesta | Medio |
| `websocket.py` | WebSocket sin cifrar (ws://) | Medio |
| `models.py` | Modelo estandarizado de hallazgos con evidencia, CVSS, CWE y MITRE | -- |
| `engine.py` | Motor con perfiles, limites, deduplicacion y cancelacion | -- |
| `dom_xss.py` | Analisis especializado de DOM XSS | Medio/Alto |
| `oast.py` | Deteccion OAST para SSRF/XXE/RCE ciego | Critico/Alto |
| `har_parser.py` | Importacion de sesiones desde archivos HAR | -- |
| `headless_crawler.py` | Rastreo dinamico con Playwright/Chromium | -- |
| `autofix.py` | Fingerprinting tecnologico y remediaciones accionables | -- |

---

## API REST

VulnScanner incluye una API REST con FastAPI:

```bash
# Iniciar servidor
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

| Endpoint | Metodo | Descripcion |
|---|---|---|
| `/` | GET | Estado del servicio |
| `/scan` | POST | Iniciar escaneo en background, devuelve `task_id` |
| `/scan/{task_id}` | GET | Estado y resultados de una tarea |
| `/scans` | GET | Historial completo de escaneos |
| `/docs` | GET | Documentacion interactiva Swagger |

Las tareas persisten en SQLite (`reports/tasks.db`), sobreviviendo reinicios del servidor.

---

## Reportes Generados

Al finalizar cada escaneo se generan **tres reportes** en la carpeta `reports/`:

- **`reporte_*.html`** — Dashboard visual interactivo con modo oscuro/claro, filtros por severidad y recomendaciones de remediacion.
- **`reporte_*.json`** — Datos estructurados para integracion con pipelines CI/CD, dashboards SOC o bases de datos.
- **`reporte_*.sarif`** — Reporte OASIS SARIF v2.1.0 para GitHub Code Scanning, GitLab, Azure DevOps y herramientas ASPM.

**Estructura del JSON:**
```json
{
    "target": "https://ejemplo.com/",
    "date": "2025-01-15 14:30:00",
    "duration_seconds": 45.2,
    "engine": {
        "profile": "normal",
        "total_requests": 125,
        "max_rps": 10,
        "cancelled": false
    },
    "sarif_report_path": "reports/reporte_ejemplo_com_1736951400.sarif",
    "summary": { "Alto": 2, "Medio": 1, "Bajo": 3 },
    "vulnerabilities": [
        {
            "vuln": "CORS Abierto (Comodin)",
            "risk": "Bajo",
            "detail": "El servidor expone Access-Control-Allow-Origin: *",
            "severity": "low",
            "confidence": "possible",
            "category": "cors",
            "affected_url": "https://ejemplo.com/",
            "cvss_score": 5.3,
            "cwe_id": "CWE-942",
            "mitre_attack_id": "T1189",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "evidence": {
                "request_method": "GET",
                "request_url": "https://ejemplo.com/",
                "response_status": 200,
                "response_fragment": "Access-Control-Allow-Origin: *"
            }
        }
    ]
}
```

---

## Validacion de Calidad

El proyecto implementa un estándar empresarial riguroso con métricas auditables, SAST/SCA automatizados y verificación estricta de tipos.

### Quality Gate Local Unificado

```bash
# 1. Linting estricto
python -m ruff check .

# 2. Type Checking estricto (Mypy)
python -m mypy scanner utils api.py main.py

# 3. SAST (Análisis de Seguridad Estático con Bandit)
python -m bandit -r scanner api.py main.py -c bandit.yaml -ll

# 4. SCA (Auditoría de Vulnerabilidades en Dependencias con pip-audit)
python -m pip_audit

# 5. Suite de Pruebas Unitaria, Integración y Contratos
python -m pytest tests -q

# 6. Benchmark Cuantitativo de Precisión (F1-Score / Precision / Recall)
python tests/benchmark_accuracy.py
```

### Criterios de Madurez Nivel Empresarial (9.5+/10)

- **Type Safety Completo**: Mypy configurado en modo estricto en `pyproject.toml` sobre todo el core (`scanner`, `utils`, `api.py`, `main.py`) sin errores ni suppressions globales.
- **Seguridad SAST & SCA**: Bandit configurado vía `bandit.yaml` con cero vulnerabilidades High/Medium, y `pip-audit` validando árbol de dependencias contra CVEs conocidos.
- **Contract & Schema Testing**: Pruebas en `tests/test_contract.py` que validan contratos OpenAPI 3.1, esquemas JSON/SARIF v2.1.0 y consistencia de payloads REST.
- **Métricas Cuantitativas de Detección**: Benchmark reproducible con 100% de Precision, 100% de Recall y F1-Score de 1.00 en controles estándar.
- **Arquitectura y Especificación**: Documento formal [`docs/architecture.md`](docs/architecture.md) y especificación [`docs/openapi.json`](docs/openapi.json).
- **Modelo de Hallazgos Integral**: `Finding` estructurado con CVSS v3.1, CWE, MITRE ATT&CK, OWASP Top 10, snippets de evidencia sanitizados y remediación accionable.
- **Motor DAST Seguro**: Perfiles `passive`, `normal` y `aggressive`, defensa SSRF (validación de RFC 1918/Loopback/Cloud Metadata), rate limiting por token bucket y auto-remediación (`scanner/autofix.py`).

---

## Entrenamiento del Modelo de IA

El modulo de IA (`scanner/ai_check.py`) usa un clasificador `TF-IDF + Regresion Logistica` entrenado localmente para identificar patrones sospechosos en parametros de URL.

```bash
python train_ai.py
```

El modelo entrenado se guarda en `models/` y es cargado automaticamente durante el escaneo. En CI se verifica que el accuracy supere el 90%.

---

## Ejecutar Pruebas

```bash
# Instalar dependencias de desarrollo y seguridad
pip install -r requirements.txt
pip install pytest pytest-mock responses pytest-cov mypy types-requests types-urllib3 types-colorama bandit pip-audit httpx

# Ejecutar suite completa (unitarios, integracion, contratos)
pytest tests/ -v

# Ejecutar con reporte de cobertura
pytest tests/ --cov=. --cov-report=term-missing --cov-branch
```

### CI/CD Pipeline

El flujo de GitHub Actions (`.github/workflows/ci.yml`) ejecuta de forma paralela y secuencial:

1. **Security Scan**: Análisis SAST (`bandit`) y análisis de vulnerabilidades en dependencias (`pip-audit`).
2. **Type Check**: Verificación estática estricta con `mypy`.
3. **Linting**: Estilo y calidad de código con `ruff`.
4. **Test Matrix**: Ejecución de la suite con `pytest` y cálculo de cobertura en Python 3.10, 3.11 y 3.12.
5. **AI Model Gate**: Entrenamiento y validación de precisión mínima (>90%) del clasificador IA.
6. **Benchmark Gate**: Validación de F1-Score mínimo (>=95%) en detección de vulnerabilidades.
7. **Package Build & Release**: Empaquetado `wheel/sdist` y publicación automática en GitHub Releases/PyPI al etiquetar `v*`.

---

## Estructura del Proyecto

```
VulnScanner/
├── main.py                  # Punto de entrada CLI y orquestador del escaneo
├── api.py                   # API REST con FastAPI
├── train_ai.py              # Script de entrenamiento del modelo de IA
├── requirements.txt         # Dependencias del proyecto
├── requirements_ai.txt      # Dependencias del modulo de IA
├── pyproject.toml           # Metadata y configuracion del paquete
├── ruff.toml                # Configuracion de linting
├── Dockerfile               # Imagen Docker
├── docker-compose.yml       # Orquestacion de servicios
│
├── scanner/                 # Modulos de deteccion de vulnerabilidades
│   ├── headers.py
│   ├── models.py
│   ├── engine.py
│   ├── oast.py
│   ├── har_parser.py
│   ├── headless_crawler.py
│   ├── autofix.py
│   ├── dom_xss.py
│   ├── https_check.py
│   ├── cookies.py
│   ├── cors.py
│   ├── ssl_check.py
│   ├── xss.py
│   ├── sqli.py
│   ├── forms.py
│   ├── injections.py
│   ├── sensitive_data.py
│   ├── directories.py
│   ├── ports.py
│   ├── crawler.py
│   ├── fuzzer.py
│   ├── subdomains.py
│   ├── sca.py
│   ├── auth_helper.py
│   ├── ai_check.py
│   ├── path_traversal.py
│   ├── xxe.py
│   ├── open_redirect.py
│   ├── jwt_attacks.py
│   ├── file_upload.py
│   ├── prototype_pollution.py
│   ├── graphql.py
│   └── websocket.py
│
├── utils/                   # Utilidades del escaner
│   ├── report.py            # Generacion de reportes HTML y JSON
│   ├── sarif.py             # Exportacion OASIS SARIF v2.1.0
│   ├── stealth.py           # Control de trafico y rate-limiting
│   └── renderer.py          # Renderizado JS opcional con Playwright
│
├── models/                  # Modelo de IA entrenado (generado por train_ai.py)
├── reports/                 # Reportes HTML, JSON y base de datos SQLite
├── tests/                   # Suite de pruebas unitarias e integracion
│   ├── test_vulnscanner.py
│   ├── test_integration.py
│   ├── test_accuracy.py
│   ├── test_advanced_features.py
│   └── test_nextlevel_features.py
└── .github/workflows/       # CI/CD pipelines
    ├── ci.yml
    └── release.yml
```

---

## Etica y Uso Responsable

> **IMPORTANTE:** Esta herramienta esta disenada exclusivamente para fines **educativos y de seguridad defensiva**.

**Uso permitido:**
- Tus propias aplicaciones web
- Entornos de laboratorio y CTFs
- Sistemas para los que tienes autorizacion explicita por escrito
- Auditorias de seguridad contratadas formalmente

**Uso NO permitido:**
- Sitios web de terceros sin autorizacion
- Infraestructura publica o gubernamental sin permiso
- Cualquier actividad que viole leyes locales o internacionales

El uso no autorizado de herramientas de escaneo puede ser ilegal en tu jurisdiccion. El autor no se responsabiliza por el uso indebido de esta herramienta.

---

## Licencia

MIT License — Libre para usar, modificar y distribuir con atribucion.
