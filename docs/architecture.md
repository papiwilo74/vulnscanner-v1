# Arquitectura y Diseño Técnico de VulnScanner

Este documento detalla la arquitectura interna, los flujos de ejecución, los mecanismos de seguridad operacional y las especificaciones de datos de **VulnScanner**.

---

## 1. Visión General del Sistema

VulnScanner es una plataforma de análisis de seguridad web modular orientada a DevSecOps. Combina cuatro metodologías de detección complementarias:

1. **DAST (Dynamic Application Security Testing):** Inyección controlada de vectores activos (SQLi, XXE, SSTI, Command Injection, Path Traversal, Open Redirect) con calibración basada en tiempo y firmas de error.
2. **SAST (Static Application Security Testing):** Análisis sintáctico y de flujo en scripts JavaScript embebidos y remotos para detección de DOM XSS, Prototype Pollution y fuga de secretos.
3. **SCA (Software Composition Analysis):** Inspección de dependencias frontend populares contra bases de datos de vulnerabilidades conocidas.
4. **OAST (Out-of-Band Application Security Testing):** Identificación de vulnerabilidades ciegas (Blind SSRF, Blind XXE, Blind RCE) mediante callbacks asíncronos correlacionados por tokens unívocos.

```mermaid
graph TD
    User["CLI / CI Pipeline / REST Client"] --> Engine["ScanEngine (scanner/engine.py)"]
    
    subgraph "Control Operacional y Seguridad"
        Engine --> RL["Token Bucket Rate Limiter (max_rps)"]
        Engine --> SSRF["Private IP Guard (RFC 1918 / Loopback)"]
        Engine --> Dedup["URL & Scope Deduplicator"]
        Engine --> Cancel["Cancellation Event Bus"]
    end

    subgraph "Fase 1: Reconocimiento y Descubrimiento"
        RL --> Crawler["Crawler & SPA Headless (Playwright)"]
        RL --> Subdomains["DNS / Subdomain Enumeration"]
        RL --> Fuzzer["Fuzzing de Archivos Sensibles"]
    end

    subgraph "Fase 2: Motores de Análisis Concurrente"
        Crawler --> DAST["DAST Activo (SQLi, SSTI, RCE, XXE, Path Traversal)"]
        Crawler --> SAST["SAST (DOM XSS, Secretos, Prototype Pollution)"]
        Crawler --> OAST["OAST Engine (Blind SSRF/XXE Callbacks)"]
        Crawler --> ML["ML Classifier (TF-IDF + Regresión Logística)"]
    end

    subgraph "Fase 3: Normalización y Remediación"
        DAST --> Norm["Normalizador de Hallazgos (Finding Model)"]
        SAST --> Norm
        OAST --> Norm
        ML --> Norm
        Norm --> AutoFix["Auto-Fix & Tech Fingerprinter (Express, Django, Nginx...)"]
    end

    subgraph "Fase 4: Reportes Estándar"
        AutoFix --> HTML["Dashboard HTML Interactivo (Modo Oscuro)"]
        AutoFix --> JSON["JSON Report (SIEM Ingestion)"]
        AutoFix --> SARIF["OASIS SARIF v2.1.0 (GitHub / GitLab Code Scanning)"]
    end
```

---

## 2. Motor Central y Seguridad Operacional (`scanner/engine.py`)

El componente `ScanEngine` actúa como orquestador centralizado de todos los módulos de escaneo. Implementa salvaguardas críticas para evitar degradación del objetivo o incidentes de denegación de servicio (DoS):

### Perfiles de Escaneo (`ScanProfile`)

| Perfil | Max RPS | Total Requests | Timeout | Payloads Activos | Profundidad Crawl | Workers | Retardo |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`passive`** | 2 | 200 | 15s | No (Solo análisis estático / cabeceras) | 1 | 3 | 1.0s |
| **`normal`** | 10 | 1,000 | 10s | Sí | 3 | 8 | 0.2s |
| **`aggressive`** | 50 | 5,000 | 8s | Sí | 5 | 20 | 0.05s |

### Mitigación de SSRF Operacional (`PRIVATE_RANGES`)
Para evitar que un escáner sea utilizado como pivote para atacar redes internas o interfaces de metadatos de nube (`169.254.169.254`), el motor valida la resolución DNS del host objetivo contra los bloques:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16`

A menos que se especifique `--allow-private`, cualquier intento de escanear estas direcciones es abortado de forma inmediata.

---

## 3. Modelo de Datos Estandarizado (`scanner/models.py`)

Cada hallazgo se transforma en una instancia inmutable del modelo `Finding`, el cual mapea automáticamente la taxonomía de seguridad:

- **CVSS v3.1:** Cálculo del puntaje base según vector formal (`CVSS:3.1/AV:N/AC:L/...`).
- **CWE (Common Weakness Enumeration):** Asociación taxonómica (ej. `CWE-89` para SQLi, `CWE-79` para XSS).
- **MITRE ATT&CK:** Mapeo de técnicas tácticas (ej. `T1190` - Exploit Public-Facing Application).
- **OWASP Top 10 2021:** Clasificación en las categorías A01 a A10.
- **Evidencia Técnica (`Evidence`):** Almacenamiento estructurado del método HTTP, URL de prueba, payload inyectado, código de respuesta HTTP y fragmento textual de confirmación.

---

## 4. Pipeline de Remediación y Auto-Fix (`scanner/autofix.py`)

VulnScanner no solo reporta la vulnerabilidad, sino que identifica el stack tecnológico mediante fingerprinting de cabeceras (`Server`, `X-Powered-By`) y patrones HTML/Cookies:
- **Node.js / Express**
- **Python / Django / FastAPI**
- **PHP / Laravel**
- **Nginx / Apache**
- **React / Next.js**

A partir de esta firma, genera snippets de código contextuales listos para aplicar (ej. configuración segura de cabeceras en `nginx.conf`, middleware `helmet` en Express o validación parametrizada con SQLAlchemy).

---

## 5. Especificación de API REST (`api.py`)

La API REST permite la automatización e integración con orquestadores CI/CD y plataformas SOAR:

- **Base de Datos:** SQLite con soporte `WAL` (Write-Ahead Logging) y control de concurrencia mediante `threading.Lock`.
- **Endpoints:**
  - `GET /` — Healthcheck y versión del servicio.
  - `POST /scan` — Encola una tarea asíncrona de escaneo (`BackgroundTasks`).
  - `GET /scan/{task_id}` — Consulta estado de la tarea y resultados detallados.
  - `GET /scans` — Historial paginado de escaneos ejecutados.
  - `GET /docs` — Swagger UI interactivo.
  - `GET /openapi.json` — Contrato OpenAPI 3.1 descargable ([docs/openapi.json](openapi.json)).

---

## 6. Despliegue en Entornos Empresariales (Docker y Kubernetes)

VulnScanner está preparado para ejecutarse como un worker efímero o como servicio continuo:

### Docker Compose
```bash
# Iniciar API REST
docker compose up -d api

# Ejecutar escaneo CLI bajo demanda
docker compose run --rm cli https://target.local --stealth --no-open
```

### Modelo Kubernetes CronJob (Auditorías Programadas)
Para escaneos periódicos en clústeres empresariales, se recomienda desplegar la imagen como un `CronJob` que ejecute el CLI con salida hacia un bucket S3 o volumen compartido montado en `/reports`.
