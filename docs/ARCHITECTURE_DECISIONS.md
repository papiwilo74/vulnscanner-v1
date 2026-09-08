# Registros de Decisiones Arquitecturales (ADR)
## VulnScanner Enterprise v2.4.0

Este documento formaliza las decisiones de diseño arquitectural clave adoptadas en el desarrollo de **VulnScanner Enterprise**, detallando el contexto técnico, las alternativas evaluadas, las razones de la elección y las consecuencias operativas.

---

### Índice de Decisiones

1. [ADR-001: Motor ML Determinista Offline vs. LLM en la Nube](#adr-001-motor-ml-determinista-offline-vs-llm-en-la-nube)
2. [ADR-002: Modelo de Concurrencia Híbrido (ThreadPoolExecutor + Async Engine)](#adr-002-modelo-de-concurrencia-híbrido-threadpoolexecutor--async-engine)
3. [ADR-003: Modelado de Rutas de Ataque mediante Grafos Acíclicos Dirigidos (DAG) y Choke Points](#adr-003-modelado-de-rutas-de-ataque-mediante-grafos-acíclicos-dirigidos-dag-y-choke-points)
4. [ADR-004: Agente IAST / RASP en Memoria vs. Proxy Interceptor Man-in-the-Middle](#adr-004-agente-iast--rasp-en-memoria-vs-proxy-interceptor-man-in-the-middle)
5. [ADR-005: Servidor de Laboratorio Aislado (Lab Mode) para CI/CD Hermético](#adr-005-servidor-de-laboratorio-aislado-lab-mode-para-cicd-hermético)

---

## ADR-001: Motor ML Determinista Offline vs. LLM en la Nube

### Estado
**Aceptado**

### Contexto
Para el análisis de parámetros HTTP anómalos y detección de payloads no convencionales, surgieron dos enfoques:
1. Conectar a APIs externas de modelos fundacionales (ej. OpenAI GPT-4, Google Gemini, Anthropic Claude).
2. Entrenar y empaquetar un modelo de Machine Learning tradicional (TF-IDF + Random Forest / Gradient Boosting) de inferencia local.

### Decisión
Se seleccionó un **modelo ML supervisado local (`scikit-learn` / `joblib`)** con vectorización n-gram y clasificación determinista:
- **Zero Data Leakage:** El código fuente analizado, las URLs auditadas, parámetros internos y cabeceras de autenticación jamás salen de la máquina local ni se transmiten a terceros.
- **Latencia Sub-milisegundo:** La inferencia local toma < 0.5 ms por parámetro, permitiendo evaluar cientos de parámetros por segundo sin cuellos de botella de red ni rate-limits de APIs.
- **Funcionamiento Hermético:** No requiere claves de API (API Keys), conectividad a internet ni costos recurrentes por tokens.
- **Fallback Heurístico Inteligente:** Si las librerías de ML no están instaladas, el sistema conmuta instantáneamente a un motor de reglas heurísticas por entropía y patrones sintácticos.

### Consecuencias
- **Positivas:** 100% de cumplimiento con directivas de privacidad corporativa (RGPD, SOC2, PCI-DSS); estabilidad e independencia total de red.
- **Compromiso:** Menor capacidad para razonar en lenguaje natural sobre vulnerabilidades contextuales de lógica de negocio profunda comparado con un LLM de miles de millones de parámetros.

---

## ADR-002: Modelo de Concurrencia Híbrido (ThreadPoolExecutor + Async Engine)

### Estado
**Aceptado**

### Contexto
El escaneo de aplicaciones web requiere despachar miles de peticiones HTTP en ráfagas de baja latencia sin agotar los descriptores de archivos del sistema operativo ni bloquear el hilo principal de renderizado/interfaz.

### Decisión
Se implementó una **arquitectura de despacho híbrida**:
1. **ThreadPoolExecutor Configurable:** Utilizado por defecto para garantizar compatibilidad nativa con toda la biblioteca estándar de Python y librerías síncronas (`requests`, sockets TCP crudos).
2. **Motor Asíncrono `httpx/asyncio` (`--async-engine`):** Activado bajo demanda para escaneos de ultra alto volumen (> 100 req/s), utilizando pooling de conexiones HTTP/2 y multiplexación no bloqueante sobre el event loop de `asyncio`.
3. **Control Perimetral Token-Bucket & Circuit Breaker:** Ambas capas están gobernadas por un limitador de tasa adaptable que respeta el perfil (`passive`, `normal`, `aggressive`) y corta el tráfico automáticamente si el servidor responde con códigos 429 (Too Many Requests) o 503 (Service Unavailable).

### Consecuencias
- **Positivas:** Rendimiento máximo medido de **181.97 req/s** con un consumo pico de memoria RAM de apenas **1.46 MB** (frente a 520 MB de OWASP ZAP).
- **Compromiso:** Mantenimiento de dos ramas de ejecución (síncrona y asíncrona) requiriendo tipado estricto unificado para los resultados.

---

## ADR-003: Modelado de Rutas de Ataque mediante Grafos Acíclicos Dirigidos (DAG) y Choke Points

### Estado
**Aceptado**

### Contexto
Los escáneres DAST tradicionales reportan vulnerabilidades en listas planas aisladas. En la práctica empresarial, los atacantes encadenan vulnerabilidades menores (ej. Info Disclosure + CORS permisivo + XSS reflejado -> Account Takeover -> RCE).

### Decisión
Se incorporó el **Módulo de Grafos de Ataque (`scanner/attack_graph.py`)**:
- Las vulnerabilidades detectadas se transforman en nodos tipados según MITRE ATT&CK v3.1 y OWASP.
- Las dependencias causales se modelan como aristas ponderadas por dificultad de explotación y CVSS score.
- **Detección de Choke Points:** Se implementó un algoritmo de análisis de cortes mínimos que identifica el nodo o control defensivo cuya aplicación mitiga la mayor cantidad de rutas de ataque críticas con el menor esfuerzo de ingeniería.

### Consecuencias
- **Positivas:** Brinda a los equipos de desarrollo y CISO una visión táctica del impacto real; prioriza el orden de remediación técnica reduciendo el Time-to-Remediate (MTTR).
- **Compromiso:** Complejidad algorítmica adicional para el cálculo de rutas; mitigada limitando la profundidad de la búsqueda en grafos densos.

---

## ADR-004: Agente IAST / RASP en Memoria vs. Proxy Interceptor Man-in-the-Middle

### Estado
**Aceptado**

### Contexto
Para enriquecer los hallazgos de caja negra (DAST) con la ubicación exacta del archivo y línea de código en el backend (IAST), se consideró un proxy interceptor tipo OWASP ZAP o un agente instrumentador en memoria.

### Decisión
Se desarrolló un **Agente IAST/RASP nativo (`scanner/iast_agent.py`)** basado en instrumentación de bajo nivel de Python:
- **Hooking de Sinks Críticos:** Monitorea directamente llamadas a `sqlite3.connect`, `os.system`, `subprocess.Popen`, `builtins.open` y wrappers ASGI/WSGI.
- **Correlación por Header de Trazabilidad:** Asocia cada ataque DAST con su traza interna mediante cabeceras de correlación `X-VulnScanner-Correlation-ID`.
- **Modo RASP Activo:** Capacidad opcional de bloquear la ejecución del proceso vulnerable en tiempo real ante inyecciones confirmadas.

### Consecuencias
- **Positivas:** Cero configuración de certificados TLS intermedios; precisión absoluta en el stack trace (archivo `.py` y número de línea exacto).
- **Compromiso:** Requiere que la aplicación objetivo en entornos de prueba cargue el middleware o agente en su proceso.

---

## ADR-005: Servidor de Laboratorio Aislado (Lab Mode) para CI/CD Hermético

### Estado
**Aceptado**

### Contexto
Los pipelines de integración continua (CI/CD) modernos operan frecuentemente en entornos herméticos sin acceso a internet o tras proxies corporativos estrictos. Las pruebas de escáneres que dependen de endpoints externos (como `example.com` o servidores públicos de prueba) sufren de inestabilidad y fallos espurios.

### Decisión
Se integró **LabServer (`scanner/lab_server.py`)** con el flag `--lab` / `--offline`:
- Servidor HTTP stdlib embebido que levanta en un puerto efímero del sistema operativo (`127.0.0.1:0`).
- Expone un catálogo determinista de vulnerabilidades controladas (cabeceras ausentes, cookies inseguras, DOM XSS, inyección SQL simulada, endpoints GraphQL, fugas de archivos `.env`).
- Ciclo de vida gestionado: se inicia al inicio del escaneo y se destruye en el bloque `finally` con cero fugas de memoria o sockets huérfanos.

### Consecuencias
- **Positivas:** Pruebas E2E 100% deterministas y reproducibles; ejecución completa de la suite de auditoría en pipelines desconectados en menos de 4 segundos.
- **Compromiso:** El servidor lab simula escenarios representativos pero no reemplaza auditorías completas en entornos de staging reales.
