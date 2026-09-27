# OmniBreach — Hoja de Ruta y Trabajo Futuro (Roadmap 2027)

> **Estado del Proyecto:** Congelado y Estable (v3.9).  
> **Propósito de este Documento:** Preservar de forma estructurada las líneas de investigación avanzada y desarrollo futuro identificadas para la evolución del escáner en 2027, tras la culminación de la fase de validación y defensa académica.

---

## 1. Contexto Estratégico

OmniBreach v3.9 ha alcanzado la madurez de su núcleo dinámico (DAST) con:
- Cobertura completa de OWASP Top 10 y API Security Top 10.
- Infraestructura OAST dedicada (servidor DNS autoritativo RFC 1035 UDP 53 y HTTP).
- Síntesis automática de parches virtuales (ModSecurity, AWS WAF, Cloudflare, Nginx).
- Motor de prevención de fuga de datos (DLP con algoritmo Luhn Mod-10).
- Suite de 481 pruebas unitarias automatizadas con tipado estricto (`mypy --strict`).

Para el ciclo de investigación y desarrollo correspondiente a **2027**, se definen cuatro pilares de evolución técnica hacia la frontera de la seguridad de aplicaciones:

---

## 2. Los 4 Pilares de Investigación para 2027

```
                     PILARES DE EVOLUCIÓN TÉCNICA (2027)
                     
     [ 1. IAST Runtime ]            [ 2. V8 DOM Engine Hooking ]
     Agente en memoria del proceso   Interceptación de prototipos nativos
     con análisis de flujo Taint.   en Chromium vía DevTools Protocol.
     
     [ 3. Fuzzing Binario gRPC ]    [ 4. Inferencia de Lógica L* ]
     Mutación de Protocol Buffers   Aprendizaje de autómatas finitos
     sobre HTTP/2 y WebSockets.     para flujos de negocio multi-paso.
```

---

### Pilar 1: Agente IAST en Tiempo de Ejecución (Interactive AST)

* **Objetivo:** Superar la limitación inherente de los escáneres DAST de caja negra mediante la inspección interactiva del flujo de ejecución en memoria.
* **Arquitectura Prevista:**
  * Desarrollo de un agente ligero (`scanner/agent/`) integrable como middleware WSGI/ASGI (Python) y agente de instrumentación de bytecode (Java JVM).
  * Uso de ganchos en tiempo de ejecución (`sys.settrace` o reescritura de árboles de sintaxis abstracta AST) para marcar datos provenientes de peticiones HTTP como *contaminados* (`tainted`).
  * Trazabilidad directa del dato contaminado hasta los sumideros críticos (`cursor.execute()`, `os.system()`, `eval()`), permitiendo reportar el archivo exacto y número de línea de la vulnerabilidad en el código fuente.

---

### Pilar 2: Instrumentación Nativa de V8 / Chromium (CDP Hooking)

* **Objetivo:** Detección de vulnerabilidades DOM-XSS complejas en Single Page Applications (SPAs) sin falsos positivos por análisis estático heurístico.
* **Arquitectura Prevista:**
  * Extensión del subsistema de navegación headless utilizando sesiones directas del Chrome DevTools Protocol (`Page.addScriptToEvaluateOnNewDocument`).
  * Sobrescritura de prototipos JavaScript nativos (`Element.prototype.setAttribute`, `Element.prototype.innerHTML`, `document.write`, `eval`) antes de la ejecución de cualquier script del sitio.
  * Captura de trazas de pila (*call stacks*) completas en el motor V8 cuando un payload inyectado por OmniBreach alcanza un sumidero real en el navegador.

---

### Pilar 3: Fuzzing de Protocolos Binarios Modernos (gRPC & Protobuf)

* **Objetivo:** Extender las capacidades de auditoría más allá de interfaces REST y GraphQL hacia microservicios de alto rendimiento basados en RPC.
* **Arquitectura Prevista:**
  * Motor de decodificación y ensamblado de wire-format de Protocol Buffers (manejo de *varints*, tipos de cableado 0, 1, 2, 5) sin requerir el archivo de definición `.proto` original.
  * Mutador probabilístico de streams binarios sobre canales multiplexados HTTP/2 y WebSockets binarios.
  * Análisis de respuestas ante deserialización anómala, desbordamientos de enteros y denegación de servicio a nivel de llamada RPC.

---

### Pilar 4: Inferencia Formal de Máquinas de Estado para Lógica de Negocio

* **Objetivo:** Identificar vulnerabilidades de lógica de negocio en flujos transaccionales complejos (e-commerce, pasarelas de pago, onboarding) que no pueden ser detectadas con ataques de inyección tradicionales.
* **Arquitectura Prevista:**
  * Implementación de una adaptación del **Algoritmo L\* de Angluin** para el aprendizaje activo de autómatas de estados finitos (máquinas de Mealy).
  * El escáner interactúa con la aplicación generando consultas de membresía (*membership queries*) para construir el grafo de transiciones válidas e inválidas del flujo.
  * Detección automática de saltos de etapa no autorizados (por ejemplo, transicionar de "carrito de compras" a "confirmación de despacho" sin pasar por "procesamiento de pago").

---

## 3. Cronograma y Metodología de Ejecución (2027)

| Fase | Periodo Estimado | Hito Técnico Principal |
| :--- | :--- | :--- |
| **Fase 1: IAST Core** | Q1-Q2 2027 | Prototipo del agente de instrumentación en memoria para Python/FastAPI. |
| **Fase 2: V8 Hooking** | Q2 2027 | Integración de hooks CDP en el crawler dinámico de Chromium. |
| **Fase 3: gRPC Fuzzing** | Q3 2027 | Parser de wire-format Protobuf y fuzzing sobre HTTP/2. |
| **Fase 4: State Machine L\*** | Q4 2027 | Inferencia de autómatas y auditoría de lógica de negocio transaccional. |

---

## 4. Registro y Validez Académica

Este documento forma parte integral del repositorio y sirve como base formal para la sección de **"Trabajo Futuro y Líneas de Investigación"** en la monografía y defensa del proyecto de grado.
