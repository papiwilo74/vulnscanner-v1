# 🗓️ Plan de Estudio Compacto: OmniBreach (Octubre – Principios de Diciembre)

> **Duración:** 9 semanas (~2 meses)  
> **Dedición sugerida:** 2 a 3 horas por semana.  
> **Objetivo:** Dominio conceptual, arquitectónico y práctico de OmniBreach para sustentar con solvencia técnica en grado y entrevistas.

---

## Estructura General

```
           OCTUBRE (Mes 1)                     NOVIEMBRE (Mes 2)                PCOS. DICIEMBRE
       [ El Motor y la Red ]             [ Inyecciones, OAST y APIs ]        [ Mitigación y Cierre ]
 ----------------------------------   ----------------------------------   --------------------------
 Sem 1: Entrada, CLI y Pipeline       Sem 5: SQLi, XSS y DOM Taint         Sem 9: DLP (Luhn), WAF
 Sem 2: AsyncIO, Rate Limiting y CB   Sem 6: Entropía de Shannon & WAF            Patching y Simulacro
 Sem 3: Crawler Dinámico (Playwright) Sem 7: Servidor OAST (DNS UDP 53)           Final de Grado
 Sem 4: Superficie Pasiva: CORS/CSP   Sem 8: APIs (BOLA), JWT y TOTP
```

---

## 🍂 MES 1: OCTUBRE — Núcleo, Red y Rastreo Dinámico

### Semana 1 (1 al 7 de Octubre): La Puerta de Entrada y el Pipeline
* **Archivos clave:** [`main.py`](../main.py).
* **Conceptos:**
  * Cómo `argparse` procesa perfiles (`passive`, `normal`, `aggressive`).
  * Orquestación del flujo: orden en que se ejecutan los módulos sin colisiones.
* **Pregunta de grado:** *¿Por qué separar la fase de descubrimiento (crawling) de la fase de explotación controlada?*

### Semana 2 (8 al 14 de Octubre): Concurrencia Asíncrona y Resiliencia
* **Archivos clave:** [`scanner/engine.py`](../scanner/engine.py), [`scanner/async_engine.py`](../scanner/async_engine.py), [`scanner/rate_limiter.py`](../scanner/rate_limiter.py).
* **Conceptos:**
  * `asyncio` vs hilos tradicionales (cómo manejar 20+ peticiones sin saturar memoria).
  * Control de flujo (*Token Bucket* / *Sliding Window*) y *Circuit Breakers* para pausar ante HTTP 429.
* **Pregunta de grado:** *¿Cómo garantiza el escáner que no provocará una denegación de servicio (DoS) en el objetivo?*

### Semana 3 (15 al 21 de Octubre): Rastreador Dinámico para SPAs (React/Vite)
* **Archivos clave:** [`scanner/headless_crawler.py`](../scanner/headless_crawler.py).
* **Conceptos:**
  * Por qué un crawler tradicional basado en expresiones regulares no ve las rutas de aplicaciones React/Vite.
  * Uso de Playwright con Chromium invisible para interactuar con botones y renderizar el DOM real.
* **Pregunta de grado:** *¿Qué diferencia técnica existe entre inspeccionar el código fuente HTML y el DOM computado en tiempo de ejecución?*

### Semana 4 (22 al 31 de Octubre): Superficie Pasiva (CORS, Headers y Cookies)
* **Archivos clave:** [`scanner/headers.py`](../scanner/headers.py), [`scanner/cookies.py`](../scanner/cookies.py), [`scanner/cors.py`](../scanner/cors.py).
* **Conceptos:**
  * Por qué `Access-Control-Allow-Origin: *` es peligroso cuando hay credenciales.
  * Análisis de directivas CSP (`unsafe-inline`) y atributos de cookies (`HttpOnly`, `SameSite`, `Secure`).
* **Pregunta de grado:** *¿Cómo mitiga la cabecera Content-Security-Policy el impacto de un ataque XSS?*

---

## 🍁 MES 2: NOVIEMBRE — Ataques Activos, Sockets y APIs

### Semana 5 (1 al 7 de Noviembre): Inyecciones Clásicas (SQLi y XSS)
* **Archivos clave:** [`scanner/sqli.py`](../scanner/sqli.py), [`scanner/xss.py`](../scanner/xss.py).
* **Conceptos:**
  * Detección por firmas de error de motor de base de datos vs inyección booleana diferencial.
  * Rastrear fuentes (*sources*) y sumideros (*sinks*) en JavaScript.
* **Pregunta de grado:** *¿Cómo comprueba el escáner una inyección SQL sin alterar ni borrar datos de la base de datos?*

### Semana 6 (8 al 14 de Noviembre): Reducción de Falsos Positivos y Entropía de Shannon
* **Archivos clave:** [`scanner/precision.py`](../scanner/precision.py), [`utils/adaptive_client.py`](../utils/adaptive_client.py).
* **Conceptos:**
  * La fórmula matemática de la **Entropía de Shannon** para medir aleatoriedad en cadenas de texto.
  * Cómo descartar falsas alarmas provocadas por respuestas de error genéricas de WAFs (Cloudflare/ModSecurity).
* **Pregunta de grado:** *¿Por qué la entropía de Shannon es superior a una expresión regular para detectar secretos filtrados?*

### Semana 7 (15 al 21 de Noviembre): Detección Fuera de Banda (OAST) a Bajo Nivel
* **Archivos clave:** [`scanner/oast.py`](../scanner/oast.py).
* **Conceptos:**
  * Servidor DNS autoritativo propio escuchando en UDP puerto 53.
  * Desempaquetado de encabezados de paquetes RFC 1035 con `struct.unpack`.
  * Confirmación determinista de vulnerabilidades ciegas (Blind SSRF y Blind XXE).
* **Pregunta de grado:** *¿Cómo funciona la correlación fuera de banda cuando el servidor web no devuelve ningún mensaje de error al atacante?*

### Semana 8 (22 al 30 de Noviembre): Seguridad en APIs y Autenticación Dinámica
* **Archivos clave:** [`scanner/api_security.py`](../scanner/api_security.py), [`scanner/auth_helper.py`](../scanner/auth_helper.py), [`scanner/totp.py`](../scanner/totp.py).
* **Conceptos:**
  * OWASP API Top 10: BOLA (Broken Object Level Authorization) y Mass Assignment.
  * Renovación autónoma de tokens JWT ante HTTP 401 y generación de claves temporales TOTP (RFC 6238).
* **Pregunta de grado:** *¿Cómo detecta el escáner una falla de autorización BOLA utilizando dos identidades distintas?*

---

## ❄️ PRINCIPIOS DE DICIEMBRE — Mitigación, WAF y Cierre

### Semana 9 (1 al 7 de Diciembre): Defensa Activa y Simulacro Final
* **Archivos clave:** [`scanner/dlp.py`](../scanner/dlp.py), [`scanner/virtual_patching.py`](../scanner/virtual_patching.py), [`scanner/compliance.py`](../scanner/compliance.py).
* **Conceptos:**
  * Validación de tarjetas de crédito mediante el **Algoritmo de Luhn (Mod-10)**.
  * Generación de reglas de mitigación inmediata (Virtual Patching) para ModSecurity, AWS WAF y Cloudflare.
  * Mapeo de hallazgos contra marcos normativos (PCI-DSS v4.0 y OWASP).
* **Simulacro de Sustentación:**
  * Ensayo general con las 10 preguntas más frecuentes de jurados y reclutadores técnicos.
* **Hito de Cierre:** OmniBreach 100% dominado y archivado. Listo para continuar con el siguiente proyecto en enero.
