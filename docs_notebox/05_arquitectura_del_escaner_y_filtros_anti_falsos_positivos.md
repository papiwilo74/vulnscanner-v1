# Módulo 05: Arquitectura del Escáner y la Batalla contra los Falsos Positivos

## 1. La Diferencia entre un Script Amateur y una Herramienta de Ingeniería

Cualquiera puede escribir un script de 50 líneas en Python que itere una lista de URLs y envíe payloads con `requests.get()`. 

Sin embargo, ese script fallará estrepitosamente en el mundo real por tres razones:
1. **Colapso de Sockets:** Agota los puertos locales del sistema operativo al no reutilizar conexiones (quedando en estado `TIME_WAIT`).
2. **Avalancha de Falsos Positivos:** Reportará que cada ruta existe porque las aplicaciones modernas (SPAs) devuelven `HTTP 200` para cualquier enlace.
3. **Cero Concurrencia Inteligente:** O bien tardará 12 horas en escanear un sitio, o bien enviará 1,000 hilos sin control y tumbará el servidor del cliente (DoS involuntario).

---

## 2. Arquitectura Modular del Motor OmniBreach

El motor de escaneo está diseñado bajo el principio de responsabilidad única, separando la orquestación, los detectores y los modelos de datos:

```
                                [ Usuario / CLI / API ]
                                           |
                                           v
                              [ ScanEngine (Orquestador) ]
                                           |
                   +-----------------------+-----------------------+
                   |                       |                       |
                   v                       v                       v
          [ Perfil Rápido ]       [ Perfil Balanceado ]     [ Perfil Profundo ]
          (Cabeceras, SSL)       (+ SQLi, XSS, CORS)      (+ Fuzzing, OAST, Playwright)
                   |                       |                       |
                   +-----------------------+-----------------------+
                                           |
                                           v
                             [ ThreadPoolExecutor (Hilos) ]
                                           |
                   +-----------------------+-----------------------+
                   |                       |                       |
                   v                       v                       v
           [ Módulo SQLi ]          [ Módulo XSS ]          [ Módulo CORS ]
                   |                       |                       |
                   +-----------------------+-----------------------+
                                           |
                                           v
                           [ Desduplicación y Deducción ]
                                           |
                                           v
                           [ Modelos Finding Normalizados ]
                                           |
                   +-----------------------+-----------------------+
                   |                       |                       |
                   v                       v                       v
             [ Base SQLite ]        [ Reporte JSON/SARIF ]    [ WebSocket UI ]
```

### 2.1 Concurrencia y Connection Pooling
Para maximizar el rendimiento sin saturar la red, se utiliza `ThreadPoolExecutor` acoplado a un `requests.Session` compartido. Esto permite la reutilización de conexiones TCP mediante **HTTP Keep-Alive** a nivel del pool de `urllib3`, reduciendo la latencia de cada prueba en un 70%.

---

## 3. La Batalla contra los Falsos Positivos: Algoritmos de Precisión

Un escáner que genera 100 alertas falsas es inútil: los ingenieros de seguridad aprenden a ignorarlo. OmniBreach implementa algoritmos específicos para neutralizar los tres mayores focos de falsos positivos en la web moderna:

### 3.1 El Problema de las Single Page Applications (SPAs) y el "Soft-404"
En frameworks como React, Angular o Next.js, el servidor web no devuelve un código `HTTP 404 Not Found` cuando una ruta no existe. En su lugar, devuelve `HTTP 200 OK` con el archivo `index.html` base y deja que el router de JavaScript del cliente dibuje la pantalla de "Página no encontrada".

* **El Error Amateur:** El escáner prueba `/admin`, recibe `HTTP 200` y reporta: *"¡Panel de administración expuesto!"*.
* **La Solución en OmniBreach ([`scanner/directories.py`](file:///c:/Users/villa/VulnScanner/scanner/directories.py)):**
  El escáner genera primero una petición de **Canario Imposible** (`/_soft404_canary_xyz_123`).
  - Almacena el código de respuesta, longitud y hash del cuerpo retornado.
  - Si una ruta probada (ej. `/backup.zip`) devuelve exactamente la misma longitud, estructura DOM o hash que el canario, se descarta automáticamente como un **Soft-404**.

---

### 3.2 Doble Verificación en Redirecciones Abiertas (Open Redirect)
Muchos sitios web tienen parámetros como `?redirect=/home` que siempre redirigen a una ruta interna fija, independientemente de lo que el usuario ingrese.

* **El Error Amateur:** El escáner inyecta `?redirect=https://evil.com`, ve un código `302 Found` y reporta la vulnerabilidad sin leer la cabecera `Location`.
* **La Solución en OmniBreach ([`scanner/open_redirect.py`](file:///c:/Users/villa/VulnScanner/scanner/open_redirect.py)):**
  Se aplica un **test de doble dominio independiente**:
  1. Se prueba `target_url?url=https://evil-phishing-site.com`.
  2. Se prueba `target_url?url=https://control-verify-target.org`.
  3. Solo si la cabecera `Location` refleja dinámicamente ambos dominios externos de forma exacta, se confirma la vulnerabilidad con `confidence="confirmed"`.

---

### 3.3 El Sistema de Niveles de Confianza (Confidence Scoring)

Cada hallazgo producido por el escáner se clasifica bajo un estándar estricto de confianza:

```python
class Finding(BaseModel):
    vuln: str
    risk: Literal["Crítico", "Alto", "Medio", "Bajo", "Informativo"]
    detail: str
    confidence: Literal["confirmed", "probable", "heuristic"]
```

| Nivel de Confianza | Significado Operativo | Acción del Auditor |
| :--- | :--- | :--- |
| **`confirmed`** | **Demostrado matemáticamente o empíricamente.** El payload ejecutó código, extrajo datos o cumplió el diferencial estricto. | Se bloquea el pipeline de despliegue (CI/CD) inmediatamente; cero intervención humana requerida. |
| **`probable`** | **Fuerte evidencia heurística.** Coincidencia en código propio o respuestas sospechosas que requieren mínima confirmación. | Revisión en el siguiente ciclo de desarrollo. |
| **`heuristic`** | **Observación informativa.** Ausencia de cabeceras de endurecimiento o prácticas no recomendadas. | Informativo para hardening. |

---

## 4. Preguntas Clave para Estudio y Guión de Video

1. **¿Por qué el reutilizar una sesión HTTP (`requests.Session`) es fundamental al ejecutar escaneos de alta concurrencia?**
   * *Respuesta:* Porque reutiliza las conexiones TCP ya negociadas (Keep-Alive), evitando la sobrecarga de hacer handshakes TCP/TLS continuos y previniendo el agotamiento de puertos efímeros en el sistema operativo del auditor.
2. **¿En qué consiste la técnica del "canario" para detectar Soft-404 en sitios construidos con React o Vue?**
   * *Respuesta:* Consiste en solicitar intencionalmente una ruta aleatoria inexistente antes de iniciar el escaneo para capturar la firma (cuerpo y tamaño) de la plantilla 200 que la SPA usa para rutas no encontradas, usándola como filtro de descarte.
3. **¿Por qué la desduplicación de hallazgos (`deduplicate_findings`) es un requerimiento crítico en arquitecturas corporativas?**
   * *Respuesta:* Porque diferentes módulos o múltiples páginas de una aplicación pueden reportar el mismo problema sistemático (ej. una cookie sin HttpOnly en 50 URLs distintas), saturando el informe técnico si no se agrupan en una única vulnerabilidad raíz.
