# 📘 GUÍA DE ESTUDIO SEMANA 1: La Puerta de Entrada y el Pipeline de OmniBreach

> **Documento optimizado para NoteBox / NotebookLM (Generación de Podcast, Presentaciones y Resúmenes Ejecutivos)**  
> **Módulo:** 01 — Arquitectura de Orquestación y Línea de Comandos (CLI)  
> **Archivo del Código Fuente:** `main.py`  
> **Duración estimada de estudio:** 2 a 3 horas  

---

## 1. El Problema que Resuelve este Módulo (La Historia Humana)

Imagina un hospital de emergencias o una orquesta sinfónica. Si no existe un director que asigne turnos, defina el orden de las intervenciones y controle los tiempos, el resultado es el caos: los músicos tocan al mismo tiempo o los médicos interfieren entre sí.

En el software de ciberseguridad ocurre exactamente lo mismo:
* Si un escáner web intenta inyectar ataques de Base de Datos (SQLi), probar scripts en el navegador (XSS), rastrear enlaces y enviar peticiones masivas en el mismo milisegundo:
  1. **El servidor colapsa:** Se produce una Denegación de Servicio (DoS) involuntaria.
  2. **Los Firewalls bloquean la IP:** Un WAF como Cloudflare detecta una ráfaga anómala y devuelve códigos `HTTP 429 Too Many Requests`.
  3. **El escáner trabaja a ciegas:** Intenta atacar formularios que ni siquiera sabe si existen.

**La solución de ingeniería:** Crear un **Director de Orquesta**. En OmniBreach, ese director es el archivo [`main.py`](../main.py). Su trabajo no es atacar ni fuzear directamente; su función es recibir las órdenes del usuario, validar la seguridad de la operación y ejecutar un **Pipeline Lineal de 6 Fases**.

---

## 2. Anatomía de la Entrada: ¿Cómo lee `main.py` la Terminal?

Cuando escribes en tu consola:
```powershell
python main.py https://www.orderflowapp.online/ --crawl 20 --headless-crawl --compliance
```

El script utiliza el módulo nativo de Python llamado **`argparse`** (Argument Parser).

### ¿Qué hace `argparse` por debajo?
Convierte el texto crudo de la terminal en un objeto estructurado (`args`) con atributos accesibles:

1. **Parámetro Posicional (Obligatorio o Principal):**
   ```python
   parser.add_argument("url", nargs="?", default=None, help="URL del sitio web a escanear")
   ```
   * *Resultado:* `args.url = "https://www.orderflowapp.online/"`

2. **Parámetro con Valor Numérico:**
   ```python
   parser.add_argument("--crawl", type=int, default=0, help="Número de páginas a rastrear")
   ```
   * *Resultado:* `args.crawl = 20`

3. **Banderas Booleanas (Interruptores On/Off):**
   ```python
   parser.add_argument("--headless-crawl", action="store_true", help="Activa navegador Playwright")
   parser.add_argument("--compliance", action="store_true", help="Evalúa normas PCI-DSS")
   ```
   * *Resultado:* `args.headless_crawl = True`, `args.compliance = True`

### El Seguro de Vida: `--allow-private`
Por diseño ético y defensivo, OmniBreach contiene un guardián de red:
* Si detecta que la URL objetivo apunta a `localhost`, `127.0.0.1` o rangos de red privada (`10.x.x.x`, `192.168.x.x`), **cancela el escaneo inmediatamente**.
* Para auditar entornos de desarrollo locales, el usuario debe incluir la bandera explícita `--allow-private`. Esto previene ataques accidentales a la red doméstica o corporativa.

---

## 3. El Flujo de Vida: Las 6 Fases Cronológicas del Pipeline

`main.py` organiza la auditoría en 6 pasos estrictos que se ejecutan en orden:

```
[ FASE 1: VALIDACIÓN ] ---> [ FASE 2: DESCUBRIMIENTO ] ---> [ FASE 3: AUDITORÍA PASIVA ]
         |                                                               |
         v                                                               v
[ FASE 6: REPORTES ]   <--- [ FASE 5: MITIGACIÓN WAF ]  <--- [ FASE 4: AUDITORÍA ACTIVA ]
```

### Fase 1: Normalización y Filtro de Seguridad
* **Qué hace:** Verifica que la URL esté bien escrita. Si el usuario escribió `orderflowapp.online`, le antepone automáticamente `https://`. Valida permisos y puertos.

### Fase 2: Descubrimiento y Mapeo de la Superficie (Crawling)
* **El principio:** *"No puedes proteger ni auditar lo que no sabes que existe"*.
* **Qué hace:** Visita la página raíz y explora todos los enlaces internos (`<a href="...">`), formularios y archivos estáticos.
* **El factor moderno:** Si se activa `--headless-crawl`, levanta un navegador Chromium mediante **Playwright** para renderizar aplicaciones Single Page Application (SPAs en React, Vue o Angular) y descubrir botones interactivos que no están en el HTML estático.

### Fase 3: Auditoría Pasiva (Inspección No Invasiva)
* **El principio:** *"Analizar la información que el servidor entrega voluntariamente sin disparar alertas"*.
* **Qué hace:** 
  * Revisa cabeceras HTTP de seguridad (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`).
  * Inspecciona cookies buscando atributos `HttpOnly`, `Secure` y `SameSite`.
  * Evalúa si las políticas de CORS tienen comodines inseguros (`Access-Control-Allow-Origin: *`).
  * Pasa el motor **DLP** preliminar sobre los archivos descargados para buscar credenciales o llaves privadas expuestas.

### Fase 4: Auditoría Activa (Inyección y Pruebas Especializadas)
* **El principio:** *"Enviar datos controlados para comprobar si el servidor valida la entrada del usuario"*.
* **Qué hace:** Dispara los módulos ofensivos:
  * Inyección SQL (`sqli.py`): Detecta si comillas o caracteres booleanos rompen la consulta.
  * Cross-Site Scripting (`xss.py`): Comprueba si el servidor refleja código JavaScript en el navegador.
  * Seguridad en APIs (`api_security.py`): Prueba parámetros ocultos y fallas de autorización (BOLA).
  * Servidor OAST (`oast.py`): Escucha peticiones fuera de banda en el puerto 53 UDP.

### Fase 5: Correlación, Mitigación y Cumplimiento
* **El principio:** *"Un informe no sirve si no le da la cura al desarrollador"*.
* **Qué hace:**
  * **Algoritmo de Luhn:** Confirma si los números encontrados son tarjetas de crédito reales antes de reportar falsos positivos.
  * **Virtual Patching:** Traduce las vulnerabilidades encontradas en reglas de bloqueo inmediatas para Cloudflare WAF, ModSecurity o Nginx.
  * **Compliance:** Calcula el porcentaje de cumplimiento frente a PCI-DSS v4.0 y OWASP Top 10.

### Fase 6: Generación y Entrega de Reportes
* **Qué hace:** Serializa los resultados en memoria y genera:
  1. El dashboard interactivo en HTML (`reporte_<dominio>_<timestamp>.html`).
  2. El informe formal ejecutivo en PDF (si se solicitó `--pdf`).
  3. El archivo estándar OASIS SARIF v2.1.0 para integraciones CI/CD en GitHub Actions.
  4. Abre automáticamente el navegador web predeterminado del usuario con los resultados.

---

## 4. Concepto Técnico Fundamental: Síncrono vs Asíncrono

En Python tradicional (síncrono), cada petición a internet congela el programa:
```python
# Lento (Síncrono): 3 peticiones de 2 segundos = 6 segundos de espera
descargar("url1") # espera 2s
descargar("url2") # espera 2s
descargar("url3") # espera 2s
```

En OmniBreach, se utiliza **I/O no bloqueante** con `asyncio` y `httpx`:
```python
# Rápido (Asíncrono): Las 3 peticiones se envían simultáneamente = 2 segundos de espera total
await asyncio.gather(
    descargar("url1"),
    descargar("url2"),
    descargar("url3")
)
```
* **Conclusión:** La asincronía permite que el escáner sea 10 veces más rápido consumiendo una fracción mínima de memoria RAM.

---

## 5. Glosario de Términos Clave para Grado y Entrevistas

* **Pipeline:** Secuencia de etapas de procesamiento ordenadas donde la salida de una etapa sirve de insumo para la siguiente.
* **CLI (Command Line Interface):** Interfaz basada en texto que recibe parámetros de ejecución en la terminal.
* **Crawling / Spidering:** Proceso automatizado de navegación web para mapear la estructura completa de un sitio.
* **Auditoría Pasiva:** Análisis de seguridad que no altera el comportamiento del servidor ni envía datos maliciosos.
* **Auditoría Activa:** Envío de cargas útiles (*payloads*) diseñadas para detonar vulnerabilidades.
* **Virtual Patching (Parcheo Virtual):** Regla de firewall (WAF) que bloquea el tráfico de explotación en el perímetro sin necesidad de modificar el código fuente de la aplicación vulnerable.

---

## 6. Banco de Preguntas para el Examen de Fin de Semana

1. ¿Cuál es la función arquitectónica principal de `main.py` y por qué no realiza los ataques directamente?
2. ¿Por qué el escáner bloquea por defecto las direcciones IP privadas y qué bandera permite omitir este bloqueo?
3. ¿Cuál es la diferencia práctica entre la Fase 3 (Auditoría Pasiva) y la Fase 4 (Auditoría Activa)?
4. ¿Por qué se utiliza Playwright (`--headless-crawl`) en lugar de un crawler básico cuando se auditan aplicaciones modernas como React o Vue?
5. ¿Qué beneficio técnico aporta el modelo asíncrono (`asyncio`) frente a un modelo síncrono tradicional al auditar decenas de endpoints?
