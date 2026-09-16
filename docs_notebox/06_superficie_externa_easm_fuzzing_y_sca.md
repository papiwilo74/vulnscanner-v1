# Módulo 06: Superficie de Ataque Externa (EASM), Fuzzing, SCA y Fuga de Secretos

## 1. El Paradigma de EASM: "No Puedes Proteger lo que No Sabes que Tienes"

La inmensa mayoría de las intrusiones corporativas no ocurren atacando el sitio web principal de la compañía (`empresa.com`). Ocurren a través de **Shadow IT**:
* Un subdominio de pruebas olvidado (`test-api.empresa.com`).
* Un servidor de staging levantado por un desarrollador externo hace 2 años (`staging-v2.empresa.com`).
* Un bucket de almacenamiento en la nube cuyo registro DNS nunca fue eliminado.

**EASM (External Attack Surface Management)** es la disciplina de mapear continuamente todos los activos digitales expuestos en internet antes de que un atacante los descubra.

---

## 2. Enumeración de Subdominios y el Peligro del Subdomain Takeover

### 2.1 Técnicas de Descubrimiento de Activos
1. **Certificate Transparency (CT Logs):** Cada vez que se emite un certificado SSL/TLS (vía Let's Encrypt o DigiCert), queda registrado en un libro contable público inmutable. Consultar estos registros permite descubrir subdominios sin enviar un solo paquete al objetivo (Reconocimiento Pasivo).
2. **Fuerza Bruta DNS y Diccionarios:** Consultas de registros tipo `A` y `CNAME` sobre prefijos comunes (`vpn`, `mail`, `dev`, `gitlab`, `jira`).

---

### 2.2 Anatomía del Subdomain Takeover (Toma de Subdominios)

Es una de las vulnerabilidades más críticas en infraestructuras basadas en la nube:

```mermaid
sequenceDiagram
    autonumber
    participant DNS as DNS Corporativo (empresa.com)
    participant S3 as Servicio Cloud (AWS S3 / GitHub Pages)
    actor Attacker as Atacante
    actor Victim as Usuario Legítimo

    Note over DNS: Registro CNAME huérfano:<br/>promo.empresa.com -> mi-promo.s3.amazonaws.com
    Note over S3: La empresa borró el bucket mi-promo para no pagar almacenamiento,<br/>pero olvidó borrar el registro en su DNS.
    Attacker->>S3: Crea un bucket con el nombre libre: "mi-promo"
    Attacker->>S3: Sube sitio web malicioso con robo de credenciales
    Victim->>DNS: Consulta promo.empresa.com
    DNS-->>Victim: Resuelve a la IP de AWS S3
    Victim->>S3: Petición HTTPS a promo.empresa.com
    S3-->>Victim: Sirve el sitio web malicioso del atacante bajo el dominio oficial
```

* **Impacto:** El atacante tiene control total del contenido bajo el dominio legítimo de la empresa, pudiendo emitir certificados SSL válidos, robar cookies de sesión con alcance de dominio (`Domain=.empresa.com`) y ejecutar ataques de phishing imposibles de detectar a simple vista.
* **La Detección en OmniBreach ([`scanner/takeover.py`](file:///c:/Users/villa/VulnScanner/scanner/takeover.py)):**
  El escáner inspecciona registros CNAME y verifica si las respuestas del servicio en la nube coinciden con firmas de "recurso no reclamado" (ej. `The specified bucket does not exist` en AWS o `There isn't a GitHub Pages site here`).

---

## 3. Fuzzing de Parámetros Ocultos

Los desarrolladores con frecuencia dejan parámetros de depuración en endpoints públicos para probar funcionalidades en desarrollo (`?debug=1`, `?test=true`, `?admin_mode=true`, `?disable_cache=1`).

Ubicación en el código: [`scanner/param_fuzzer.py`](file:///c:/Users/villa/VulnScanner/scanner/param_fuzzer.py)

* **¿Cómo funciona el Fuzzer?**
  1. Realiza una petición base a la URL (`/api/catalogo`).
  2. Mide la respuesta (longitud en bytes, número de palabras, código de estado).
  3. Inyecta concurrentemente una lista de palabras clave como parámetros GET y POST.
  4. Si al inyectar `?debug=true` la respuesta incrementa sustancialmente de tamaño o cambia de estado, el parámetro es marcado como descubierto para posterior auditoría.

---

## 4. Software Composition Analysis (SCA) y Detección de Secretos

### 4.1 SCA: La Cadena de Suministro de Software
El 80% del código de una aplicación moderna proviene de librerías de terceros (npm, pip, Maven). Si una aplicación utiliza una versión desactualizada de una librería con una vulnerabilidad conocida (CVE), el atacante ni siquiera necesita auditar el código propio: busca el exploit público en bases de datos de seguridad.

* **Detección en OmniBreach ([`scanner/sca.py`](file:///c:/Users/villa/VulnScanner/scanner/sca.py)):**
  El motor extrae los metadatos de las versiones de frameworks y dependencias (ej. `bootstrap.js v3.3.7` o `jquery.min.js v1.12.4`) a partir de cabeceras, archivos `package.json` expuestos o comentarios en el código, comparándolos contra listas de versiones vulnerables conocidas.

### 4.2 Fuga de Secretos en Código Frontend (Secret Leaks)
Es muy común que desarrolladores incluyan accidentalmente credenciales y claves privadas en el código JavaScript compilado que se envía a los clientes:

```python
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Clave de Acceso AWS (IAM)"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Clave Privada de Stripe en Producción"),
    (r"AIza[0-9A-Za-z-_]{35}", "API Key de Google Cloud"),
    (r"ghp_[0-9a-zA-Z]{36}", "Token Personal de GitHub"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "Clave Privada RSA Expuesta")
]
```

OmniBreach descarga los bundles JavaScript y analiza el texto con expresiones regulares especializadas para alertar fugas de tokens antes de que sean indexados por motores de búsqueda.

---

## 5. Preguntas Clave para Estudio y Guión de Video

1. **¿Por qué la verificación de registros CNAME huérfanos es suficiente para prevenir un Subdomain Takeover?**
   * *Respuesta:* Porque si el registro CNAME se elimina del servidor DNS corporativo inmediatamente después de dar de baja el servicio en la nube, el subdominio deja de apuntar al espacio de nombres de la nube y ningún tercero puede reclamarlo.
2. **¿Cuál es la diferencia entre el análisis de código estático (SAST) y el Software Composition Analysis (SCA)?**
   * *Respuesta:* SAST analiza el código fuente propio desarrollado por el equipo en busca de fallos lógicos; SCA audita las librerías, paquetes y dependencias de terceros importadas en el proyecto contra bases de datos de vulnerabilidades conocidas (CVEs).
3. **¿Por qué las claves de API privadas en código JavaScript del cliente son un riesgo crítico incluso si el desarrollador cree que están "minificadas"?**
   * *Respuesta:* Porque la minificación solo acorta nombres de variables para reducir tamaño; no es cifrado. Las cadenas de texto como `sk_live_...` permanecen en texto plano e intactas en el archivo descargado por cualquier navegador.
