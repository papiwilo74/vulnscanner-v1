# Guía Oficial de Despliegue en la Nube — OmniBreach Enterprise
## Arquitectura Serverless: Vercel (Frontend) + Render (API Backend) + Neon (PostgreSQL)

Esta guía detalla el procedimiento paso a paso para desplegar **OmniBreach Enterprise v2.5.0** en un entorno de producción en la nube utilizando los niveles gratuitos (**Free Tier**) de **Vercel**, **Render** y **Neon**, optimizado para evitar cuellos de botella de memoria RAM y suspensión por inactividad.

---

```mermaid
graph TD
    User[Analista SOC / Navegador] -->|Carga UI Ultra-rápida Edge CDN| Vercel[Vercel: Dashboard Web Frontend]
    Vercel -->|REST API Calls & WebSocket Telemetría| Render[Render: FastAPI Backend api.py]
    Render -->|PgBouncer Connection Pooling :6543| Neon[(Neon: PostgreSQL Serverless)]
    Render -->|Auditoría Web DAST / Fuzzing / Payloads| Target[Objetivo a Auditar]
```

---

## Requisitos Previos

1. Cuenta gratuita en [Neon.tech](https://neon.tech).
2. Cuenta gratuita en [Render.com](https://render.com).
3. Cuenta gratuita en [Vercel.com](https://vercel.com).
4. Repositorio de GitHub con el código de OmniBreach.

---

## Paso 1: Configurar la Base de Datos en Neon (PostgreSQL)

Neon proporciona una base de datos PostgreSQL serverless que escala a cero cuando no se usa, ideal para el nivel gratuito.

1. Inicia sesión en [console.neon.tech](https://console.neon.tech) y haz clic en **New Project**.
2. Asigna un nombre (ej. `omnibreach-db`) y selecciona la región más cercana (ej. `US East (Ohio)`).
3. En el panel principal del proyecto, localiza la sección **Connection Details**:
   - Activa la casilla **Connection Pooling** (esto utilizará PgBouncer en el puerto `6543`, evitando saturar los límites de conexión de PostgreSQL).
4. Copia la cadena de conexión completa, que tendrá una estructura similar a:
   ```text
   postgresql://neondb_owner:tu_password@ep-cool-pond-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
5. Guarda esta URL; la usarás como `DATABASE_URL` en Render.

---

## Paso 2: Desplegar el Backend en Render (Web Service)

El backend de FastAPI (`api.py`) gestiona las auditorías, WebSockets y telemetría en tiempo real.

### Opción A: Despliegue con Blueprint Automático (`render.yaml`)
El repositorio incluye el archivo [`render.yaml`](file:///c:/Users/villa/VulnScanner/render.yaml) preconfigurado.
1. En el Dashboard de Render, ve a **Blueprints** -> **New Blueprint Instance**.
2. Conecta tu repositorio de GitHub `OmniBreach`.
3. Render detectará automáticamente [`render.yaml`](file:///c:/Users/villa/VulnScanner/render.yaml).
4. Rellena la variable de entorno `DATABASE_URL` con la cadena obtenida en Neon.
5. Haz clic en **Apply**.

### Opción B: Despliegue Manual del Web Service
1. En Render, selecciona **New +** -> **Web Service**.
2. Conecta tu repositorio de GitHub.
3. Configura los parámetros:
   - **Name:** `omnibreach-api`
   - **Region:** `Oregon` o `Frankfurt` (la más cercana a tu base de datos Neon).
   - **Language:** `Python 3`
   - **Branch:** `main`
   - **Build Command:**
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command:**
     ```bash
     uvicorn api.py:app --host 0.0.0.0 --port $PORT --workers 1
     ```
   - **Plan:** `Free`
4. En la sección **Advanced** -> **Environment Variables**, añade:
   - `DATABASE_URL`: La URL de conexión de Neon (con `sslmode=require`).
   - `OMNIBREACH_LIGHTWEIGHT`: `1` *(imprescindible para el plan gratuito)*.
   - `ENVIRONMENT`: `production`.
   - `CORS_ORIGINS`: `*` (o la URL de tu frontend en Vercel una vez desplegado).
   - `JWT_SECRET`: Una clave aleatoria segura de al menos 32 caracteres.
5. En **Health Check Path**, escribe `/health`.
6. Haz clic en **Create Web Service**.

Una vez completado el build, obtendrás la URL pública de tu backend:
`https://omnibreach-api.onrender.com`

---

## Paso 3: Desplegar el Frontend en Vercel (Edge CDN)

Vercel servirá el panel de operaciones SOC con latencia mínima global y certificado SSL automático.

1. Ve a [vercel.com](https://vercel.com) y selecciona **Add New...** -> **Project**.
2. Importa tu repositorio de GitHub.
3. En la configuración del proyecto:
   - **Framework Preset:** `Other` (servirá los archivos estáticos preconfigurados en `public/` y `vercel.json`).
   - **Root Directory:** `./`
4. Haz clic en **Deploy**.
5. Vercel desplegará instantáneamente tu sitio en una dirección como:
   `https://omnibreach.vercel.app`

### Conexión Frontend <-> Backend
El panel web incluye detección inteligente de endpoints:
- Si abres el dashboard en Vercel, puedes ingresar la URL de tu API de Render en el panel de configuración o almacenarla localmente:
  ```javascript
  localStorage.setItem('omnibreach_api_base', 'https://omnibreach-api.onrender.com');
  ```
- Todas las peticiones REST y los WebSockets se enrutarán automáticamente a tu backend en Render.

---

## Paso 4: Mitigación de Limitaciones del Plan Gratuito

> [!IMPORTANT]
> Los entornos gratuitos tienen restricciones específicas que pueden afectar herramientas de auditoría ofensiva si no se configuran correctamente:

### 1. Evitar la Suspensión por Inactividad (Cold Starts)
* **El Reto:** Render Free apaga el contenedor tras 15 minutos sin peticiones HTTP. La reactivación puede tardar entre 50 y 90 segundos.
* **Solución Gratuita:**
  1. Entra a un servicio de monitoreo como [cron-job.org](https://cron-job.org) o [UptimeRobot](https://uptimerobot.com) (ambos gratuitos).
  2. Configura un monitor tipo HTTP (GET) apuntando a:
     `https://tu-api.onrender.com/health`
  3. Establece el intervalo en **cada 10 minutos**.
  4. Esto mantiene el contenedor en Render despierto 24/7 sin coste alguno.

### 2. Prevención de Fallos por Memoria (Límite de 512 MB RAM)
* **El Reto:** Render Free limita la memoria RAM a 512 MB. Si se ejecuta Chromium Headless (Playwright), la memoria supera rápidamente los 600 MB y el contenedor es terminado por Out Of Memory (OOM Kill).
* **Solución de OmniBreach:**
  - Al configurar `OMNIBREACH_LIGHTWEIGHT=1`, OmniBreach desactiva automáticamente el lanzamiento de Chromium en la nube y delega todo el análisis de crawling y fuzzing a su motor HTTP asíncrono ultrarrápido (`requests` / `httpx`), manteniendo el consumo de memoria por debajo de los **180 MB**.

### 3. Evitar Timeouts Serverless (10 segundos)
* **El Reto:** Vercel cancela peticiones que duren más de 10 segundos.
* **Solución de OmniBreach:**
  - Los escaneos se ejecutan exclusivamente en Render en segundo plano (`BackgroundTasks`). Vercel únicamente sirve la interfaz visual y recibe la telemetría en tiempo real mediante WebSockets (`/ws/scan/{task_id}`).

---

## Verificación del Despliegue

Una vez completados los pasos:
1. Abre tu URL de Render: `https://tu-api.onrender.com/health`
   - Debe responder:
     ```json
     {
       "status": "healthy",
       "service": "OmniBreach Enterprise API",
       "version": "2.5.0",
       "database": "neon-postgresql",
       "lightweight_mode": true
     }
     ```
2. Abre tu panel en Vercel: `https://tu-frontend.vercel.app`
3. Lanza un escaneo contra tu dominio o sitio de prueba y observa la telemetría y hallazgos en vivo en el gráfico de severidad y registro de eventos.
