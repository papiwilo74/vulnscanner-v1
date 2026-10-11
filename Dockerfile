# OmniBreach v3.10 — Multi-Platform Production Container
FROM python:3.11-slim as base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Instalar dependencias del sistema mínimas requeridas para compilación y utilidades
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libffi-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copiar el código fuente completo
COPY . .

# Directorio de persistencia para reportes y base de datos SQLite
RUN mkdir -p reports

EXPOSE 8000

# Por defecto inicia el servidor API y panel SOC; se puede sobrescribir con argumentos CLI
ENTRYPOINT ["python", "main.py"]
CMD ["--web"]
