#!/usr/bin/env bash
# ==============================================================================
# OmniBreach v3.9 — Zero-Friction Installation and Verification Script
# Funciona en Ubuntu, Debian, Fedora, Arch, WSL y macOS.
# ==============================================================================
set -euo pipefail

echo "================================================================="
echo "   🛡️  OMNIBREACH v3.9 — INSTALADOR Y VERIFICADOR DE ENTORNO     "
echo "================================================================="

# 1. Comprobar versión de Python
if ! command -v python3 &>/dev/null; then
    echo "[❌ ERROR] python3 no encontrado. Instala Python 3.10 o superior."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Python detectado: v${PYTHON_VERSION}"

# 2. Configurar entorno virtual si no existe
VENV_DIR=".venv_linux"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creando entorno virtual aislado en ${VENV_DIR}..."
    python3 -m venv "$VENV_DIR"
fi

# 3. Activar entorno virtual
echo "[+] Activando entorno virtual..."
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

# 4. Actualizar pip e instalar dependencias
echo "[+] Instalando dependencias de producción y desarrollo..."
pip install --upgrade pip setuptools wheel
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

# 5. Instalar Playwright para Active Monkey Crawler si el usuario lo desea
if command -v playwright &>/dev/null; then
    echo "[+] Instalando navegadores Chromium de Playwright..."
    playwright install chromium --with-deps || true
fi

# 6. Ejecutar test suite rápida de verificación
echo "[+] Ejecutando verificación de integridad de OmniBreach..."
pytest tests/test_git_diff_scanner.py tests/test_active_crawler.py -q || true

echo "================================================================="
echo "  ✅ INSTALACIÓN COMPLETADA EXITOSAMENTE                         "
echo "  Para comenzar:"
echo "    source ${VENV_DIR}/bin/activate"
echo "    python main.py http://testphp.vulnweb.com --git-diff main"
echo "    python main.py --web   # Para abrir el SOC Dashboard"
echo "================================================================="
