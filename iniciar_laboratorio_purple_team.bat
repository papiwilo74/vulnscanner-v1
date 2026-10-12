@echo off
title Laboratorio Purple Team: OmniBreach vs NovaFlow en OrderFlowApp
color 0B
chcp 65001 > nul
cls
echo =========================================================================
echo       INICIANDO LABORATORIO PURPLE TEAM (OMNIBREACH vs NOVAFLOW)
echo =========================================================================
echo.
set PYTHON_EXE=venv\Scripts\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

echo [1/2] Entorno Python detectado: %PYTHON_EXE%
echo [2/2] Lanzando ciber-range interactivo en tiempo real...
echo.
"%PYTHON_EXE%" "C:\Users\villa\.gemini\antigravity\scratch\novaflow-ndr\tools\purple_team_lab.py"

echo.
echo =========================================================================
echo [OK] Demostración finalizada. Presiona cualquier tecla para salir...
echo =========================================================================
pause > nul
