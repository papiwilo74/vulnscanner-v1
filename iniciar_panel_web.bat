@echo off
title VulnScanner Enterprise - Real-Time SOC Dashboard
echo ======================================================================
echo          VulnScanner Enterprise v2.4.0 - Panel Web SOC
echo ======================================================================
echo.
echo Iniciando servidor web de telemetria en vivo...
echo Abriendo tu navegador en: http://localhost:8000/dashboard
echo.
start http://localhost:8000/dashboard
.\venv\Scripts\python.exe main.py --web
pause
