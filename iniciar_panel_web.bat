@echo off
title OmniBreach v3.8 - Real-Time SOC Dashboard
echo ======================================================================
echo          OmniBreach v3.8 - Panel Web SOC
echo ======================================================================
echo.
echo Iniciando servidor web de telemetria en vivo...
echo Abriendo tu navegador en: http://localhost:8000/dashboard
echo.
start http://localhost:8000/dashboard
.\venv\Scripts\python.exe main.py --web
pause
