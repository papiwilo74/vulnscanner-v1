import sys
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

import requests
import time
from scanner.headers import check_headers
from scanner.https_check import check_https
from scanner.cookies import check_cookies
from scanner.directories import check_directories
from scanner.xss import check_xss
from scanner.sqli import check_sqli
from scanner.ai_check import check_with_ai
from scanner.ports import check_ports
from utils.report import print_report

import argparse

def scan(url, no_open=False):
    print(f"\n Escaneando: {url}\n")
    all_results = []
    
    start_time = time.time()

    try:
        response = requests.get(url, timeout=10)
    except Exception as e:
        print(f" Error conectando a {url}: {e}")
        sys.exit(1)

    print("   Headers...")
    all_results += check_headers(response)

    print("   HTTPS...")
    all_results += check_https(url, response)

    print("   Cookies...")
    all_results += check_cookies(response)

    print("   Directorios expuestos...")
    all_results += check_directories(url)

    print("   XSS reflejado...")
    all_results += check_xss(url)

    print("   SQL Injection...")
    all_results += check_sqli(url)

    print("  ✔ Análisis de IA en parámetros...")
    all_results += check_with_ai(url)

    print("  ✔ Escaneando puertos y servicios expuestos...")
    all_results += check_ports(url)

    duration = time.time() - start_time
    print_report(url, all_results, duration, no_open=no_open)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScanner — Escáner de vulnerabilidades web")
    parser.add_argument("url", help="URL del sitio web a escanear")
    parser.add_argument("--no-open", action="store_true", help="Evita abrir el reporte HTML automáticamente en el navegador")
    
    args = parser.parse_args()
    scan(args.url, no_open=args.no_open)