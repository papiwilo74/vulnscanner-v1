import requests
import sys
from scanner.headers import check_headers
from scanner.https_check import check_https
from scanner.cookies import check_cookies
from scanner.directories import check_directories
from scanner.xss import check_xss
from scanner.sqli import check_sqli
from utils.report import print_report

def scan(url):
    print(f"\n🔍 Escaneando: {url}\n")
    all_results = []

    try:
        response = requests.get(url, timeout=10)
    except Exception as e:
        print(f"❌ Error conectando a {url}: {e}")
        sys.exit(1)

    print("  ✔ Headers...")
    all_results += check_headers(response)

    print("  ✔ HTTPS...")
    all_results += check_https(url, response)

    print("  ✔ Cookies...")
    all_results += check_cookies(response)

    print("  ✔ Directorios expuestos...")
    all_results += check_directories(url)

    print("  ✔ XSS reflejado...")
    all_results += check_xss(url)

    print("  ✔ SQL Injection...")
    all_results += check_sqli(url)

    print_report(url, all_results)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py <URL>")
        print("Ejemplo: python main.py https://ejemplo.com?id=1")
        sys.exit(1)

    scan(sys.argv[1])