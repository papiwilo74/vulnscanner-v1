from utils.http_client import get
from scanner.headers import check_headers
from utils.report import print_report

url = "https://trabajo-ya-five.vercel.app/candidato/buscar"
response = get(url)

if response:
    results = check_headers(response)
    print_report(url, results)