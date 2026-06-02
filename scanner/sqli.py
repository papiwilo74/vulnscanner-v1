import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1; DROP TABLE users--"]
ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ORA-", "syntax error",
    "unclosed quotation", "pg_query", "sqlite_"
]

def check_sqli(url):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                r = requests.get(test_url, timeout=5)
                body = r.text.lower()
                if any(sig in body for sig in ERROR_SIGNATURES):
                    results.append({
                        "vuln": f"Posible SQLi en parámetro '{param}'",
                        "risk": "Alto",
                        "detail": f"Error de DB detectado con payload: {payload}"
                    })
                    break
            except:
                pass

    return results