import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1; DROP TABLE users--"]
ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ORA-", "syntax error",
    "unclosed quotation", "pg_query", "sqlite_"
]

def test_sqli_payload(parsed, params, param, payload):
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        r = requests.get(test_url, timeout=5)
        body = r.text.lower()
        if any(sig in body for sig in ERROR_SIGNATURES):
            return {
                "vuln": f"Posible SQLi en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Error de DB detectado con payload: {payload}"
            }
    except:
        pass
    return None

def check_sqli(url):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    tasks = []
    for param in params:
        for payload in SQLI_PAYLOADS:
            tasks.append((param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_sqli_payload, parsed, params, t[0], t[1]): t for t in tasks}
        flagged_params = set()
        for future in as_completed(futures):
            param, payload = futures[future]
            if param in flagged_params:
                continue
            res = future.result()
            if res:
                results.append(res)
                flagged_params.add(param)

    return results