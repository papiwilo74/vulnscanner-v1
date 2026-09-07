import time
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

# Payloads de Command Injection basados en tiempo (duermen 5 segundos)
CMD_TIME_PAYLOADS: list[str] = [
    "|| sleep 5",
    "; sleep 5",
    "& sleep 5 &",
    "| ping -n 6 127.0.0.1",  # Para Windows
    "`sleep 5`",
    "$(sleep 5)",
]

# Payloads de SSTI usando operaciones matemáticas únicas para evitar falsos positivos con números comunes
SSTI_PAYLOADS: list[tuple[str, str]] = [
    ("${9876*5432}", "53646432"),
    ("{{9876*5432}}", "53646432"),
    ("#{9876*5432}", "53646432"),
    ("${{9876*5432}}", "53646432"),
    ("*{9876*5432}", "53646432"),
]

def check_injections(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    """
    Analiza la URL en busca de vulnerabilidades de OS Command Injection (basado en tiempo)
    y Server-Side Template Injection (SSTI) en parámetros query.
    """
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return results

    baseline_text = ""
    try:
        start_base = time.time()
        r_base = client.get(url, timeout=6)
        baseline_time = time.time() - start_base
        baseline_text = r_base.text
    except requests.RequestException:
        baseline_time = 1.0

    # Analizar parámetro por parámetro
    for param_name in query_params:
        # --- A. OS Command Injection (Time-based) ---
        for payload in CMD_TIME_PAYLOADS:
            modified_query = query_params.copy()
            modified_query[param_name] = [payload]

            new_query_string = urlencode(modified_query, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query_string, parsed.fragment
            ))

            try:
                start_test = time.time()
                r = client.get(test_url, timeout=9)
                elapsed = time.time() - start_test

                # Debe requerir al menos 4.5s adicionales sobre la línea base
                if elapsed >= baseline_time + 4.5:
                    # Confirmación estricta realizando una petición de control sin payload
                    try:
                        start_verify = time.time()
                        r_v = client.get(url, timeout=5)
                        verify_elapsed = time.time() - start_verify

                        if verify_elapsed < baseline_time + 1.5 and r_v.status_code == 200:
                            results.append({
                                "vuln": "Inyección de Comandos del Sistema Operativo (OS Command Injection)",
                                "risk": "Alto",
                                "detail": f"Inyección basada en tiempo exitosa en el parámetro '{param_name}'. Retardo de {elapsed:.2f}s (Línea base: {baseline_time:.2f}s) con payload: {payload}"
                            })
                            break
                    except requests.RequestException:
                        pass
            except (requests.exceptions.Timeout, requests.RequestException):
                pass

        # --- B. Server-Side Template Injection (SSTI) ---
        for payload, expected in SSTI_PAYLOADS:
            modified_query = query_params.copy()
            modified_query[param_name] = [payload]

            new_query_string = urlencode(modified_query, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query_string, parsed.fragment
            ))

            try:
                r = client.get(test_url, timeout=5)
                # El resultado matemático debe aparecer en la respuesta, pero NO la expresión original ni en la respuesta base
                if expected in r.text and payload not in r.text and expected not in baseline_text:
                    results.append({
                        "vuln": "Inyección de Plantillas del Servidor (SSTI)",
                        "risk": "Alto",
                        "detail": f"El servidor evaluó la expresión matemática del payload '{payload}' dando como resultado '{expected}' en el parámetro '{param_name}'."
                    })
                    break
            except requests.RequestException:
                pass

    return results
