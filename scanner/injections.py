import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads de Command Injection basados en tiempo (duermen 5 segundos)
CMD_TIME_PAYLOADS = [
    "|| sleep 5",
    "; sleep 5",
    "& sleep 5 &",
    "| ping -n 6 127.0.0.1",  # Para Windows (6 pings de 1s de intervalo ≈ 5s de retraso)
    "`sleep 5`",
    "$(sleep 5)"
]

# Payloads de SSTI y sus resultados matemáticos esperados
SSTI_PAYLOADS = [
    ("${7*7}", "49"),
    ("{{7*7}}", "49"),
    ("#{7*7}", "49"),
    ("{{7+'7'}}", "77"), # Para Jinja/Twig en ciertos contextos
    ("${{7*7}}", "49")
]

def check_injections(url, session=None):
    """
    Analiza la URL en busca de vulnerabilidades de OS Command Injection (basado en tiempo)
    y Server-Side Template Injection (SSTI) en parámetros query.
    
    Args:
        url: URL de la página.
        session: Instancia opcional de requests.Session.
        
    Returns:
        Lista de vulnerabilidades encontradas.
    """
    results = []
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
    except:
        baseline_time = 1.0

    # Analizar parámetro por parámetro
    for param_name, param_values in query_params.items():
        base_val = param_values[0] if param_values else ""
        
        # --- A. OS Command Injection (Time-based) ---
        for payload in CMD_TIME_PAYLOADS:
            # Reemplazar el parámetro con el payload
            modified_query = query_params.copy()
            modified_query[param_name] = [payload]
            
            new_query_string = urlencode(modified_query, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query_string, parsed.fragment
            ))
            
            try:
                start_test = time.time()
                r = client.get(test_url, timeout=8)
                elapsed = time.time() - start_test
                
                # Si tarda al menos 4.5 segundos más que la línea base
                if elapsed >= baseline_time + 4.5:
                    # Confirmar con doble verificación (enviando el valor original para ver si baja el tiempo)
                    try:
                        start_verify = time.time()
                        client.get(url, timeout=5)
                        verify_elapsed = time.time() - start_verify
                        
                        if verify_elapsed < baseline_time + 1.5:
                            results.append({
                                "vuln": "Inyección de Comandos del Sistema Operativo (OS Command Injection)",
                                "risk": "Alto",
                                "detail": f"Inyección basada en tiempo exitosa en el parámetro '{param_name}'. Retardo de {elapsed:.2f}s (Línea base: {baseline_time:.2f}s) con payload: {payload}"
                            })
                            break # Pasar al siguiente parámetro si ya es vulnerable
                    except:
                        pass
            except requests.exceptions.Timeout:
                pass
            except:
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
                # Si la respuesta contiene el resultado matemático evaluado (ej. 49) 
                # pero NO contiene la expresión matemática literal (ej. 7*7 o el payload entero)
                if expected in r.text and payload not in r.text and expected not in baseline_text:
                    results.append({
                        "vuln": "Inyección de Plantillas del Servidor (SSTI)",
                        "risk": "Alto",
                        "detail": f"El servidor evaluó la expresión matemática del payload '{payload}' dando como resultado '{expected}' en el parámetro '{param_name}'."
                    })
                    break # Pasar al siguiente parámetro
            except:
                pass
                
    return results
