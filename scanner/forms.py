import html
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from scanner.sqli import ERROR_PAYLOADS, ERROR_SIGNATURES, TIME_PAYLOADS

# Reutilizar payloads y firmas ya definidos en otros módulos
from scanner.xss import XSS_PAYLOADS


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.current_form: Optional[dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attr_dict.get('action', '') or '',
                'method': (attr_dict.get('method', 'get') or 'get').lower(),
                'inputs': []
            }
        elif self.current_form is not None:
            if tag == 'input':
                input_name = attr_dict.get('name')
                input_type = (attr_dict.get('type', 'text') or 'text').lower()
                # Omitir botones y elementos que no reciben entrada textual directa
                if input_name and input_type not in ['submit', 'reset', 'button', 'image', 'file']:
                    self.current_form['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': attr_dict.get('value', '') or ''
                    })
            elif tag in ['textarea', 'select']:
                input_name = attr_dict.get('name')
                if input_name:
                    self.current_form['inputs'].append({
                        'name': input_name,
                        'type': tag,
                        'value': ''
                    })

    def handle_endtag(self, tag: str) -> None:
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

def extract_forms(url: str, html_content: str) -> list[dict[str, Any]]:
    parser = FormParser()
    try:
        parser.feed(html_content)
    except Exception as e:
        print(f"  [WARN] Error parsing HTML forms: {e}")

    for form in parser.forms:
        # Resolver URLs de acción a absolutas
        form['action'] = urljoin(url, form['action'])
    return parser.forms

def send_form_request(
    action_url: str,
    method: str,
    data: dict[str, Any],
    timeout: int = 5,
    session: Optional[requests.Session] = None
) -> requests.Response:
    client = session if session is not None else requests
    if method == 'post':
        return client.post(action_url, data=data, timeout=timeout)
    else:
        return client.get(action_url, params=data, timeout=timeout)

def test_form_xss(
    action_url: str,
    method: str,
    base_data: dict[str, Any],
    target_input: str,
    payload: str,
    baseline_text: str = "",
    session: Optional[requests.Session] = None
) -> Optional[dict[str, str]]:
    data = base_data.copy()
    data[target_input] = payload
    try:
        r = send_form_request(action_url, method, data, timeout=5, session=session)
        headers = getattr(r, "headers", {})
        content_type = headers.get("Content-Type", "") if hasattr(headers, "get") else ""
        if isinstance(content_type, str) and content_type:
            ct_lower = content_type.lower()
            if not any(t in ct_lower for t in ["text/html", "application/xhtml+xml", "image/svg+xml"]):
                return None

        if payload in r.text and payload not in baseline_text:
            escaped_payload = html.escape(payload)
            if payload != escaped_payload and escaped_payload in r.text and r.text.count(payload) == r.text.count(escaped_payload):
                return None

            return {
                "vuln": f"XSS Reflejado en Formulario ({method.upper()})",
                "risk": "Alto",
                "detail": f"Input: '{target_input}', Action: {action_url}. Payload reflejado sin escapar: {payload}"
            }
    except requests.RequestException:
        pass
    return None

def test_form_error_sqli(
    action_url: str,
    method: str,
    base_data: dict[str, Any],
    target_input: str,
    payload: str,
    baseline_body: str = "",
    session: Optional[requests.Session] = None
) -> Optional[dict[str, str]]:
    data = base_data.copy()
    data[target_input] = payload
    try:
        r = send_form_request(action_url, method, data, timeout=5, session=session)
        body = r.text.lower()
        new_sigs = [sig for sig in ERROR_SIGNATURES if sig in body and sig not in baseline_body]
        if new_sigs:
            return {
                "vuln": f"SQLi en Formulario ({method.upper()})",
                "risk": "Alto",
                "detail": f"Input: '{target_input}', Action: {action_url}. Error de DB detectado con payload: {payload} (firmas: {', '.join(new_sigs)})"
            }
    except requests.RequestException:
        pass
    return None

def test_form_time_sqli(
    action_url: str,
    method: str,
    base_data: dict[str, Any],
    target_input: str,
    payload: str,
    baseline_time: float,
    session: Optional[requests.Session] = None
) -> Optional[dict[str, str]]:
    data = base_data.copy()
    data[target_input] = payload
    try:
        start_time = time.time()
        send_form_request(action_url, method, data, timeout=7, session=session)
        elapsed = time.time() - start_time

        # Si tarda más de 2.7 segundos comparado con la línea base
        if elapsed >= baseline_time + 2.7:
            # Doble verificación: comprobar que responde rápido sin el payload
            try:
                start_verify = time.time()
                send_form_request(action_url, method, base_data, timeout=5, session=session)
                verify_elapsed = time.time() - start_verify

                if verify_elapsed < baseline_time + 1.2:
                    return {
                        "vuln": f"Blind SQLi (Tiempo) en Formulario ({method.upper()})",
                        "risk": "Alto",
                        "detail": f"Input: '{target_input}', Action: {action_url}. Retardo de {elapsed:.2f}s (Línea base: {baseline_time:.2f}s) con payload: {payload}"
                    }
            except requests.RequestException:
                pass
    except requests.RequestException:
        pass
    return None

def scan_single_form(
    form: dict[str, Any],
    session: Optional[requests.Session] = None,
    passive: bool = False
) -> list[dict[str, str]]:
    results = []
    action_url = form['action']
    method = form['method']
    inputs = form['inputs']

    # 0. Detectar ausencia de Token CSRF en formularios POST (análisis estático, pasivo)
    if method == 'post':
        csrf_patterns = [
            r'csrf', r'token', r'authenticity_token', r'xsrf', r'middlewaretoken'
        ]
        has_csrf = False
        for inp in inputs:
            inp_name = inp.get('name', '').lower()
            if any(re.search(pat, inp_name) for pat in csrf_patterns):
                has_csrf = True
                break
        if not has_csrf:
            results.append({
                "vuln": "Ausencia de Token CSRF",
                "risk": "Medio",
                "detail": f"El formulario POST con acción '{action_url}' no contiene ningún campo input aparente para tokens CSRF (ej. csrf, _token, xsrf)."
            })

    # En modo pasivo, omitir las pruebas activas (XSS/SQLi con payloads)
    if passive or not inputs:
        return results


    # Construir el diccionario base con valores predeterminados vacíos
    base_data = {inp['name']: inp['value'] for inp in inputs}

    baseline_body = ""
    try:
        start_base = time.time()
        r_base = send_form_request(action_url, method, base_data, timeout=5, session=session)
        baseline_time = time.time() - start_base
        baseline_body = r_base.text.lower()
    except requests.RequestException:
        baseline_time = 1.0

    # Ejecutar escaneo para cada input
    for inp in inputs:
        target_name = inp['name']

        # 1. Comprobar XSS
        for payload in XSS_PAYLOADS:
            res = test_form_xss(action_url, method, base_data, target_name, payload, baseline_text=baseline_body, session=session)
            if res:
                results.append(res)
                break # si un input es vulnerable a XSS, pasamos al siguiente test

        # 2. Comprobar SQLi basado en errores
        for payload in ERROR_PAYLOADS:
            res = test_form_error_sqli(action_url, method, base_data, target_name, payload, baseline_body=baseline_body, session=session)
            if res:
                results.append(res)
                break

        # 3. Comprobar Blind SQLi basado en tiempo
        for payload in TIME_PAYLOADS:
            res = test_form_time_sqli(action_url, method, base_data, target_name, payload, baseline_time, session)
            if res:
                results.append(res)
                break

    return results

def check_forms(url: str, html_content: Optional[str] = None, session: Optional[requests.Session] = None, passive: bool = False) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    if not html_content:
        return results

    print("Extrayendo formularios de la pagina...")
    forms = extract_forms(url, html_content)

    if not forms:
        return results

    print(f"Escaneando {len(forms)} formularios detectados...")

    # Procesar formularios concurrentemente
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_single_form, form, session, passive): form for form in forms}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.extend(res)

    return results
