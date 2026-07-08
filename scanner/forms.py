import requests
import time
import os
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Reutilizar payloads y firmas ya definidos en otros módulos
from scanner.xss import XSS_PAYLOADS
from scanner.sqli import ERROR_PAYLOADS, TIME_PAYLOADS, ERROR_SIGNATURES

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attr_dict.get('action', ''),
                'method': attr_dict.get('method', 'get').lower(),
                'inputs': []
            }
        elif self.current_form is not None:
            if tag == 'input':
                input_name = attr_dict.get('name')
                input_type = attr_dict.get('type', 'text').lower()
                # Omitir botones y elementos que no reciben entrada textual directa
                if input_name and input_type not in ['submit', 'reset', 'button', 'image', 'file']:
                    self.current_form['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': attr_dict.get('value', '')
                    })
            elif tag in ['textarea', 'select']:
                input_name = attr_dict.get('name')
                if input_name:
                    self.current_form['inputs'].append({
                        'name': input_name,
                        'type': tag,
                        'value': ''
                    })

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

def extract_forms(url, html_content):
    parser = FormParser()
    try:
        parser.feed(html_content)
    except Exception as e:
        print(f"  ⚠️ Error parsing HTML forms: {e}")
        
    for form in parser.forms:
        # Resolver URLs de acción a absolutas
        form['action'] = urljoin(url, form['action'])
    return parser.forms

def send_form_request(action_url, method, data, timeout=5, session=None):
    client = session if session is not None else requests
    if method == 'post':
        return client.post(action_url, data=data, timeout=timeout)
    else:
        return client.get(action_url, params=data, timeout=timeout)

def test_form_xss(action_url, method, base_data, target_input, payload, baseline_text="", session=None):
    data = base_data.copy()
    data[target_input] = payload
    try:
        r = send_form_request(action_url, method, data, timeout=5, session=session)
        if payload in r.text and payload not in baseline_text:
            return {
                "vuln": f"XSS Reflejado en Formulario ({method.upper()})",
                "risk": "Alto",
                "detail": f"Input: '{target_input}', Action: {action_url}. Payload reflejado sin escapar: {payload}"
            }
    except:
        pass
    return None

def test_form_error_sqli(action_url, method, base_data, target_input, payload, baseline_body="", session=None):
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
    except:
        pass
    return None

def test_form_time_sqli(action_url, method, base_data, target_input, payload, baseline_time, session=None):
    data = base_data.copy()
    data[target_input] = payload
    try:
        start_time = time.time()
        r = send_form_request(action_url, method, data, timeout=7, session=session)
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
            except:
                pass
    except:
        pass
    return None

def scan_single_form(form, session=None, passive=False):
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
    except:
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

def check_forms(url, html_content, session=None, passive=False):
    results = []
    if not html_content:
        return results
        
    print(f"  ✔ Extrayendo formularios de la página...")
    forms = extract_forms(url, html_content)
    
    if not forms:
        return results
        
    print(f"  ✔ Escaneando {len(forms)} formularios detectados...")
    
    # Procesar formularios concurrentemente
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_single_form, form, session, passive): form for form in forms}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.extend(res)
                
    return results
