"""
Módulo de Re-Testing Quirúrgico Bi-Direccional (Verify Fix).
Permite verificar rápidamente un hallazgo específico utilizando su evidencia original,
validando si la corrección aplicada por los desarrolladores resolvió la vulnerabilidad
sin necesidad de ejecutar un escaneo completo de 30 minutos.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.Retest")

SQL_ERROR_PATTERNS = [
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"mysql_fetch_array", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"ORA-01756", re.IGNORECASE),
]

LFI_PATTERNS = [
    re.compile(r"root:.*:0:0:", re.IGNORECASE),
    re.compile(r"\[boot loader\]", re.IGNORECASE),
    re.compile(r"/bin/(bash|sh)", re.IGNORECASE),
    re.compile(r"default=multi\(0\)disk\(0\)", re.IGNORECASE),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Inyecta el payload en el parámetro indicado dentro de la query string."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def retest_finding(
    finding: Finding | dict[str, Any],
    session: requests.Session | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """
    Ejecuta una re-verificación quirúrgica de un hallazgo específico.

    Retorna un diccionario con:
      - finding_id: Identificador del hallazgo
      - vuln_type: Categoría o tipo de vulnerabilidad
      - url: URL probada
      - status: 'fixed', 'still_vulnerable', o 'inconclusive'
      - http_status: Código de respuesta HTTP obtenido
      - duration_ms: Tiempo en milisegundos que tomó la re-prueba
      - details: Explicación forense del resultado
    """
    if isinstance(finding, Finding):
        finding_id = finding.id
        title = finding.title
        category = finding.category.lower()
        param = finding.parameter
        evidence = finding.evidence
        url = (evidence.request_url if evidence and evidence.request_url else finding.affected_url) or ""
        method = (evidence.request_method if evidence and evidence.request_method else "GET").upper()
        payload = (evidence.payload if evidence and evidence.payload else "") or ""
        orig_fragment = (evidence.response_fragment if evidence else "") or ""
    else:
        finding_id = str(finding.get("id", "unknown"))
        title = str(finding.get("title", ""))
        category = str(finding.get("category", "")).lower()
        param = finding.get("parameter")
        ev_dict = finding.get("evidence")
        if isinstance(ev_dict, dict):
            url = str(ev_dict.get("request_url", "") or finding.get("affected_url", ""))
            method = str(ev_dict.get("request_method", "GET")).upper()
            payload = str(ev_dict.get("payload", ""))
            orig_fragment = str(ev_dict.get("response_fragment", ""))
        else:
            url = str(finding.get("affected_url", ""))
            method = "GET"
            payload = ""
            orig_fragment = ""

    if not url:
        return {
            "finding_id": finding_id,
            "vuln_type": category or title,
            "url": "",
            "status": "inconclusive",
            "http_status": None,
            "duration_ms": 0.0,
            "details": "No se encontró URL objetivo en la evidencia del hallazgo.",
        }

    s = session or requests.Session()
    target_url = url
    data_payload: dict[str, str] | None = None

    if method == "GET":
        if param and payload:
            target_url = _inject_param(url, param, payload)
    elif method in ("POST", "PUT", "PATCH") and param and payload:
        data_payload = {param: payload}

    start_time = time.perf_counter()
    try:
        if method == "GET":
            resp = s.get(target_url, timeout=timeout)
        elif method == "POST":
            resp = s.post(target_url, data=data_payload, timeout=timeout)
        elif method == "PUT":
            resp = s.put(target_url, data=data_payload, timeout=timeout)
        elif method == "PATCH":
            resp = s.patch(target_url, data=data_payload, timeout=timeout)
        else:
            resp = s.request(method, target_url, data=data_payload, timeout=timeout)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning("[Retest] Error de conexión re-probando %s: %s", target_url, exc)
        return {
            "finding_id": finding_id,
            "vuln_type": category or title,
            "url": target_url,
            "status": "inconclusive",
            "http_status": None,
            "duration_ms": elapsed_ms,
            "details": f"Fallo al conectar con el servidor: {exc}",
        }

    body = resp.text
    status_code = resp.status_code

    # Evaluación heurística por categoría
    if "sql" in category or "sqli" in category or "sql injection" in title.lower():
        found_pattern = next((p.pattern for p in SQL_ERROR_PATTERNS if p.search(body)), None)
        if found_pattern or (orig_fragment and orig_fragment in body and status_code >= 500):
            return {
                "finding_id": finding_id,
                "vuln_type": "SQL Injection",
                "url": target_url,
                "status": "still_vulnerable",
                "http_status": status_code,
                "duration_ms": elapsed_ms,
                "details": (
                    f"El servidor continúa disparando error de SQL con patrón '{found_pattern}'."
                    if found_pattern
                    else f"El servidor respondió con código {status_code} y fragmento '{orig_fragment}'."
                ),
            }
        return {
            "finding_id": finding_id,
            "vuln_type": "SQL Injection",
            "url": target_url,
            "status": "fixed",
            "http_status": status_code,
            "duration_ms": elapsed_ms,
            "details": "No se reprodujo ningún error de SQL; payload neutralizado o parametrizado.",
        }

    if "xss" in category or "cross-site scripting" in title.lower():
        if payload and payload in body:
            return {
                "finding_id": finding_id,
                "vuln_type": "Cross-Site Scripting",
                "url": target_url,
                "status": "still_vulnerable",
                "http_status": status_code,
                "duration_ms": elapsed_ms,
                "details": "El payload XSS se refleja sin escape HTML en la respuesta.",
            }
        return {
            "finding_id": finding_id,
            "vuln_type": "Cross-Site Scripting",
            "url": target_url,
            "status": "fixed",
            "http_status": status_code,
            "duration_ms": elapsed_ms,
            "details": "El payload fue sanitizado, escapado o filtrado por el servidor.",
        }

    if "traversal" in category or "lfi" in category or "path traversal" in title.lower():
        found_lfi = next((p.pattern for p in LFI_PATTERNS if p.search(body)), None)
        if found_lfi:
            return {
                "finding_id": finding_id,
                "vuln_type": "Path Traversal",
                "url": target_url,
                "status": "still_vulnerable",
                "http_status": status_code,
                "duration_ms": elapsed_ms,
                "details": f"Patrón sensible de sistema operativo detectado: '{found_lfi}'.",
            }
        return {
            "finding_id": finding_id,
            "vuln_type": "Path Traversal",
            "url": target_url,
            "status": "fixed",
            "http_status": status_code,
            "duration_ms": elapsed_ms,
            "details": "Acceso a rutas del sistema bloqueado exitosamente.",
        }

    if "exposed" in category or "directories" in category or "git" in title.lower():
        if status_code in (403, 404):
            return {
                "finding_id": finding_id,
                "vuln_type": "Exposed Artifacts",
                "url": target_url,
                "status": "fixed",
                "http_status": status_code,
                "duration_ms": elapsed_ms,
                "details": f"El recurso sensible ahora responde HTTP {status_code} (no expuesto).",
            }
        if status_code == 200 and ("ref: refs/" in body or "[core]" in body or orig_fragment in body):
            return {
                "finding_id": finding_id,
                "vuln_type": "Exposed Artifacts",
                "url": target_url,
                "status": "still_vulnerable",
                "http_status": status_code,
                "duration_ms": elapsed_ms,
                "details": "El archivo sensible sigue respondiendo con código 200 y contenido de repositorio.",
            }

    # Evaluación genérica basada en fragmento original o códigos de error
    if orig_fragment and orig_fragment in body:
        return {
            "finding_id": finding_id,
            "vuln_type": category or title,
            "url": target_url,
            "status": "still_vulnerable",
            "http_status": status_code,
            "duration_ms": elapsed_ms,
            "details": f"El fragmento de evidencia original '{orig_fragment[:40]}...' continúa presente.",
        }

    return {
        "finding_id": finding_id,
        "vuln_type": category or title,
        "url": target_url,
        "status": "fixed",
        "http_status": status_code,
        "duration_ms": elapsed_ms,
        "details": "La condición de vulnerabilidad ya no se reproduce.",
    }


def retest_multiple_findings(
    findings: list[Finding | dict[str, Any]],
    session: requests.Session | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """
    Re-prueba quirúrgicamente una lista de hallazgos y genera un resumen consolidado.
    """
    results: list[dict[str, Any]] = []
    fixed_count = 0
    vulnerable_count = 0
    inconclusive_count = 0

    s = session or requests.Session()
    for f in findings:
        res = retest_finding(f, session=s, timeout=timeout)
        results.append(res)
        status = res.get("status")
        if status == "fixed":
            fixed_count += 1
        elif status == "still_vulnerable":
            vulnerable_count += 1
        else:
            inconclusive_count += 1

    return {
        "total_retested": len(findings),
        "fixed": fixed_count,
        "still_vulnerable": vulnerable_count,
        "inconclusive": inconclusive_count,
        "results": results,
    }
