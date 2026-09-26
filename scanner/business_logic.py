"""
Motor de Auditoría de Lógica de Negocio y Concurrencia (Business Logic & Race Conditions).
Implementa análisis para:
1. CWE-362: Condiciones de Carrera (Race Conditions / Limit Overrun via Synchronized Request Bursts).
2. CWE-840: Evasión de Máquina de Estados / Salto de Pasos en Flujos Transaccionales (Workflow Step Skipping).
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import threading
from typing import Any
from urllib.parse import urlparse

import requests

from scanner.models import Evidence, Finding

logger = logging.getLogger("OmniBreach.BusinessLogic")


def check_race_condition(
    url: str,
    method: str = "POST",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    burst_count: int = 8,
    session: requests.Session | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Evalúa si un endpoint sensible a límites (canje de cupones, reintentos, débitos, votos)
    es vulnerable a condiciones de carrera (Race Conditions / Limit Overrun) mediante una ráfaga
    sincronizada en paralelo con barrera de hilos (threading.Barrier).
    """
    if burst_count < 2:
        return None

    client = session or requests.Session()
    barrier = threading.Barrier(burst_count)
    responses: list[tuple[int, str, float]] = []
    lock = threading.Lock()

    req_headers = dict(headers or {})
    if payload is not None and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    def _worker() -> None:
        try:
            # Esperar a que todos los hilos estén listos para disparar en el mismo milisegundo
            barrier.wait(timeout=5.0)
            req_kwargs: dict[str, Any] = {"headers": req_headers, "timeout": timeout}
            if payload is not None:
                req_kwargs["json"] = payload

            r = client.request(method, url, **req_kwargs)
            with lock:
                responses.append((r.status_code, r.text[:200], r.elapsed.total_seconds()))
        except Exception as exc:
            logger.debug("[RaceCondition] Error en worker de ráfaga: %s", exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=burst_count) as executor:
        futures = [executor.submit(_worker) for _ in range(burst_count)]
        concurrent.futures.wait(futures)

    if len(responses) < 2:
        return None

    success_codes = [status for status, _, _ in responses if status in (200, 201)]

    # Si se permitieron múltiples ejecuciones exitosas concurrentes (>= 2) en una acción
    # que típicamente debe ser idempotente o de uso único
    if len(success_codes) >= 2:
        sample_bodies = [body for _, body, _ in responses if body]
        # Verificar si hay indicios de éxito duplicado
        path = urlparse(url).path
        return Finding(
            category="race_condition",
            title=f"Condición de Carrera (Limit Overrun) detectada en '{path}'",
            severity="high",
            confidence="confirmed" if len(success_codes) >= 3 else "possible",
            description=(
                f"El endpoint '{path}' permitió {len(success_codes)} de {len(responses)} peticiones "
                f"concurrentes exitosas (HTTP 200/201) disparadas simultáneamente. "
                f"Esto indica falta de sincronización atómica a nivel de base de datos o mutex de sesión (CWE-362)."
            ),
            affected_url=url,
            evidence=Evidence(
                request_method=method,
                request_url=url,
                payload=json.dumps(payload) if payload else None,
                response_status=success_codes[0],
                response_fragment=sample_bodies[0] if sample_bodies else "Múltiples respuestas 200 OK simultáneas",
            ),
            remediation=(
                "Implementar bloqueos atómicos en base de datos ('SELECT FOR UPDATE', transacciones aisladas SERIALIZABLE), "
                "bloqueos distribuidos mediante Redis (Redlock) o tokens anti-repetición de un solo uso."
            ),
        )

    return None


def check_workflow_step_skipping(
    steps: list[dict[str, Any]],
    session: requests.Session | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Verifica si en un flujo de varios pasos (ej. [Paso 1: Checkout, Paso 2: Pagar, Paso 3: Confirmar]),
    es posible invocar directamente el paso final o de acción omitiendo los pasos intermedios de validación.
    `steps` debe ser una lista ordenada: [{'url': ..., 'method': ..., 'payload': ...}, ...]
    """
    if len(steps) < 2:
        return None

    # Sesión limpia que NO ha completado los pasos previos
    unprepared_client = session or requests.Session()

    # Intentar ejecutar directamente el último paso
    final_step = steps[-1]
    final_url = str(final_step.get("url", ""))
    final_method = str(final_step.get("method", "POST")).upper()
    final_payload = final_step.get("payload")

    if not final_url:
        return None

    try:
        req_kwargs: dict[str, Any] = {"timeout": timeout}
        if final_payload is not None:
            req_kwargs["json"] = final_payload

        resp = unprepared_client.request(final_method, final_url, **req_kwargs)

        # Si el paso final responde con éxito HTTP 200/201 sin haber pasado por los pasos anteriores
        if resp.status_code in (200, 201):
            body_lower = resp.text.lower()
            # Descartar respuestas de error que devuelvan 200 con mensaje de validación
            if not any(err in body_lower for err in ("error", "invalid state", "prerequisito", "missing step", "unauthorized")):
                path = urlparse(final_url).path
                return Finding(
                    category="business_logic",
                    title=f"Evasión de Flujo de Negocio (Step Skipping) en '{path}'",
                    severity="high",
                    confidence="confirmed",
                    description=(
                        f"Fue posible invocar directamente el paso final '{path}' del flujo de negocio sin haber "
                        f"completado los {len(steps) - 1} paso(s) previo(s) requeridos (CWE-840). "
                        f"La aplicación respondió HTTP {resp.status_code} procesando la acción sin validar el estado de la sesión."
                    ),
                    affected_url=final_url,
                    evidence=Evidence(
                        request_method=final_method,
                        request_url=final_url,
                        payload=json.dumps(final_payload) if final_payload else None,
                        response_status=resp.status_code,
                        response_fragment=resp.text[:300],
                    ),
                    remediation=(
                        "Implementar una máquina de estados finitos (Finite State Machine / FSM) en el servidor que valide "
                        "estrictamente la transición válida de estados antes de procesar cada etapa del flujo de negocio."
                    ),
                )
    except Exception as exc:
        logger.debug("[BusinessLogic] Error probando salto de flujo en %s: %s", final_url, exc)

    return None
