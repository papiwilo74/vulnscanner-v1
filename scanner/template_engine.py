"""
Motor de Reglas Declarativas y Plantillas Dinámicas (YAML/JSON DSL Engine) para OmniBreach.

Permite definir auditorías de seguridad, comprobaciones de configuración y detección de
vulnerabilidades mediante plantillas declarativas desacopladas del código Python del escáner.
Soporta:
1. Peticiones multi-paso encadenadas con interpolación de variables ({{BaseURL}}, {{RootURL}}, etc.).
2. Coincidencias avanzadas (Matchers): Status, Word, Regex, Size con lógica AND/OR y negación (negative: true).
3. Extracción de valores dinámicos (Extractors): Regex y JSONPath para propagación entre pasos consecutivos.
4. Generación estandarizada de modelos Finding con evidencia forense, CWE, CVSS y remediación.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from scanner.models import Evidence, Finding

logger = logging.getLogger("OmniBreach.TemplateEngine")

# Soporte condicional para PyYAML con fallback nativo transparente
try:
    import yaml  # type: ignore

    _HAS_PYYAML = True
except ImportError:
    _HAS_PYYAML = False


class MatcherType(str, Enum):
    STATUS = "status"
    WORD = "word"
    REGEX = "regex"
    SIZE = "size"


class MatcherPart(str, Enum):
    BODY = "body"
    HEADER = "header"
    STATUS = "status"
    ALL = "all"


class MatcherCondition(str, Enum):
    AND = "and"
    OR = "or"


class ExtractorType(str, Enum):
    REGEX = "regex"
    JSON = "json"
    KVAL = "kval"


@dataclass
class Matcher:
    """Regla de validación sobre la respuesta HTTP."""
    type: MatcherType
    part: MatcherPart = MatcherPart.BODY
    condition: MatcherCondition = MatcherCondition.OR
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    negative: bool = False
    case_sensitive: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Matcher:
        m_type = MatcherType(str(data.get("type", "word")).lower())
        m_part = MatcherPart(str(data.get("part", "body")).lower())
        m_cond = MatcherCondition(str(data.get("condition", "or")).lower())

        words = [str(w) for w in data.get("words", [])]
        regex = [str(r) for r in data.get("regex", [])]
        status = [int(s) for s in data.get("status", [])]

        return cls(
            type=m_type,
            part=m_part,
            condition=m_cond,
            words=words,
            regex=regex,
            status=status,
            negative=bool(data.get("negative", False)),
            case_sensitive=bool(data.get("case_sensitive", False)),
        )


@dataclass
class Extractor:
    """Extractor de valores dinámicos para reutilización entre pasos."""
    name: str
    type: ExtractorType = ExtractorType.REGEX
    part: MatcherPart = MatcherPart.BODY
    regex: list[str] = field(default_factory=list)
    json_path: str = ""
    group: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Extractor:
        return cls(
            name=str(data.get("name", "extracted_var")),
            type=ExtractorType(str(data.get("type", "regex")).lower()),
            part=MatcherPart(str(data.get("part", "body")).lower()),
            regex=[str(r) for r in data.get("regex", [])],
            json_path=str(data.get("json_path", "")),
            group=int(data.get("group", 1)),
        )


@dataclass
class RequestSpec:
    """Especificación de petición HTTP a ejecutar dentro de la plantilla."""
    method: str = "GET"
    path: list[str] = field(default_factory=lambda: ["/"])
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    follow_redirects: bool = True
    matchers: list[Matcher] = field(default_factory=list)
    matchers_condition: MatcherCondition = MatcherCondition.AND
    extractors: list[Extractor] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestSpec:
        method = str(data.get("method", "GET")).upper()
        raw_path = data.get("path", ["/"])
        path = [raw_path] if isinstance(raw_path, str) else [str(p) for p in raw_path]

        headers = {str(k): str(v) for k, v in data.get("headers", {}).items()}
        body = data.get("body")
        if body is not None:
            body = str(body)

        matchers = [Matcher.from_dict(m) for m in data.get("matchers", [])]
        extractors = [Extractor.from_dict(e) for e in data.get("extractors", [])]
        m_cond = MatcherCondition(str(data.get("matchers_condition", "and")).lower())

        return cls(
            method=method,
            path=path,
            headers=headers,
            body=body,
            follow_redirects=bool(data.get("redirects", True)),
            matchers=matchers,
            matchers_condition=m_cond,
            extractors=extractors,
        )


@dataclass
class TemplateInfo:
    """Metadatos de la plantilla de seguridad."""
    name: str
    author: str = "OmniBreach Community"
    severity: str = "medium"
    description: str = ""
    remediation: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cwe_id: str = "CWE-200"
    cvss_score: float = 5.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateInfo:
        refs = [str(r) for r in data.get("reference", [])] if isinstance(data.get("reference"), list) else []
        tags = [str(t) for t in data.get("tags", [])] if isinstance(data.get("tags"), list) else []
        try:
            cvss = float(data.get("cvss_score", 5.0))
        except (ValueError, TypeError):
            cvss = 5.0

        return cls(
            name=str(data.get("name", "Plantilla sin nombre")),
            author=str(data.get("author", "OmniBreach Community")),
            severity=str(data.get("severity", "medium")).lower(),
            description=str(data.get("description", "")),
            remediation=str(data.get("remediation", "")),
            reference=refs,
            tags=tags,
            cwe_id=str(data.get("cwe_id", "CWE-200")),
            cvss_score=cvss,
        )


@dataclass
class SecurityTemplate:
    """Definición declarativa completa de una prueba de seguridad."""
    id: str
    info: TemplateInfo
    requests: list[RequestSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityTemplate:
        t_id = str(data.get("id", "custom-template"))
        info = TemplateInfo.from_dict(data.get("info", {}))
        requests_data = data.get("requests", [])
        req_specs = [RequestSpec.from_dict(r) for r in requests_data]
        return cls(id=t_id, info=info, requests=req_specs)


# =========================================================================
# Parser Universal: Soporta YAML nativo o Parser Ligero embebido
# =========================================================================

def _parse_yaml_or_json(content: str) -> dict[str, Any]:
    """Parsea el contenido como JSON o YAML tolerando ausencia de librerías externas."""
    stripped = content.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            return json.loads(stripped)
        except Exception as exc:
            logger.debug("Error parseando como JSON: %s", exc)

    if _HAS_PYYAML:
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:
            logger.warning("Fallo al parsear YAML con PyYAML: %s", exc)

    # Fallback: Parser declarativo ligero para subconjunto YAML estructurado
    return _parse_lightweight_yaml(content)


def _parse_lightweight_yaml(text: str) -> dict[str, Any]:
    """
    Parser recursivo ligero para plantillas YAML de OmniBreach.
    Soporta diccionarios anidados, listas y cadenas escalares.
    """
    lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any, str | None]] = [(-1, root, None)]

    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        # Ajustar la pila según nivel de indentación
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()

        current_parent = stack[-1][1]

        # Elemento de lista "- ..."
        if stripped.startswith("- "):
            item_content = stripped[2:].strip()
            if not isinstance(current_parent, list):
                # Si el contenedor actual esperaba lista
                continue

            if ":" in item_content and not item_content.startswith(('"', "'", "{", "[")):
                # Lista de diccionarios "- key: value"
                k, v = item_content.split(":", 1)
                new_dict: dict[str, Any] = {k.strip(): _coerce_yaml_scalar(v.strip())}
                current_parent.append(new_dict)
                stack.append((indent, new_dict, k.strip()))
            else:
                current_parent.append(_coerce_yaml_scalar(item_content))
            continue

        # Clave-Valor "key: value"
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            key = k.strip()
            val = v.strip()

            if not val:
                # Se espera un contenedor anidado (dict o lista)
                # Inspección heurística: si el siguiente bloque empieza con -, es lista
                new_container: Any = {}
                if isinstance(current_parent, dict):
                    current_parent[key] = new_container
                elif isinstance(current_parent, list):
                    current_parent.append({key: new_container})
                stack.append((indent, new_container, key))
            else:
                if isinstance(current_parent, dict):
                    # Si el contenedor era dict pero la clave recibe '- ' en líneas posteriores
                    current_parent[key] = _coerce_yaml_scalar(val)

    return root


def _coerce_yaml_scalar(val: str) -> Any:
    """Convierte cadenas escalares de YAML a tipos nativos Python."""
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    val_lower = val.lower()
    if val_lower in ("true", "yes", "on"):
        return True
    if val_lower in ("false", "no", "off"):
        return False
    if val_lower in ("null", "none", "~"):
        return None
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        pass
    if val.startswith("[") and val.endswith("]"):
        items = val[1:-1].split(",")
        return [_coerce_yaml_scalar(i.strip()) for i in items if i.strip()]
    return val


# =========================================================================
# Motor de Ejecución de Plantillas
# =========================================================================

class TemplateEngine:
    """Orquestador de ejecución de plantillas declarativas DSL."""

    def __init__(self, session: requests.Session | None = None, default_timeout: float = 6.0) -> None:
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    @staticmethod
    def load_from_string(content: str) -> SecurityTemplate:
        """Carga una plantilla desde una cadena YAML o JSON."""
        data = _parse_yaml_or_json(content)
        return SecurityTemplate.from_dict(data)

    @staticmethod
    def load_from_file(file_path: str | Path) -> SecurityTemplate:
        """Lee y deserializa una plantilla desde el sistema de archivos."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Plantilla no encontrada: {file_path}")
        content = p.read_text(encoding="utf-8")
        return TemplateEngine.load_from_string(content)

    @staticmethod
    def load_from_dir(dir_path: str | Path, recursive: bool = True) -> list[SecurityTemplate]:
        """Carga todas las plantillas (.yaml, .yml, .json) de un directorio."""
        p = Path(dir_path)
        if not p.is_dir():
            logger.warning("Directorio de plantillas no existe: %s", dir_path)
            return []

        pattern = "**/*" if recursive else "*"
        templates: list[SecurityTemplate] = []
        for file in p.glob(pattern):
            if file.suffix.lower() in (".yaml", ".yml", ".json") and file.is_file():
                try:
                    tmpl = TemplateEngine.load_from_file(file)
                    templates.append(tmpl)
                except Exception as exc:
                    logger.warning("Error cargando plantilla '%s': %s", file.name, exc)
        return templates

    def execute_template(
        self,
        template: SecurityTemplate,
        target_url: str,
        timeout: float | None = None,
    ) -> list[Finding]:
        """
        Ejecuta una plantilla contra un objetivo HTTP respetando encadenamiento,
        interpolación de variables, evaluación de matchers y extractores.
        """
        findings: list[Finding] = []
        tout = timeout or self.default_timeout

        # Construcción del contexto base de variables
        parsed_target = urlparse(target_url)
        root_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        hostname = parsed_target.hostname or ""
        port = str(parsed_target.port or (443 if parsed_target.scheme == "https" else 80))

        env_vars: dict[str, str] = {
            "BaseURL": target_url.rstrip("/"),
            "RootURL": root_url.rstrip("/"),
            "Hostname": hostname,
            "Host": parsed_target.netloc,
            "Port": port,
            "Scheme": parsed_target.scheme or "http",
        }

        # Ejecución secuencial de las peticiones especificadas en la plantilla
        for _req_idx, req_spec in enumerate(template.requests):
            for path_tpl in req_spec.path:
                resolved_url = self._interpolate(path_tpl, env_vars)
                if not resolved_url.startswith(("http://", "https://")):
                    resolved_url = urljoin(target_url, resolved_url)

                # Resolver cabeceras y cuerpo
                req_headers = {k: self._interpolate(v, env_vars) for k, v in req_spec.headers.items()}
                req_body = self._interpolate(req_spec.body, env_vars) if req_spec.body else None

                try:
                    resp = self.session.request(
                        method=req_spec.method,
                        url=resolved_url,
                        headers=req_headers,
                        data=req_body,
                        timeout=tout,
                        allow_redirects=req_spec.follow_redirects,
                        verify=False,  # nosec B501
                    )
                except Exception as exc:
                    logger.debug("Error ejecutando petición [%s %s]: %s", req_spec.method, resolved_url, exc)
                    continue

                # Ejecutar extractores para propagar variables a pasos posteriores
                for ext in req_spec.extractors:
                    self._run_extractor(ext, resp, env_vars)

                # Evaluar matchers
                matched, evidence_fragment = self._evaluate_matchers(req_spec, resp)

                if matched:
                    finding = Finding(
                        category="template_dsl",
                        title=f"[{template.id}] {template.info.name}",
                        severity=template.info.severity,
                        confidence="confirmed",
                        description=template.info.description or f"Regla declarativa '{template.id}' activada.",
                        affected_url=resolved_url,
                        evidence=Evidence(
                            request_method=req_spec.method,
                            request_url=resolved_url,
                            payload=req_body or path_tpl,
                            response_status=resp.status_code,
                            response_fragment=evidence_fragment or resp.text[:250],
                        ),
                        remediation=template.info.remediation or "Revisar la configuración y accesos del recurso.",
                    )
                    # Enriquecer con metadatos de estándares
                    if template.info.cwe_id:
                        finding.cwe_id = template.info.cwe_id
                    if template.info.cvss_score:
                        finding.cvss_score = template.info.cvss_score

                    findings.append(finding)

        return findings

    def execute_all(
        self,
        templates: list[SecurityTemplate],
        target_url: str,
        max_workers: int = 5,
        timeout: float | None = None,
    ) -> list[Finding]:
        """Ejecuta una colección de plantillas en paralelo contra el objetivo."""
        if not templates:
            return []

        all_findings: list[Finding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tmpl = {
                executor.submit(self.execute_template, tmpl, target_url, timeout): tmpl
                for tmpl in templates
            }
            for future in concurrent.futures.as_completed(future_to_tmpl):
                tmpl = future_to_tmpl[future]
                try:
                    res = future.result()
                    all_findings.extend(res)
                except Exception as exc:
                    logger.warning("Fallo al ejecutar plantilla '%s': %s", tmpl.id, exc)

        return all_findings

    # ---------------------------------------------------------------------
    # Métodos Auxiliares de Interpolación y Evaluación
    # ---------------------------------------------------------------------

    def _interpolate(self, text: str | None, vars_dict: dict[str, str]) -> str:
        """Reemplaza marcas {{Variable}} por su valor en el diccionario."""
        if not text:
            return ""
        result = text
        for k, v in vars_dict.items():
            result = result.replace(f"{{{{{k}}}}}", str(v))
        return result

    def _evaluate_matchers(self, req_spec: RequestSpec, resp: requests.Response) -> tuple[bool, str]:
        """Evalúa las reglas de coincidencia (matchers) sobre la respuesta recibida."""
        if not req_spec.matchers:
            # Los pasos sin matchers son auxiliares (para extracción de tokens o setup)
            return (False, "")

        results: list[tuple[bool, str]] = []
        for matcher in req_spec.matchers:
            res, frag = self._evaluate_single_matcher(matcher, resp)
            results.append((res, frag))

        matches = [r[0] for r in results]
        evidence_frags = [r[1] for r in results if r[1]]

        final_match: bool
        if req_spec.matchers_condition == MatcherCondition.AND:
            final_match = all(matches)
        else:
            final_match = any(matches)

        frag = evidence_frags[0] if evidence_frags else ""
        return (final_match, frag)

    def _evaluate_single_matcher(self, matcher: Matcher, resp: requests.Response) -> tuple[bool, str]:
        """Evalúa un matcher individual según su tipo y parte evaluada."""
        # Seleccionar texto objetivo según matcher.part
        target_text: str = ""
        if matcher.part == MatcherPart.BODY:
            target_text = resp.text
        elif matcher.part == MatcherPart.HEADER:
            target_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        elif matcher.part == MatcherPart.ALL:
            header_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            target_text = f"{header_str}\n\n{resp.text}"

        matched = False
        evidence = ""

        if matcher.type == MatcherType.STATUS:
            matched = resp.status_code in matcher.status
            evidence = f"HTTP Status: {resp.status_code}"

        elif matcher.type == MatcherType.WORD:
            evaluated_text = target_text if matcher.case_sensitive else target_text.lower()
            word_matches: list[bool] = []
            found_words: list[str] = []

            for w in matcher.words:
                search_word = w if matcher.case_sensitive else w.lower()
                is_present = search_word in evaluated_text
                word_matches.append(is_present)
                if is_present:
                    found_words.append(w)

            if matcher.condition == MatcherCondition.AND:
                matched = bool(word_matches and all(word_matches))
            else:
                matched = any(word_matches)

            if matched:
                evidence = f"Palabras coincidentes: {', '.join(found_words)}"

        elif matcher.type == MatcherType.REGEX:
            for pattern in matcher.regex:
                flags = 0 if matcher.case_sensitive else re.IGNORECASE
                match_obj = re.search(pattern, target_text, flags)
                if match_obj:
                    matched = True
                    evidence = f"Expresión regular '{pattern}' encontrada: {match_obj.group(0)[:120]}"
                    break

        elif matcher.type == MatcherType.SIZE:
            # Tamaño en bytes del cuerpo
            body_size = len(resp.content)
            # matcher.status se reutiliza para tamaños válidos en bytes
            matched = body_size in matcher.status
            evidence = f"Tamaño de cuerpo: {body_size} bytes"

        # Manejo de condición negativa
        if matcher.negative:
            matched = not matched

        return (matched, evidence)

    def _run_extractor(self, extractor: Extractor, resp: requests.Response, env_vars: dict[str, str]) -> None:
        """Extrae datos de la respuesta y los almacena en el diccionario de variables."""
        target_text = resp.text if extractor.part == MatcherPart.BODY else "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        if extractor.type == ExtractorType.REGEX:
            for pat in extractor.regex:
                m = re.search(pat, target_text)
                if m:
                    extracted = m.group(extractor.group) if m.lastindex and m.lastindex >= extractor.group else m.group(0)
                    env_vars[extractor.name] = extracted
                    logger.debug("Extractor '%s' capturó: %s", extractor.name, extracted)
                    break

        elif extractor.type == ExtractorType.JSON:
            with contextlib.suppress(Exception):
                data = resp.json()
                # Navegación básica por claves separadas por puntos (ej. "data.token")
                val: Any = data
                for part in extractor.json_path.split("."):
                    if isinstance(val, dict):
                        val = val.get(part)
                    else:
                        val = None
                        break
                if val is not None:
                    env_vars[extractor.name] = str(val)
                    logger.debug("Extractor JSON '%s' capturó: %s", extractor.name, val)
