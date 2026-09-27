"""
Motor de Parcheo Virtual y Síntesis de Reglas WAF (Virtual Patching Engine).

Genera automáticamente contramedidas y reglas defensivas inmediatas para Web Application
Firewalls (WAF) a partir de vulnerabilidades detectadas (SQLi, XSS, Path Traversal, SSRF, etc.),
permitiendo mitigar amenazas en producción (ModSecurity/OWASP CRS, AWS WAF, Cloudflare WAF, Nginx)
en minutos mientras se repara el código fuente subyacente.
"""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from scanner.models import Finding


@dataclass
class VirtualPatch:
    """Representa una contramedida de parcheo virtual para un hallazgo específico."""
    rule_id: int
    vuln_type: str
    target_url: str
    parameter: str | None
    cwe_id: str
    modsecurity_rule: str
    aws_waf_rule: dict[str, Any]
    cloudflare_rule: str
    nginx_rule: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VirtualPatchEngine:
    """
    Sintetizador de reglas de mitigación WAF multi-proveedor.
    Soporta ModSecurity (OWASP CRS), AWS WAF v2, Cloudflare WAF Expressions y Nginx.
    """

    # Firmas regex estándar para contramedidas perimetrales por categoría de vulnerabilidad
    CATEGORY_SIGNATURES: dict[str, dict[str, str]] = {
        "sqli": {
            "regex": r"(?i)(?:'|\"|%27|%22)\s*(?:union|select|insert|update|delete|drop|or\s+1=1|and\s+1=1|--|#|/\*)",
            "aws_pattern": "union select",
            "cf_pattern": "union select",
            "desc": "Bloquear vectores comunes de inyección SQL en parámetros o cuerpo.",
        },
        "xss": {
            "regex": r"(?i)(?:<script|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=)",
            "aws_pattern": "<script>",
            "cf_pattern": "<script",
            "desc": "Filtrar tags script y manejadores de eventos JavaScript para prevenir XSS.",
        },
        "path_traversal": {
            "regex": r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)",
            "aws_pattern": "../",
            "cf_pattern": "../",
            "desc": "Denegar secuencias de escape de directorio (dot-dot-slash) en rutas y argumentos.",
        },
        "injections": {
            "regex": r"(?i)(?:;\s*(?:cat|ls|whoami|id|bash|sh|curl|wget)\b|\||\`|\$\()",
            "aws_pattern": "; whoami",
            "cf_pattern": "; cat",
            "desc": "Impedir inyección de comandos del sistema operativo y tuberías de shell.",
        },
        "ssrf": {
            "regex": r"(?i)(?:https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\]))",
            "aws_pattern": "169.254.169.254",
            "cf_pattern": "169.254.169.254",
            "desc": "Bloquear intentos de redirección hacia direcciones de loopback o metadatos de nube.",
        },
        "xxe": {
            "regex": r"(?i)(?:<!ENTITY\s+|SYSTEM\s+[\"']file://)",
            "aws_pattern": "<!ENTITY",
            "cf_pattern": "<!ENTITY",
            "desc": "Rechazar entidades externas XML (XXE) en cuerpos de peticiones XML.",
        },
        "file_upload": {
            "regex": r"(?i)\.(?:php[0-9]?|phtml|jsp[xa]?|asp[x]?|exe|sh|bash)$",
            "aws_pattern": ".php",
            "cf_pattern": ".php",
            "desc": "Restringir la subida de extensiones ejecutables o web shells.",
        },
        "default": {
            "regex": r"(?i)(?:'|\"|;|--|<|>|\.\./)",
            "aws_pattern": "../",
            "cf_pattern": "../",
            "desc": "Mitigación defensiva genérica de filtrado de metacaracteres.",
        },
    }

    @staticmethod
    def _extract_finding_data(f: Finding | dict[str, Any]) -> tuple[str, str, str | None, str, str]:
        """Extrae (category, affected_url, parameter, cwe_id, title) de forma agnóstica."""
        if isinstance(f, Finding):
            cat = f.category or "default"
            url = f.affected_url or "/"
            param = f.parameter
            cwe = f.cwe_id or "CWE-693"
            title = f.title or "Vulnerabilidad detectada"
        else:
            cat = f.get("category", "default")
            url = f.get("affected_url") or f.get("url") or "/"
            param = f.get("parameter") or f.get("param")
            cwe = f.get("cwe_id") or "CWE-693"
            title = f.get("title") or f.get("vuln") or "Vulnerabilidad detectada"
        return cat.lower(), url, param, cwe, title

    @classmethod
    def synthesize_patch(cls, finding: Finding | dict[str, Any], rule_id: int = 100001) -> VirtualPatch:
        """
        Sintetiza un parche virtual en 4 formatos (ModSecurity, AWS WAF, Cloudflare, Nginx)
        para una vulnerabilidad individual.
        """
        category, url, parameter, cwe, title = cls._extract_finding_data(finding)
        sig = cls.CATEGORY_SIGNATURES.get(category, cls.CATEGORY_SIGNATURES["default"])
        regex = sig["regex"]
        aws_pattern = sig["aws_pattern"]
        cf_pattern = sig["cf_pattern"]
        desc = sig["desc"]

        parsed = urlparse(url)
        path = parsed.path if parsed.path else "/"
        # Sanitizar path para expresiones
        clean_path = re.sub(r'["\\]', '', path)
        param_clean = re.sub(r'[^a-zA-Z0-9_\-\[\]]', '', parameter) if parameter else None

        # 1. ModSecurity / OWASP CRS
        if param_clean:
            modsec = (
                f'SecRule REQUEST_URI "@beginsWith {clean_path}" '
                f'"id:{rule_id},phase:2,deny,status:403,log,'
                f'msg:\'OmniBreach Virtual Patch: {title} on parameter {param_clean}\','
                f'tag:\'omnibreach\',tag:\'{cwe}\',chain"\n'
                f'  SecRule ARGS:{param_clean} "@rx {regex}"'
            )
        else:
            modsec = (
                f'SecRule REQUEST_URI "@beginsWith {clean_path}" '
                f'"id:{rule_id},phase:1,deny,status:403,log,'
                f'msg:\'OmniBreach Virtual Patch: {title} on path {clean_path}\','
                f'tag:\'omnibreach\',tag:\'{cwe}\'"'
            )

        # 2. AWS WAF v2 JSON
        rule_name = f"OmniBreach_VP_{rule_id}_{category.upper()}"
        if param_clean:
            statement: dict[str, Any] = {
                "AndStatement": {
                    "Statements": [
                        {
                            "ByteMatchStatement": {
                                "SearchString": clean_path,
                                "FieldToMatch": {"UriPath": {}},
                                "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                                "PositionalConstraint": "STARTS_WITH",
                            }
                        },
                        {
                            "ByteMatchStatement": {
                                "SearchString": aws_pattern,
                                "FieldToMatch": {
                                    "SingleQueryArgument": {"Name": param_clean}
                                },
                                "TextTransformations": [
                                    {"Priority": 0, "Type": "URL_DECODE"},
                                    {"Priority": 1, "Type": "LOWERCASE"},
                                ],
                                "PositionalConstraint": "CONTAINS",
                            }
                        },
                    ]
                }
            }
        else:
            statement = {
                "ByteMatchStatement": {
                    "SearchString": clean_path,
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                    "PositionalConstraint": "STARTS_WITH",
                }
            }

        aws_waf: dict[str, Any] = {
            "Name": rule_name,
            "Priority": rule_id % 1000,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": rule_name,
            },
            "Statement": statement,
        }

        # 3. Cloudflare WAF Expression
        if param_clean:
            cloudflare = (
                f'(http.request.uri.path eq "{clean_path}" and '
                f'http.request.uri.args["{param_clean}"][0] contains "{cf_pattern}")'
            )
        else:
            cloudflare = f'http.request.uri.path eq "{clean_path}"'

        # 4. Nginx Native Mitigation Snippet
        if param_clean:
            nginx = (
                f"location = {clean_path} {{\n"
                f'    if ($arg_{param_clean} ~* "{regex}") {{\n'
                f"        return 403;\n"
                f"    }}\n"
                f"    proxy_pass http://backend_upstream;\n"
                f"}}"
            )
        else:
            nginx = (
                f"location = {clean_path} {{\n"
                f"    deny all;\n"
                f"    return 403;\n"
                f"}}"
            )

        return VirtualPatch(
            rule_id=rule_id,
            vuln_type=category,
            target_url=url,
            parameter=param_clean,
            cwe_id=cwe,
            modsecurity_rule=modsec,
            aws_waf_rule=aws_waf,
            cloudflare_rule=cloudflare,
            nginx_rule=nginx,
            description=desc,
        )

    @classmethod
    def synthesize_all(
        cls,
        findings: Sequence[Finding | dict[str, Any]],
        starting_id: int = 100001,
    ) -> list[VirtualPatch]:
        """Sintetiza parches virtuales para todos los hallazgos proporcionados."""
        patches: list[VirtualPatch] = []
        current_id = starting_id
        for f in findings:
            patches.append(cls.synthesize_patch(f, rule_id=current_id))
            current_id += 1
        return patches

    @classmethod
    def export_ruleset(
        cls,
        findings: Sequence[Finding | dict[str, Any]],
        format: str = "modsecurity",
        starting_id: int = 100001,
    ) -> str:
        """
        Exporta el conjunto de parches virtuales en el formato deseado:
        'modsecurity', 'aws_waf', 'cloudflare', 'nginx' o 'all'.
        """
        patches = cls.synthesize_all(findings, starting_id=starting_id)
        fmt = format.lower().strip()

        if fmt == "modsecurity":
            lines = [
                "# =====================================================================",
                "# OMNIBREACH AUTOMATED VIRTUAL PATCHING RULESET - MODSECURITY (OWASP CRS)",
                f"# Generated rules: {len(patches)}",
                "# =====================================================================\n",
            ]
            for p in patches:
                lines.append(f"# {p.vuln_type.upper()} on {p.target_url} ({p.cwe_id})")
                lines.append(p.modsecurity_rule)
                lines.append("")
            return "\n".join(lines)

        if fmt in ("aws_waf", "awswaf", "aws"):
            rules = [p.aws_waf_rule for p in patches]
            return json.dumps(rules, indent=2, ensure_ascii=False)

        if fmt in ("cloudflare", "cf"):
            lines = [
                "# Cloudflare Custom Firewall Rules (Expressions)",
                f"# Total Expressions: {len(patches)}\n",
            ]
            for p in patches:
                lines.append(f"# Rule {p.rule_id} - {p.vuln_type} ({p.cwe_id})")
                lines.append(f"Expression: {p.cloudflare_rule}")
                lines.append("Action: Block\n")
            return "\n".join(lines)

        if fmt == "nginx":
            lines = [
                "# Nginx Virtual Patching Mitigation Block",
                f"# Generated rules: {len(patches)}\n",
            ]
            for p in patches:
                lines.append(f"# Mitigate {p.vuln_type} ({p.cwe_id})")
                lines.append(p.nginx_rule)
                lines.append("")
            return "\n".join(lines)

        # Multi-format consolidated bundle
        bundle = {
            "summary": {
                "total_patches": len(patches),
                "starting_id": starting_id,
            },
            "modsecurity": cls.export_ruleset(findings, format="modsecurity", starting_id=starting_id),
            "aws_waf": [p.aws_waf_rule for p in patches],
            "cloudflare": [
                {"id": p.rule_id, "expression": p.cloudflare_rule, "action": "block"}
                for p in patches
            ],
            "nginx": cls.export_ruleset(findings, format="nginx", starting_id=starting_id),
            "patches": [p.to_dict() for p in patches],
        }
        return json.dumps(bundle, indent=2, ensure_ascii=False)
