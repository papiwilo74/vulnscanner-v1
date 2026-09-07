"""Modelo estandarizado de hallazgos para VulnScanner con soporte CVSS v3.1, CWE y MITRE ATT&CK."""
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """Evidencia técnica de un hallazgo de vulnerabilidad."""
    request_method: str = "GET"
    request_url: str = ""
    payload: Optional[str] = None
    response_status: Optional[int] = None
    response_fragment: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_method": self.request_method,
            "request_url": self.request_url,
            "payload": self.payload,
            "response_status": self.response_status,
            "response_fragment": self.response_fragment,
        }


# Base de conocimiento formal de estándares de la industria
VULN_STANDARDS_DB: dict[str, dict[str, Any]] = {
    "sqli": {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 9.8,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021-Injection",
    },
    "xss": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "mitre_attack_id": "T1189",
        "mitre_attack_name": "Drive-by Compromise",
        "default_cvss_score": 7.2,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "owasp_category": "A03:2021-Injection",
    },
    "dom_xss": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('DOM-based Cross-site Scripting')",
        "mitre_attack_id": "T1059.007",
        "mitre_attack_name": "JavaScript Execution / DOM XSS",
        "default_cvss_score": 6.1,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "owasp_category": "A03:2021-Injection",
    },
    "injections": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "mitre_attack_id": "T1059",
        "mitre_attack_name": "Command and Scripting Interpreter",
        "default_cvss_score": 9.8,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021-Injection",
    },
    "path_traversal": {
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "mitre_attack_id": "T1083",
        "mitre_attack_name": "File and Directory Discovery",
        "default_cvss_score": 7.5,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A01:2021-Broken Access Control",
    },
    "xxe": {
        "cwe_id": "CWE-611",
        "cwe_name": "Improper Restriction of XML External Entity Reference",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 8.2,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "ssrf": {
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 8.6,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
    },
    "oast": {
        "cwe_id": "CWE-918",
        "cwe_name": "Out-of-Band Interaction (Blind SSRF / Blind RCE / Blind XXE)",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 9.0,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
    },
    "jwt": {
        "cwe_id": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "mitre_attack_id": "T1552",
        "mitre_attack_name": "Unsecured Credentials",
        "default_cvss_score": 8.1,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
    },
    "cors": {
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-Domain Policy with Untrusted Domains",
        "mitre_attack_id": "T1189",
        "mitre_attack_name": "Drive-by Compromise",
        "default_cvss_score": 5.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "csrf": {
        "cwe_id": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery (CSRF)",
        "mitre_attack_id": "T1189",
        "mitre_attack_name": "Drive-by Compromise",
        "default_cvss_score": 6.5,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "owasp_category": "A01:2021-Broken Access Control",
    },
    "headers": {
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure (Missing Security Headers)",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 3.7,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "cookies": {
        "cwe_id": "CWE-614",
        "cwe_name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "mitre_attack_id": "T1539",
        "mitre_attack_name": "Steal Web Session Cookie",
        "default_cvss_score": 4.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "ssl": {
        "cwe_id": "CWE-326",
        "cwe_name": "Inadequate Encryption Strength",
        "mitre_attack_id": "T1040",
        "mitre_attack_name": "Network Sniffing",
        "default_cvss_score": 5.9,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021-Cryptographic Failures",
    },
    "sensitive_data": {
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "mitre_attack_id": "T1552.001",
        "mitre_attack_name": "Credentials in Files",
        "default_cvss_score": 7.5,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021-Cryptographic Failures",
    },
    "open_redirect": {
        "cwe_id": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "mitre_attack_id": "T1566.002",
        "mitre_attack_name": "Spearphishing Link",
        "default_cvss_score": 6.1,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "owasp_category": "A01:2021-Broken Access Control",
    },
    "prototype_pollution": {
        "cwe_id": "CWE-1321",
        "cwe_name": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
        "mitre_attack_id": "T1059.007",
        "mitre_attack_name": "JavaScript",
        "default_cvss_score": 7.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "owasp_category": "A03:2021-Injection",
    },
    "file_upload": {
        "cwe_id": "CWE-434",
        "cwe_name": "Unrestricted Upload of File with Dangerous Type",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 8.8,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021-Injection",
    },
    "graphql": {
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure Through Introspection Query",
        "mitre_attack_id": "T1083",
        "mitre_attack_name": "File and Directory Discovery",
        "default_cvss_score": 5.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "websocket": {
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information (Unencrypted WebSocket)",
        "mitre_attack_id": "T1040",
        "mitre_attack_name": "Network Sniffing",
        "default_cvss_score": 5.9,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021-Cryptographic Failures",
    },
    "sca": {
        "cwe_id": "CWE-1395",
        "cwe_name": "Dependency on Vulnerable Third-Party Component",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 6.5,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
    },
    "directories": {
        "cwe_id": "CWE-548",
        "cwe_name": "Exposure of Information Through Directory Listing / Exposed Path",
        "mitre_attack_id": "T1083",
        "mitre_attack_name": "File and Directory Discovery",
        "default_cvss_score": 5.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "ports": {
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure Through Exposed Network Service",
        "mitre_attack_id": "T1046",
        "mitre_attack_name": "Network Service Discovery",
        "default_cvss_score": 5.3,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "fuzzer": {
        "cwe_id": "CWE-538",
        "cwe_name": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "mitre_attack_id": "T1552.001",
        "mitre_attack_name": "Credentials in Files",
        "default_cvss_score": 7.5,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
    "default": {
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "mitre_attack_id": "T1190",
        "mitre_attack_name": "Exploit Public-Facing Application",
        "default_cvss_score": 4.0,
        "default_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021-Security Misconfiguration",
    },
}


@dataclass
class Finding:
    """Hallazgo estandarizado de vulnerabilidad con soporte para métricas avanzadas."""
    category: str
    title: str
    severity: str
    confidence: str = "possible"
    description: str = ""
    evidence: Optional[Evidence] = None
    remediation: Optional[str] = None
    affected_url: Optional[str] = None
    parameter: Optional[str] = None

    # Campos avanzados para estándares profesionales
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    mitre_attack_id: str = ""
    mitre_attack_name: str = ""
    owasp_category: str = ""
    autofix: Optional[dict[str, Any]] = None

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    SEVERITY_ORDER: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }, repr=False, init=False)

    def __post_init__(self):
        # Auto-enriquecer con estándares de seguridad si no se especificaron explícitamente
        std = VULN_STANDARDS_DB.get(self.category, VULN_STANDARDS_DB["default"])
        if not self.cwe_id:
            self.cwe_id = std.get("cwe_id", "CWE-693")
        if not self.cwe_name:
            self.cwe_name = std.get("cwe_name", "Protection Mechanism Failure")
        if not self.mitre_attack_id:
            self.mitre_attack_id = std.get("mitre_attack_id", "T1190")
        if not self.mitre_attack_name:
            self.mitre_attack_name = std.get("mitre_attack_name", "Exploit Public-Facing Application")
        if not self.owasp_category:
            self.owasp_category = std.get("owasp_category", "A05:2021-Security Misconfiguration")
        if not self.cvss_vector:
            self.cvss_vector = std.get("default_cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        if self.cvss_score == 0.0:
            # Calibrar CVSS según la severidad asignada
            base_score = std.get("default_cvss_score", 4.0)
            if self.severity == "critical":
                self.cvss_score = max(base_score, 9.0)
            elif self.severity == "high":
                self.cvss_score = min(max(base_score, 7.0), 8.9)
            elif self.severity == "medium":
                self.cvss_score = min(max(base_score, 4.0), 6.9)
            elif self.severity == "low":
                self.cvss_score = min(max(base_score, 0.1), 3.9)
            else:
                self.cvss_score = 0.0

    @property
    def severity_rank(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 99)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "remediation": self.remediation,
            "affected_url": self.affected_url,
            "parameter": self.parameter,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_attack_name": self.mitre_attack_name,
            "owasp_category": self.owasp_category,
            "autofix": self.autofix,
        }

    @classmethod
    def from_legacy(cls, data: dict, category: str, url: str = "", param: str = "") -> "Finding":
        """Convierte un dict legacy {vuln, risk, detail} a Finding con enriquecimiento automático."""
        risk_map = {"Alto": "high", "Medio": "medium", "Bajo": "low"}
        return cls(
            category=category,
            title=data.get("vuln", ""),
            severity=risk_map.get(data.get("risk", ""), "info"),
            confidence=data.get("confidence", "possible"),
            description=data.get("detail", ""),
            affected_url=url,
            parameter=param,
        )

    @classmethod
    def from_legacy_list(cls, items: list[dict], category: str, url: str = "") -> list["Finding"]:
        return [cls.from_legacy(item, category, url) for item in items]

    def __hash__(self) -> int:
        key = f"{self.category}:{self.title}:{self.affected_url}:{self.parameter}"
        return hash(key)

    def dedup_key(self) -> str:
        return hashlib.md5(
            f"{self.category}|{self.title}|{self.affected_url or ''}|{self.parameter or ''}".encode(),
            usedforsecurity=False
        ).hexdigest()


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Elimina hallazgos duplicados manteniendo el de mayor severidad y más evidencia."""
    seen: dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key()
        if key not in seen or f.severity_rank < seen[key].severity_rank:
            seen[key] = f
    return sorted(seen.values(), key=lambda f: f.severity_rank)


REMEDIATIONS: dict[str, str] = {
    "headers": "Configurar cabeceras de seguridad HTTP (CSP, HSTS, X-Content-Type-Options) en el servidor web o WAF.",
    "xss": "Escapar toda salida HTML usando Contextual Output Encoding e implementar Content-Security-Policy estricto.",
    "sqli": "Usar consultas parametrizadas (Prepared Statements) o un ORM seguro.",
    "cors": "Restringir Access-Control-Allow-Origin a dominios explícitos de confianza y evitar '*' con credenciales.",
    "ssl": "Habilitar HTTPS obligatorio con certificados válidos y deshabilitar versiones obsoletas de TLS (1.0/1.1).",
    "cookies": "Agregar flags Secure, HttpOnly y SameSite=Lax/Strict a todas las cookies de sesión.",
    "csrf": "Implementar tokens anti-CSRF criptográficos en todos los formularios y operaciones con estado.",
    "sensitive_data": "No exponer claves API, credenciales ni endpoints internos en el código del frontend.",
    "path_traversal": "Validar y sanitizar rutas de archivo mediante whitelists estrictas sin permitir '../'.",
    "xxe": "Deshabilitar el procesamiento de entidades externas DTD en todos los parsers XML.",
    "open_redirect": "Validar URLs de redirección contra una lista blanca fija de dominios autorizados.",
    "jwt": "Rechazar tokens con algoritmo 'none', forzar firmas robustas (RS256/ES256) y validar claims de expiración.",
    "file_upload": "Validar tipo MIME, extensión, contenido real y almacenar archivos fuera del webroot.",
    "prototype_pollution": "Usar Object.create(null) o Map, y congelar Object.prototype para prevenir mutaciones.",
    "graphql": "Deshabilitar introspección en producción, limitar profundidad de consulta e implementar rate limiting.",
    "websocket": "Usar protocolo seguro wss:// y autenticar el handshake inicial.",
    "injections": "Nunca concatenar entradas de usuario en comandos del sistema operativo ni en motores de plantillas (SSTI).",
    "sca": "Actualizar las librerías frontend a versiones seguras sin vulnerabilidades conocidas.",
    "oast": "Sanitizar URLs remotas para evitar SSRF ciego, deshabilitar entidades DTD y restringir tráfico de salida.",
    "default": "Revisar la configuración del servidor y aplicar el principio de mínimo privilegio y defensa en profundidad.",
}
