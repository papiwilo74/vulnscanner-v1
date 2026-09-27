"""
Motor Avanzado de Prevención de Fuga de Datos (DLP - Data Loss Prevention) y Detección de Secretos.

Detecta y valida fugas de información confidencial en cabeceras y cuerpos HTTP:
1. Números de tarjetas de crédito validados mediante el Algoritmo de Luhn (Mod 10).
2. Números de Seguro Social (SSN) con verificación de rangos geográficos.
3. Bloques de certificados y llaves privadas criptográficas (PEM / RSA / EC).
4. Secretos de infraestructura de nube (AWS, Stripe, Slack, GitHub, Firebase).
5. Cadenas de conexión de bases de datos con credenciales embebidas.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any

from scanner.models import Evidence, Finding


def luhn_checksum(number_str: str) -> bool:
    """
    Verifica si una cadena numérica cumple con el algoritmo de Luhn (Módulo 10).
    Elimina falsos positivos de secuencias numéricas aleatorias en HTML/JS.
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Descartar repeticiones triviales (ej. 1111111111111111, 0000000000000000)
    if len(set(digits)) <= 1:
        return False

    checksum = 0
    # Recorrer dígitos de derecha a izquierda
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else (doubled - 9)
        else:
            checksum += digit

    return checksum % 10 == 0


def mask_credit_card(card_digits: str) -> str:
    """Oculta los dígitos centrales de una tarjeta de crédito (ej. 4532-****-****-8821)."""
    clean = re.sub(r"\D", "", card_digits)
    if len(clean) < 13:
        return "****"
    first4 = clean[:4]
    last4 = clean[-4:]
    return f"{first4}-****-****-{last4}"


def mask_secret(secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Oculta el cuerpo central de un secreto (ej. sk_live_...4f2a)."""
    if len(secret) <= (keep_start + keep_end):
        return "..."
    return f"{secret[:keep_start]}...{secret[-keep_end:]}"


def shannon_entropy(data: str) -> float:
    """Calcula la entropía de Shannon en bits/carácter para descartar cadenas predecibles."""
    if not data:
        return 0.0
    length = len(data)
    counts = {c: data.count(c) for c in set(data)}
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


@dataclass
class DLPLeak:
    """Representa una fuga de datos sensibles detectada por el motor DLP."""
    category: str
    leak_type: str
    masked_value: str
    location: str
    severity: str
    cwe_id: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DLPEngine:
    """Motor de inspección profunda de datos sensibles y cumplimiento PCI-DSS / HIPAA."""

    CARD_BRAND_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("Visa", re.compile(r"^4[0-9]{12}(?:[0-9]{3})?$")),
        ("Mastercard", re.compile(r"^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$")),
        ("American Express", re.compile(r"^3[47][0-9]{13}$")),
        ("Discover", re.compile(r"^6(?:011|5[0-9]{2})[0-9]{12}$")),
        ("Diners Club", re.compile(r"^3(?:0[0-5]|[68][0-9])[0-9]{11}$")),
        ("JCB", re.compile(r"^(?:2131|1800|35\d{3})\d{11}$")),
    ]

    # Expresiones regulares para secretos de nube y claves privadas
    SECRET_PATTERNS: dict[str, dict[str, Any]] = {
        "Clave Privada Criptográfica (PEM)": {
            "pattern": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
            "severity": "critical",
            "cwe": "CWE-312",
        },
        "Token de Slack (Bot/User)": {
            "pattern": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b"),
            "severity": "high",
            "cwe": "CWE-798",
        },
        "Clave Privada de Stripe Live": {
            "pattern": re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,34}\b"),
            "severity": "critical",
            "cwe": "CWE-798",
        },
        "Token de Acceso Personal GitHub": {
            "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b|\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
            "severity": "high",
            "cwe": "CWE-798",
        },
        "Clave de API de AWS (Access Key)": {
            "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "severity": "high",
            "cwe": "CWE-798",
        },
        "Clave de API de Google / Firebase": {
            "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            "severity": "medium",
            "cwe": "CWE-798",
        },
        "Cadena de Conexión de Base de Datos": {
            "pattern": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s'\"@]+:[^\s'\"@]+@[^\s'\"]+"),
            "severity": "critical",
            "cwe": "CWE-312",
        },
    }

    # SSN de EE.UU.: 3 dígitos - 2 dígitos - 4 dígitos con exclusiones estándar de la SSA
    SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b")

    # Candidatos a tarjeta de crédito: 13 a 19 dígitos separados por espacios o guiones
    CC_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    @classmethod
    def scan_text(cls, text: str, location_label: str = "Respuesta HTTP", target_url: str = "") -> list[DLPLeak]:
        """Analiza un texto o respuesta HTTP en busca de cualquier fuga de datos sensible."""
        leaks: list[DLPLeak] = []
        if not text:
            return leaks

        # 1. Detección de Tarjetas de Crédito con Algoritmo de Luhn
        for match in cls.CC_CANDIDATE_PATTERN.finditer(text):
            raw_val = match.group(0)
            digits_only = re.sub(r"\D", "", raw_val)
            if 13 <= len(digits_only) <= 19 and luhn_checksum(digits_only):
                brand = "Desconocida"
                for brand_name, brand_regex in cls.CARD_BRAND_PATTERNS:
                    if brand_regex.match(digits_only):
                        brand = brand_name
                        break
                masked = mask_credit_card(digits_only)
                leaks.append(DLPLeak(
                    category="credit_card",
                    leak_type=f"Tarjeta de Crédito ({brand})",
                    masked_value=masked,
                    location=location_label,
                    severity="critical",
                    cwe_id="CWE-359",
                    detail=f"Se detectó un número de tarjeta de crédito válido bajo el algoritmo de Luhn ({brand}: {masked}) en {location_label}.",
                ))

        # 2. Detección de Números de Seguro Social (SSN)
        for match in cls.SSN_PATTERN.finditer(text):
            masked_ssn = f"***-**-{match.group(3)}"
            leaks.append(DLPLeak(
                category="ssn",
                leak_type="Número de Seguro Social (SSN)",
                masked_value=masked_ssn,
                location=location_label,
                severity="high",
                cwe_id="CWE-359",
                detail=f"Se identificó un patrón de identificación personal (SSN: {masked_ssn}) expuesto en {location_label}.",
            ))

        # 3. Detección de Secretos de Nube y Claves Criptográficas
        for leak_name, config in cls.SECRET_PATTERNS.items():
            pattern = config["pattern"]
            matches = pattern.findall(text)
            for m in set(matches):
                if leak_name == "Clave de API de AWS":
                    body = m[4:]
                    if len(set(body)) <= 3 or shannon_entropy(body) < 2.5:
                        continue
                masked = mask_secret(m) if len(m) < 100 else "-----BEGIN PRIVATE KEY ... [TRUNCATED]-----"
                leaks.append(DLPLeak(
                    category="secret",
                    leak_type=leak_name,
                    masked_value=masked,
                    location=location_label,
                    severity=config["severity"],
                    cwe_id=config["cwe"],
                    detail=f"Exposición de credencial o secreto sensible '{leak_name}' ({masked}) en {location_label}.",
                ))

        return leaks

    @classmethod
    def scan_to_findings(cls, text: str, location_label: str = "Respuesta HTTP", target_url: str = "") -> list[Finding]:
        """Convierte las fugas DLP detectadas en objetos Finding tipados para el motor de auditoría."""
        leaks = cls.scan_text(text, location_label=location_label, target_url=target_url)
        findings: list[Finding] = []

        for leak in leaks:
            f = Finding(
                category="sensitive_data",
                title=f"Fuga DLP: {leak.leak_type}",
                severity=leak.severity,
                confidence="confirmed",
                description=leak.detail,
                affected_url=target_url or location_label,
                cwe_id=leak.cwe_id,
                remediation="Cifrar datos sensibles en reposo y en tránsito. Implementar filtros de Data Loss Prevention en el API Gateway y aplicar enmascaramiento de PII/tarjetas (PCI-DSS Requisito 3.4).",
                evidence=Evidence(
                    request_method="GET",
                    request_url=target_url or location_label,
                    response_fragment=f"DLP Match ({leak.leak_type}): {leak.masked_value}",
                ),
            )
            findings.append(f)

        return findings
