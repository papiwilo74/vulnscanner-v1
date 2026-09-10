"""
Módulo de Seguridad de Contenedores y Análisis Estático de Dockerfiles (Container Security).
Detecta malas prácticas de configuración, escalamiento de privilegios (root execution),
secretos embebidos en capas, puertos inseguros y directivas riesgosas en contenedores OCI/Docker.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.ContainerSecurity")

DOCKERFILE_RULES: list[dict[str, Any]] = [
    {
        "id": "CONT-001",
        "title": "Contenedor ejecutándose como usuario Root sin restricción",
        "severity": "high",
        "category": "container_security",
        "description": "El Dockerfile no define una directiva USER no privilegiada, provocando que los procesos corran como root en el host.",
        "cwe_id": "CWE-250",
        "mitre_id": "T1611",
        "remediation": "Crear un usuario de sistema no privilegiado y añadir 'USER appuser' antes del ENTRYPOINT/CMD.",
    },
    {
        "id": "CONT-002",
        "title": "Uso de etiqueta mutable ':latest' en imagen base",
        "severity": "medium",
        "category": "container_security",
        "description": "El uso de 'FROM ...:latest' introduce indeterminismo en los builds y expone la aplicación a roturas o vulnerabilidades no testeadas.",
        "cwe_id": "CWE-1104",
        "mitre_id": "T1195.002",
        "remediation": "Fijar una versión semántica o digest SHA256 inmutable (ej. 'python:3.11-slim-bookworm' o 'python@sha256:...').",
    },
    {
        "id": "CONT-003",
        "title": "Exposición de puertos de administración remota inseguros",
        "severity": "critical",
        "category": "container_security",
        "description": "Se detectó la directiva EXPOSE para puertos de acceso remoto como SSH (22), Telnet (23) o RDP (3389).",
        "cwe_id": "CWE-284",
        "mitre_id": "T1021",
        "remediation": "Eliminar la exposición de puertos de administración dentro de la imagen del contenedor. Usar orquestadores (k8s/docker exec) para tareas operativas.",
    },
    {
        "id": "CONT-004",
        "title": "Credenciales o claves secretas embebidas en variables de entorno (ENV)",
        "severity": "critical",
        "category": "container_security",
        "description": "Directiva ENV contiene contraseñas, tokens o claves de API que quedan persistidas en el historial de capas de la imagen.",
        "cwe_id": "CWE-798",
        "mitre_id": "T1552.001",
        "remediation": "No utilizar directivas ENV para secretos. Inyectar secretos en runtime mediante variables de entorno del host o Docker Secrets.",
    },
    {
        "id": "CONT-005",
        "title": "Uso de comando ADD en lugar de COPY",
        "severity": "low",
        "category": "container_security",
        "description": "La instrucción ADD tiene comportamientos implícitos (extracción de tarballs, descarga remota de URLs) que pueden introducir malware.",
        "cwe_id": "CWE-73",
        "mitre_id": "T1204",
        "remediation": "Reemplazar 'ADD' por 'COPY' a menos que se requiera deliberadamente la auto-extracción de un archivo tar local.",
    },
    {
        "id": "CONT-006",
        "title": "Instalación de paquetes sin limpiar la caché de apt/yum",
        "severity": "low",
        "category": "container_security",
        "description": "Comandos 'apt-get update' o 'apt-get install' sin eliminar '/var/lib/apt/lists/*' aumentan la superficie de ataque y el tamaño de la imagen.",
        "cwe_id": "CWE-1104",
        "mitre_id": "T1059",
        "remediation": "Encadenar '&& rm -rf /var/lib/apt/lists/*' en la misma capa RUN para reducir el tamaño y eliminar artefactos temporales.",
    },
    {
        "id": "CONT-007",
        "title": "Ausencia de directiva HEALTHCHECK",
        "severity": "medium",
        "category": "container_security",
        "description": "El contenedor carece de mecanismo de verificación de salud activa para que el orquestador detecte bloqueos o denegación de servicio.",
        "cwe_id": "CWE-693",
        "mitre_id": "T1499",
        "remediation": "Añadir 'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1'.",
    },
]


@dataclass
class ContainerScanFinding:
    """Hallazgo de seguridad detectado en el contenedor o Dockerfile."""
    rule_id: str
    title: str
    severity: str
    line_number: int
    line_content: str
    description: str
    remediation: str
    cwe_id: str = "CWE-284"
    mitre_id: str = "T1611"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_finding(self, file_path: str = "Dockerfile") -> Finding:
        return Finding(
            category="container_security",
            title=self.title,
            severity=self.severity,
            description=f"[{self.rule_id}] Línea {self.line_number}: {self.description}",
            affected_url=f"file://{file_path}#L{self.line_number}",
            parameter=self.line_content[:60],
            cwe_id=self.cwe_id,
            mitre_attack_id=self.mitre_id,
            remediation=self.remediation,
        )


class DockerfileScanner:
    """Escáner estático de seguridad para Dockerfiles y manifiestos de contenedores."""

    def scan_content(self, content: str, file_path: str = "Dockerfile") -> list[ContainerScanFinding]:
        """Analiza el contenido textual de un Dockerfile."""
        findings: list[ContainerScanFinding] = []
        if not content.strip():
            return findings

        lines = content.splitlines()
        has_user_directive = False
        has_healthcheck_directive = False

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            upper_line = clean_line.upper()

            # 1. Chequeo de USER
            if upper_line.startswith("USER "):
                user_val = clean_line[5:].strip().lower()
                if user_val in ("root", "0"):
                    findings.append(ContainerScanFinding(
                        rule_id="CONT-001",
                        title="Contenedor configurado explícitamente para correr como Root",
                        severity="high",
                        line_number=idx,
                        line_content=clean_line,
                        description="Se detectó directiva 'USER root', anulando las protecciones de contención de privilegios.",
                        remediation="Usar un usuario no root como 'USER 10001' o 'USER appuser'.",
                        cwe_id="CWE-250",
                        mitre_id="T1611",
                    ))
                else:
                    has_user_directive = True

            # 2. Chequeo de HEALTHCHECK
            if upper_line.startswith("HEALTHCHECK "):
                has_healthcheck_directive = True

            # 3. Chequeo de :latest en imágenes base
            if upper_line.startswith("FROM ") and (":latest" in clean_line.lower() or (":" not in clean_line.split()[1] and "@" not in clean_line)):
                    findings.append(ContainerScanFinding(
                        rule_id="CONT-002",
                        title=DOCKERFILE_RULES[1]["title"],
                        severity=DOCKERFILE_RULES[1]["severity"],
                        line_number=idx,
                        line_content=clean_line,
                        description=DOCKERFILE_RULES[1]["description"],
                        remediation=DOCKERFILE_RULES[1]["remediation"],
                        cwe_id=DOCKERFILE_RULES[1]["cwe_id"],
                        mitre_id=DOCKERFILE_RULES[1]["mitre_id"],
                    ))

            # 4. Chequeo de EXPOSE de puertos peligrosos
            if upper_line.startswith("EXPOSE "):
                exposed_ports = re.findall(r"\d+", clean_line)
                insecure_ports = {"22", "23", "3389", "5900"}
                for p in exposed_ports:
                    if p in insecure_ports:
                        findings.append(ContainerScanFinding(
                            rule_id="CONT-003",
                            title=f"Exposición de puerto de administración remota inseguro ({p})",
                            severity="critical",
                            line_number=idx,
                            line_content=clean_line,
                            description=f"El puerto {p} no debe exponerse públicamente en contenedores de aplicación.",
                            remediation="Remover directiva EXPOSE para este puerto.",
                            cwe_id="CWE-284",
                            mitre_id="T1021",
                        ))

            # 5. Chequeo de ENV con secretos sospechosos
            if upper_line.startswith("ENV "):
                secret_patterns = [
                    r"(?:PASSWORD|SECRET|TOKEN|API_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)\s*=",
                    r"AKIA[0-9A-Z]{16}",
                ]
                for sp in secret_patterns:
                    if re.search(sp, clean_line, re.IGNORECASE):
                        findings.append(ContainerScanFinding(
                            rule_id="CONT-004",
                            title=DOCKERFILE_RULES[3]["title"],
                            severity="critical",
                            line_number=idx,
                            line_content=clean_line,
                            description=DOCKERFILE_RULES[3]["description"],
                            remediation=DOCKERFILE_RULES[3]["remediation"],
                            cwe_id=DOCKERFILE_RULES[3]["cwe_id"],
                            mitre_id=DOCKERFILE_RULES[3]["mitre_id"],
                        ))
                        break

            # 6. Chequeo de comando ADD
            if upper_line.startswith("ADD ") and not clean_line.endswith(".tar.gz") and not clean_line.endswith(".tar"):
                findings.append(ContainerScanFinding(
                    rule_id="CONT-005",
                    title=DOCKERFILE_RULES[4]["title"],
                    severity="low",
                    line_number=idx,
                    line_content=clean_line,
                    description=DOCKERFILE_RULES[4]["description"],
                    remediation=DOCKERFILE_RULES[4]["remediation"],
                    cwe_id=DOCKERFILE_RULES[4]["cwe_id"],
                    mitre_id=DOCKERFILE_RULES[4]["mitre_id"],
                ))

            # 7. Chequeo de apt-get sin limpiar caché
            if "apt-get install" in clean_line and "/var/lib/apt/lists" not in clean_line:
                findings.append(ContainerScanFinding(
                    rule_id="CONT-006",
                    title=DOCKERFILE_RULES[5]["title"],
                    severity="low",
                    line_number=idx,
                    line_content=clean_line,
                    description=DOCKERFILE_RULES[5]["description"],
                    remediation=DOCKERFILE_RULES[5]["remediation"],
                    cwe_id=DOCKERFILE_RULES[5]["cwe_id"],
                    mitre_id=DOCKERFILE_RULES[5]["mitre_id"],
                ))

        # Al finalizar, validar si nunca se definió USER no privilegiado
        if not has_user_directive:
            findings.append(ContainerScanFinding(
                rule_id="CONT-001",
                title=DOCKERFILE_RULES[0]["title"],
                severity=DOCKERFILE_RULES[0]["severity"],
                line_number=len(lines),
                line_content="[Fin de archivo]",
                description=DOCKERFILE_RULES[0]["description"],
                remediation=DOCKERFILE_RULES[0]["remediation"],
                cwe_id=DOCKERFILE_RULES[0]["cwe_id"],
                mitre_id=DOCKERFILE_RULES[0]["mitre_id"],
            ))

        # Validar si falta HEALTHCHECK
        if not has_healthcheck_directive:
            findings.append(ContainerScanFinding(
                rule_id="CONT-007",
                title=DOCKERFILE_RULES[6]["title"],
                severity="medium",
                line_number=1,
                line_content="[Configuración Global]",
                description=DOCKERFILE_RULES[6]["description"],
                remediation=DOCKERFILE_RULES[6]["remediation"],
                cwe_id=DOCKERFILE_RULES[6]["cwe_id"],
                mitre_id=DOCKERFILE_RULES[6]["mitre_id"],
            ))

        return findings

    def scan_file(self, file_path: str) -> list[ContainerScanFinding]:
        """Lee y analiza un archivo Dockerfile desde el sistema de archivos."""
        if not os.path.exists(file_path):
            logger.warning("Archivo Dockerfile no encontrado: %s", file_path)
            return []
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            return self.scan_content(content, file_path=file_path)
        except OSError as err:
            logger.error("Error al leer Dockerfile %s: %s", file_path, err)
            return []
