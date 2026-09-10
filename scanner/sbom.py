"""
Generador de Software Bill of Materials (SBOM) para OmniBreach.
Soporta los estándares CycloneDX v1.5 JSON y SPDX v2.3 JSON para cumplir
con directivas de Supply Chain Security (EU CRA y US EO 14028).
"""
from __future__ import annotations

import importlib.metadata
import json
import logging
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("OmniBreach.SBOM")


@dataclass
class SBOMComponent:
    """Componente de software en el inventario SBOM."""
    name: str
    version: str
    purl: str
    type: str = "library"
    description: str = ""
    license: str = "NOASSERTION"
    supplier: str = "OpenSource"
    hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SBOMGenerator:
    """Generador de SBOM multi-formato a partir de dependencias instaladas y archivos de manifiesto."""

    def __init__(self, project_root: str | None = None) -> None:
        self.project_root = project_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def collect_components(self) -> list[SBOMComponent]:
        """Recolecta componentes desde el entorno activo y manifiestos del proyecto."""
        components_map: dict[str, SBOMComponent] = {}

        # 1. Leer paquetes declarados en requirements.txt si existe
        req_path = os.path.join(self.project_root, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, encoding="utf-8") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Extraer nombre del paquete
                        match = re.match(r"^([a-zA-Z0-9_\-]+)", line)
                        if match:
                            pkg_name = match.group(1).lower()
                            purl = f"pkg:pypi/{pkg_name}"
                            components_map[pkg_name] = SBOMComponent(
                                name=pkg_name,
                                version="unknown",
                                purl=purl,
                                description="Dependencia de producción declarada en requirements.txt",
                            )
            except OSError as err:
                logger.debug("No se pudo leer requirements.txt: %s", err)

        # 2. Enriquecer con metadatos reales desde importlib.metadata
        for dist in importlib.metadata.distributions():
            try:
                name = dist.metadata["Name"] or ""
                norm_name = name.lower()
                version = dist.version or "0.0.0"
                summary = str(dist.metadata["Summary"] or "")
                license_val = str(dist.metadata["License"]) if "License" in dist.metadata else "NOASSERTION"
                author = str(dist.metadata["Author"]) if "Author" in dist.metadata else "Community"

                purl = f"pkg:pypi/{norm_name}@{version}"

                # Si el componente ya estaba en el mapa o pertenece al stack core
                components_map[norm_name] = SBOMComponent(
                    name=norm_name,
                    version=version,
                    purl=purl,
                    description=summary,
                    license=license_val if len(license_val) < 60 else "Custom",
                    supplier=author,
                )
            except Exception as err:
                logger.debug("Error leyendo metadatos de distribucion: %s", err)

        # 3. Componente principal: OmniBreach Core
        components_map["omnibreach"] = SBOMComponent(
            name="omnibreach",
            version="3.0.0",
            purl="pkg:generic/omnibreach@3.0.0",
            type="application",
            description="Plataforma de Ciberdefensa EASM + DAST + SAST + IAST/RASP",
            license="MIT",
            supplier="NovaSec CyberDefense",
        )

        return sorted(components_map.values(), key=lambda c: c.name)

    def generate_cyclonedx(self, serial_number: str | None = None) -> dict[str, Any]:
        """Genera un documento SBOM conforme al estándar CycloneDX v1.5 JSON."""
        components = self.collect_components()
        bom_serial = serial_number or f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        cdx_components: list[dict[str, Any]] = []
        for c in components:
            if c.name == "omnibreach":
                continue
            item: dict[str, Any] = {
                "type": c.type,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "description": c.description,
            }
            if c.license and c.license != "NOASSERTION":
                item["licenses"] = [{"license": {"name": c.license}}]
            cdx_components.append(item)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": bom_serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "NovaSec",
                        "name": "OmniBreach SBOM Generator",
                        "version": "3.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "OmniBreach",
                    "version": "3.0.0",
                    "description": "Enterprise External Attack Surface Management & Threat Defense",
                    "purl": "pkg:generic/omnibreach@3.0.0",
                },
            },
            "components": cdx_components,
        }

    def generate_spdx(self) -> dict[str, Any]:
        """Genera un documento SBOM conforme al estándar SPDX v2.3 JSON."""
        components = self.collect_components()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"

        spdx_packages: list[dict[str, Any]] = []
        for idx, c in enumerate(components):
            spdx_packages.append({
                "SPDXID": f"SPDXRef-Package-{idx}-{c.name}",
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": c.license if c.license != "NOASSERTION" else "NOASSERTION",
                "licenseDeclared": c.license if c.license != "NOASSERTION" else "NOASSERTION",
                "description": c.description,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }
                ],
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": "OmniBreach Software Bill of Materials",
            "documentNamespace": f"https://spdx.org/spdxdocs/omnibreach-v3.0-{uuid.uuid4().hex[:8]}",
            "creationInfo": {
                "created": timestamp,
                "creators": ["Tool: OmniBreach-SBOMGenerator-3.0", "Organization: NovaSec"],
            },
            "packages": spdx_packages,
        }

    def export_to_file(self, output_path: str, format_type: str = "cyclonedx") -> str:
        """Exporta el SBOM generado a un archivo JSON."""
        if format_type.lower() == "spdx":
            data = self.generate_spdx()
        else:
            data = self.generate_cyclonedx()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info("SBOM (%s) exportado a: %s", format_type, output_path)
        return output_path
