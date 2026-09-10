"""Unit tests for Software Bill of Materials (SBOM) Generator."""
import json
import os

from scanner.sbom import SBOMGenerator


def test_sbom_collect_components() -> None:
    gen = SBOMGenerator()
    components = gen.collect_components()
    assert len(components) >= 1

    names = {c.name for c in components}
    assert "omnibreach" in names

    # Check omnibreach properties
    ob = next(c for c in components if c.name == "omnibreach")
    assert ob.version == "3.0.0"
    assert ob.type == "application"
    assert "NovaSec" in ob.supplier

def test_sbom_cyclonedx_generation() -> None:
    gen = SBOMGenerator()
    cdx = gen.generate_cyclonedx()

    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert "serialNumber" in cdx
    assert "metadata" in cdx
    assert cdx["metadata"]["component"]["name"] == "OmniBreach"
    assert len(cdx["components"]) >= 1

def test_sbom_spdx_generation() -> None:
    gen = SBOMGenerator()
    spdx = gen.generate_spdx()

    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert "SPDXID" in spdx
    assert len(spdx["packages"]) >= 1
    assert any("omnibreach" in p["name"] for p in spdx["packages"])

def test_sbom_export_file(tmp_path) -> None:
    gen = SBOMGenerator()
    out_file = str(tmp_path / "test_sbom.json")
    saved = gen.export_to_file(out_file, format_type="cyclonedx")

    assert os.path.exists(saved)
    with open(saved, encoding="utf-8") as f:
        data = json.load(f)
    assert data["bomFormat"] == "CycloneDX"
