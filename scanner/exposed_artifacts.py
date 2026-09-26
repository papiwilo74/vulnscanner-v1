"""
Motor de Auditoría de Artefactos de Nube y Repositorios Expuestos (.git, Cloud Buckets y Dumps).
Implementa análisis para:
1. Detección y verificación de repositorios Git expuestos (/.git/HEAD y /.git/config).
2. Detección de Buckets de Nube (AWS S3, Google Cloud Storage, Azure Blob) y verificación de listado anónimo.
3. Descubrimiento y validación de volcados de bases de datos olvidados (.sql, .sql.gz, .dump).
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlparse

import requests

from scanner.models import Evidence, Finding

logger = logging.getLogger("OmniBreach.ExposedArtifacts")

# Expresiones regulares para descubrir buckets de nube en el código fuente
CLOUD_BUCKET_PATTERNS: dict[str, str] = {
    "aws_s3_vhost": r"https?://([a-z0-9.\-_]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com",
    "aws_s3_path": r"https?://s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9.\-_]+)",
    "gcp_storage": r"https?://storage\.googleapis\.com/([a-z0-9.\-_]+)",
    "azure_blob": r"https?://([a-z0-9]+)\.blob\.core\.windows\.net/([a-z0-9.\-_]+)",
}

# Firmas de inicio de volcados de bases de datos para descartar páginas 404 que devuelven 200
DATABASE_DUMP_SIGNATURES: list[tuple[str, str]] = [
    (r"-- (?:MySQL dump|PostgreSQL database dump|SQLite)", "SQL Plaintext Dump Header"),
    (r"CREATE TABLE [`\"']?[a-zA-Z0-9_]+[`\"']?", "SQL DDL Table Creation Statement"),
    (r"INSERT INTO [`\"']?[a-zA-Z0-9_]+[`\"']? VALUES", "SQL Data Population Insert"),
]


def check_exposed_git(
    base_url: str,
    session: requests.Session | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Verifica si el directorio de control de versiones `/.git/` está expuesto públicamente.
    Comprueba `/.git/HEAD` y valida la firma `ref: refs/heads/` para evitar falsos positivos con SPAs.
    """
    client = session or requests.Session()
    head_url = urljoin(base_url, "/.git/HEAD")

    try:
        r_head = client.get(head_url, timeout=timeout)
        if r_head.status_code == 200 and r_head.text:
            text = r_head.text.strip()
            # Un archivo .git/HEAD genuino contiene "ref: refs/heads/<rama>" o un hash SHA-1 de 40 hexadecimales
            is_valid_head = text.startswith("ref: refs/heads/") or bool(re.match(r"^[0-9a-fA-F]{40}$", text))

            if is_valid_head and "<html" not in text.lower():
                # Intentar leer /.git/config para extraer evidencia adicional (ej. URL del repositorio remoto)
                config_url = urljoin(base_url, "/.git/config")
                remote_info = ""
                try:
                    r_conf = client.get(config_url, timeout=timeout)
                    if r_conf.status_code == 200 and "[core]" in r_conf.text:
                        match_remote = re.search(r"url\s*=\s*(.+)", r_conf.text)
                        if match_remote:
                            remote_info = f" Repositorio remoto identificado: '{match_remote.group(1).strip()}'."
                except Exception:
                    pass

                return Finding(
                    category="sensitive_data",
                    title="Repositorio Git Expuesto Públicamente (/.git/HEAD)",
                    severity="critical",
                    confidence="confirmed",
                    description=(
                        f"El directorio de control de versiones Git está expuesto públicamente en '{head_url}'. "
                        f"Un atacante puede reconstruir el código fuente completo, historial de commits y credenciales "
                        f"embebidas mediante herramientas de volcado de objetos Git.{remote_info}"
                    ),
                    affected_url=head_url,
                    evidence=Evidence(
                        request_method="GET",
                        request_url=head_url,
                        response_status=200,
                        response_fragment=text[:200],
                    ),
                    remediation=(
                        "Bloquear inmediatamente el acceso a carpetas ocultas que comiencen con punto (/\\..*) "
                        "en el servidor web (Nginx: 'location ~ /\\.git { deny all; }', Apache: 'RedirectMatch 404 /\\.git')."
                    ),
                )
    except Exception as exc:
        logger.debug("[ExposedArtifacts] Error verificando .git en %s: %s", head_url, exc)

    return None


def check_cloud_storage_leak(
    html_or_js: str,
    base_url: str = "",
    session: requests.Session | None = None,
    timeout: float = 5.0,
) -> list[Finding]:
    """
    Descubre referencias a buckets de nube (AWS S3, GCP, Azure Blob) en el código fuente
    y evalúa si permiten listado anónimo público.
    """
    client = session or requests.Session()
    findings: list[Finding] = []
    discovered_buckets: set[tuple[str, str]] = set()

    for provider, pattern in CLOUD_BUCKET_PATTERNS.items():
        matches = re.findall(pattern, html_or_js, re.IGNORECASE)
        for m in matches:
            bucket_name = str(m[0] if isinstance(m, tuple) else m)
            if bucket_name:
                discovered_buckets.add((provider, bucket_name))

    for provider, bucket in discovered_buckets:
        probe_url = ""
        if "aws" in provider:
            probe_url = f"https://{bucket}.s3.amazonaws.com/?max-keys=1"
        elif "gcp" in provider:
            probe_url = f"https://storage.googleapis.com/{bucket}"
        elif "azure" in provider:
            probe_url = f"https://{bucket}.blob.core.windows.net/?comp=list&maxresults=1"

        if not probe_url:
            continue

        try:
            r = client.get(probe_url, timeout=timeout)
            # Detección de listado público anónimo en AWS S3
            if r.status_code == 200 and ("<ListBucketResult" in r.text or "<EnumerationResults" in r.text):
                findings.append(
                    Finding(
                        category="cloud_misconfiguration",
                        title=f"Bucket de Nube con Listado Público Anónimo ({bucket})",
                        severity="high",
                        confidence="confirmed",
                        description=(
                            f"Se detectó un bucket de nube ({provider}) en el código fuente con permisos de "
                            f"listado público anónimo en '{probe_url}'. Cualquier visitante puede enumerar y descargar "
                            f"todos los objetos almacenados."
                        ),
                        affected_url=probe_url,
                        evidence=Evidence(
                            request_method="GET",
                            request_url=probe_url,
                            response_status=r.status_code,
                            response_fragment=r.text[:300],
                        ),
                        remediation=(
                            "Habilitar 'Block Public Access' (S3) o restringir permisos IAM retirando la política "
                            "'allUsers' / 'allAuthenticatedUsers' para lectura de objetos y listas."
                        ),
                    )
                )
        except Exception as exc:
            logger.debug("[CloudLeak] Error al consultar bucket %s: %s", probe_url, exc)

    return findings


def check_database_backup_exposure(
    base_url: str,
    session: requests.Session | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Busca heurísticamente volcados o copias de seguridad de bases de datos olvidadas en el servidor web.
    """
    client = session or requests.Session()
    domain = urlparse(base_url).netloc.split(":")[0].replace("www.", "")
    domain_clean = domain.split(".")[0]

    candidate_files: list[str] = [
        f"/{domain_clean}.sql",
        f"/backup_{domain_clean}.sql",
        "/dump.sql",
        "/backup.sql",
        "/database.sql",
        "/db_backup.sql",
    ]

    for c_file in candidate_files:
        test_url = urljoin(base_url, c_file)
        try:
            # Leer únicamente los primeros 1024 bytes con stream=True para no descargar archivos pesados
            with client.get(test_url, timeout=timeout, stream=True) as resp:
                if resp.status_code == 200:
                    chunk = resp.raw.read(1024)
                    chunk_text = chunk.decode("utf-8", errors="ignore")

                    # Validar si contiene firma real de base de datos y no una página HTML 404
                    if "<!doctype html" not in chunk_text.lower() and "<html" not in chunk_text.lower():
                        for sig, sig_label in DATABASE_DUMP_SIGNATURES:
                            if re.search(sig, chunk_text, re.IGNORECASE):
                                return Finding(
                                    category="sensitive_data",
                                    title=f"Respaldo de Base de Datos Expuesto Públicamente ({c_file})",
                                    severity="critical",
                                    confidence="confirmed",
                                    description=(
                                        f"Se descubrió un archivo de volcado de base de datos ({sig_label}) accesible "
                                        f"públicamente en '{test_url}'. Contiene la estructura y potencialmente datos "
                                        f"confidenciales de la aplicación."
                                    ),
                                    affected_url=test_url,
                                    evidence=Evidence(
                                        request_method="GET",
                                        request_url=test_url,
                                        response_status=200,
                                        response_fragment=chunk_text[:300],
                                    ),
                                    remediation=(
                                        "Eliminar de inmediato los respaldos de la raíz pública del servidor web y "
                                        "almacenar las copias de seguridad en un almacenamiento seguro con cifrado y control de acceso."
                                    ),
                                )
        except Exception as exc:
            logger.debug("[ExposedArtifacts] Error buscando dump %s: %s", test_url, exc)

    return None
