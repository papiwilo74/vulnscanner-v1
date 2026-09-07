import datetime
import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

import requests


def check_ssl(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    """
    Analiza la configuración de SSL/TLS de un sitio web.
    Verifica si HTTPS está habilitado, la validez del certificado, y si soporta versiones antiguas/inseguras de TLS.

    Args:
        url: La URL del sitio web.
        session: Instancia opcional de requests.Session (para compatibilidad de firma).

    Returns:
        Una lista de diccionarios con vulnerabilidades detectadas.
    """
    results: list[dict[str, str]] = []
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        return results

    # Si no usa HTTPS, es un hallazgo crítico inmediato
    if parsed_url.scheme.lower() != 'https':
        results.append({
            "vuln": "SSL/TLS No Habilitado (HTTP Claro)",
            "risk": "Alto",
            "detail": "El sitio web utiliza HTTP sin cifrar. Todo el tráfico, incluidas contraseñas y datos sensibles, se transmite en texto plano."
        })
        return results

    # Si es HTTPS, analizar el certificado
    port = parsed_url.port if parsed_url.port else 443
    context = ssl.create_default_context()

    # 1. Comprobar validez general y autofirmado/expirado
    cert_valid = True
    cert_info = None

    try:
        with socket.create_connection((hostname, port), timeout=6) as sock, \
             context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_info = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        cert_valid = False
        results.append({
            "vuln": "Certificado SSL/TLS Inválido o Autofirmado",
            "risk": "Alto",
            "detail": f"No se pudo verificar la cadena de confianza del certificado para {hostname}. Error: {e.reason or e}"
        })
    except (OSError, ssl.SSLError):
        cert_valid = False
        return results

    # Si el certificado es válido ante la CA local, inspeccionamos las fechas de expiración
    if cert_valid and cert_info:
        try:
            not_after_val = cert_info.get('notAfter')
            if isinstance(not_after_val, str):
                not_after = datetime.datetime.strptime(not_after_val, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (not_after - datetime.datetime.utcnow()).days

                if days_remaining < 0:
                    results.append({
                        "vuln": "Certificado SSL/TLS Expirado",
                        "risk": "Alto",
                        "detail": f"El certificado SSL/TLS para {hostname} expiró el {not_after}."
                    })
                elif days_remaining < 15:
                    results.append({
                        "vuln": "Certificado SSL/TLS Próximo a Expirar",
                        "risk": "Bajo",
                        "detail": f"El certificado SSL/TLS expirará pronto (en {days_remaining} días, el {not_after})."
                    })
        except (ValueError, KeyError):
            pass

    # 2. Comprobar soporte a protocolos antiguos/inseguros (TLS 1.0 y TLS 1.1)
    # Intentamos crear contextos que usen explícitamente TLSv1 o TLSv1_1 si el sistema los permite
    for tls_proto, name in [("TLSv1", "TLS 1.0"), ("TLSv1_1", "TLS 1.1")]:
        try:
            # Crear un contexto restrictivo para esa versión
            test_context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{tls_proto}"))
            test_context.check_hostname = False
            test_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=4) as sock, \
                 test_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results.append({
                    "vuln": f"Soporte para Protocolo Obsoleto ({name})",
                    "risk": "Medio",
                    "detail": f"El servidor acepta conexiones negociadas con {name}, el cual es obsoleto y vulnerable a ataques como BEAST y POODLE."
                })
        except (OSError, AttributeError, ssl.SSLError):
            # Si el sistema actual no soporta PROTOCOL_TLSv1/PROTOCOL_TLSv1_1 o la conexión falla, asumimos que no se aceptó
            pass

    return results
