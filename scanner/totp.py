"""
Motor de Generación y Validación de Códigos TOTP / HOTP (RFC 6238 / RFC 4226).

Permite a OmniBreach calcular en tiempo real contraseñas de un solo uso basadas
en tiempo (TOTP) para flujos de autenticación de dos factores (2FA/MFA)
durante auditorías DAST automatizadas, sin dependencias externas obligatorias.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def clean_base32_secret(secret: str) -> bytes:
    """
    Normaliza y decodifica un secreto Base32 según la RFC 4648.
    Elimina espacios en blanco, guiones, convierte a mayúsculas
    y agrega el relleno '=' necesario si falta.
    """
    if not secret:
        raise ValueError("El secreto Base32 no puede estar vacío.")

    # Remover espacios, guiones y convertir a mayúsculas
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()

    # Calcular relleno '=' necesario para longitud múltiplo de 8
    missing_padding = len(cleaned) % 8
    if missing_padding != 0:
        cleaned += "=" * (8 - missing_padding)

    try:
        return base64.b32decode(cleaned, casefold=True)
    except Exception as exc:
        raise ValueError(f"Secreto Base32 inválido o malformado: {exc}") from exc


def generate_hotp(key: bytes, counter: int, digits: int = 6) -> str:
    """
    Genera un valor HOTP según RFC 4226 a partir de una clave y un contador numérico.
    """
    if digits < 6 or digits > 8:
        raise ValueError("El número de dígitos debe ser entre 6 y 8.")

    # Empaquetar contador en formato big-endian entero de 8 bytes (RFC 4226 §5.1)
    msg = struct.pack(">Q", counter)

    # Calcular HMAC-SHA1
    mac = hmac.new(key, msg, hashlib.sha1).digest()

    # Truncamiento dinámico (Dynamic Truncation - RFC 4226 §5.3)
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF

    # Módulo para el número de dígitos solicitado y relleno con ceros a la izquierda
    token = code_int % (10 ** digits)
    return str(token).zfill(digits)


def generate_totp(
    secret: str,
    digits: int = 6,
    interval: int = 30,
    for_time: float | None = None,
) -> str:
    """
    Calcula el código TOTP según RFC 6238 en una marca de tiempo dada (por defecto time.time()).

    :param secret: Clave secreta codificada en Base32 (ej. 'JBSWY3DPEHPK3PXP').
    :param digits: Cantidad de dígitos del código (habitualmente 6 u 8).
    :param interval: Intervalo de validez en segundos (habitualmente 30 segundos).
    :param for_time: Timestamp UNIX en segundos para el cual calcular el token.
    :return: Cadena con el código numérico de 6 dígitos.
    """
    key_bytes = clean_base32_secret(secret)
    current_time = time.time() if for_time is None else for_time
    counter = int(current_time // interval)
    return generate_hotp(key_bytes, counter, digits=digits)


def verify_totp(
    code: str,
    secret: str,
    window: int = 1,
    digits: int = 6,
    interval: int = 30,
    for_time: float | None = None,
) -> bool:
    """
    Verifica si un código proporcionado coincide con el token esperado,
    permitiendo una ventana de tolerancia hacia adelante o atrás para compensar desincronización de reloj.

    :param code: Código de 6 u 8 dígitos recibido a validar.
    :param secret: Clave secreta Base32.
    :param window: Número de intervalos de 30s de tolerancia (1 = [-30s, 0s, +30s]).
    :param digits: Cantidad de dígitos esperados.
    :param interval: Duración del intervalo en segundos.
    :param for_time: Marca de tiempo para la comprobación.
    :return: True si el código es válido dentro de la ventana de tolerancia.
    """
    clean_code = str(code).strip()
    if not clean_code.isdigit() or len(clean_code) != digits:
        return False

    current_time = time.time() if for_time is None else for_time
    base_counter = int(current_time // interval)

    try:
        key_bytes = clean_base32_secret(secret)
    except ValueError:
        return False

    # Evaluar la ventana [-window, +window]
    for drift in range(-window, window + 1):
        expected_code = generate_hotp(key_bytes, base_counter + drift, digits=digits)
        if hmac.compare_digest(clean_code, expected_code):
            return True

    return False
