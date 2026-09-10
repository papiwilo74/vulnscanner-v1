# Política de Gestión de Vulnerabilidades y CVEs (VulnScanner Enterprise)

Esta política documenta los mecanismos, estándares y herramientas utilizadas por **VulnScanner** para la prevención, detección, seguimiento y mitigación de vulnerabilidades conocidas (CVEs) en su cadena de suministro de software (Software Supply Chain Security).

---

## 1. Alcance de la Auditoría de Dependencias

Para garantizar reproducibilidad e independencia del entorno del host, el análisis de vulnerabilidades de VulnScanner se delimita estrictamente al árbol de dependencias declarado del proyecto:

1. **Dependencias Base y de Ejecución:** Definidas en [`requirements.txt`](../requirements.txt) y [`pyproject.toml`](../pyproject.toml).
   - Servidor Web y API: `fastapi`, `uvicorn`
   - Cliente HTTP y Transporte: `requests`, `urllib3`, `httpx`
   - Inteligencia Artificial y ML: `scikit-learn`, `joblib`
   - Reportes y Testing: `reportlab`, `responses`
   - Stubs de Tipado Estricto: `types-requests`, `types-urllib3`, `types-colorama`
2. **Herramienta Oficial de Verificación (SCA):**
   ```bash
   pip-audit -r requirements.txt
   ```
   *Estado actual:* **0 vulnerabilidades conocidas (No known vulnerabilities found)**.

> [!NOTE]
> Paquetes ajenos al proyecto instalados en el entorno global del sistema (tales como `torch`, `streamlit`, `litellm`, etc.) no forman parte de VulnScanner y deben gestionarse mediante entornos virtuales aislados (`venv`).

---

## 2. Niveles de Severidad y Acuerdos de Nivel de Servicio (SLA)

| Severidad CVSS v3 | Puntaje | Plazo Máximo de Remediación (SLA) | Acción Requerida |
|---|---|---|---|
| **Crítica** | 9.0 – 10.0 | **< 24 horas** | Actualización inmediata, hotfix y re-emisión de versión menor |
| **Alta** | 7.0 – 8.9 | **< 72 horas** | Evaluación de impacto, actualización de versión y pruebas de no-regresión |
| **Media** | 4.0 – 6.9 | **< 7 días** | Inclusión en el siguiente ciclo semanal de Dependabot |
| **Baja** | 0.1 – 3.9 | **< 30 días** | Mantenimiento periódico |

---

## 3. Automatización en el Pipeline CI/CD

El pipeline oficial de GitHub Actions ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) ejecuta verificaciones de seguridad en cada commit y Pull Request:

1. **SAST (Static Application Security Testing):**
   - Herramienta: `bandit -c bandit.yaml -r scanner api.py main.py`
   - Criterio de rechazo: Bloqueo del build ante cualquier hallazgo High o Medium.
2. **SCA (Software Composition Analysis):**
   - Herramienta: `pip-audit -r requirements.txt`
   - Criterio de rechazo: Bloqueo del build si existe un CVE conocido reportado en PyPI Advisory Database / OSV.
3. **Dependabot Automatizado:**
   - Archivo: [`.github/dependabot.yml`](../.github/dependabot.yml)
   - Frecuencia: Semanal (Lunes a las 06:00 UTC).
   - Genera Pull Requests automáticos con análisis de compatibilidad semántica.

---

## 4. Reporte Responsable de Vulnerabilidades

Para reportar problemas de seguridad en VulnScanner, por favor contactar al equipo de seguridad directamente a través de GitHub Security Advisories o al correo indicado en la documentación del repositorio.
