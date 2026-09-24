"""OmniBreach Enterprise — Copiloto de Seguridad Ofensiva y Remediación (AI Security Copilot).

Provee un motor de inteligencia híbrido (Groq Cloud ultrarrápido + Ollama local en RTX 4060)
con cinco modos operativos:
1. Triage y Explicación Contextual de Vulnerabilidades.
2. Generador de Parches de Código Seguro (Remediation Generator).
3. Motor de Auto-Corrección Local y Auto-PR con verificación AST y backups.
4. Resumen Ejecutivo y Mapeo de Cumplimiento Normativo (CISO, OWASP, PCI-DSS).
5. Chat Interactivo de Auditoría y Asistencia Técnica en Tiempo Real.
"""
from __future__ import annotations

import ast
import difflib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, cast

import requests

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.AICopilot")


# ─────────────────────────────────────────────────────────────
# Configuración y Cliente Híbrido LLM (Groq + Ollama Local)
# ─────────────────────────────────────────────────────────────

@dataclass
class AIConfig:
    """Configuración del motor híbrido de Inteligencia Artificial."""
    groq_api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", "").strip())
    groq_model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL", "qwen-2.5-32b").strip())
    groq_endpoint: str = "https://api.groq.com/openai/v1/chat/completions"

    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen2.5:7b").strip())

    prefer_local: bool = field(
        default_factory=lambda: os.getenv("COPILOT_PREFER_LOCAL", "false").lower() in ("true", "1", "yes")
    )
    timeout_seconds: float = 20.0


class HybridLLMClient:
    """Cliente híbrido con tolerancia a fallos: Groq LPU (Cloud) <-> Ollama (Local GPU)."""

    def __init__(self, config: AIConfig | None = None) -> None:
        self.config = config or AIConfig()

    def generate(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
        temperature: float = 0.2,
    ) -> tuple[str, str, float]:
        """
        Ejecuta la inferencia LLM con conmutación inteligente y fallback resiliente.
        Retorna: (contenido_respuesta, proveedor_usado, latencia_ms).
        """
        t0 = time.perf_counter()

        # Ruta 1: Preferencia Local explícita
        if self.config.prefer_local:
            res = self._call_ollama(messages, json_mode, temperature)
            if res is not None:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return res, "ollama_local", elapsed_ms
            # Fallback a Groq si local falla
            if self.config.groq_api_key:
                res = self._call_groq(messages, json_mode, temperature)
                if res is not None:
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    return res, "groq_cloud", elapsed_ms

        # Ruta 2: Preferencia Groq (Cloud ultrarrápido)
        elif self.config.groq_api_key:
            res = self._call_groq(messages, json_mode, temperature)
            if res is not None:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return res, "groq_cloud", elapsed_ms
            # Fallback a Ollama si Groq falla
            res = self._call_ollama(messages, json_mode, temperature)
            if res is not None:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return res, "ollama_local", elapsed_ms

        # Ruta 3: Solo Ollama si no hay Groq API key
        else:
            res = self._call_ollama(messages, json_mode, temperature)
            if res is not None:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return res, "ollama_local", elapsed_ms

        # Ruta 4: Fallback determinista seguro (Sin conexión a LLM)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        fallback_text = self._rule_based_fallback(messages, json_mode)
        return fallback_text, "rule_engine_fallback", elapsed_ms

    def _call_groq(
        self,
        messages: list[dict[str, str]],
        json_mode: bool,
        temperature: float,
    ) -> str | None:
        if not self.config.groq_api_key:
            return None
        headers = {
            "Authorization": f"Bearer {self.config.groq_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "OmniBreach-Copilot/5.0.0",
        }
        payload: dict[str, Any] = {
            "model": self.config.groq_model,
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            resp = requests.post(
                self.config.groq_endpoint,
                headers=headers,
                json=payload,
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return cast(str, content)
            logger.debug("Groq API devolvió código %d: %s", resp.status_code, resp.text[:200])
            return None
        except Exception as err:
            logger.debug("Error de conexión con Groq Cloud: %s", err)
            return None

    def _call_ollama(
        self,
        messages: list[dict[str, str]],
        json_mode: bool,
        temperature: float,
    ) -> str | None:
        url = f"{self.config.ollama_url}/api/chat"
        payload: dict[str, Any] = {
            "model": self.config.ollama_model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            payload["format"] = "json"

        try:
            resp = requests.post(url, json=payload, timeout=self.config.timeout_seconds)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("message", {}).get("content", "")
                if content:
                    return cast(str, content)
            return None
        except Exception as err:
            logger.debug("Error de conexión con Ollama Local: %s", err)
            return None

    def _rule_based_fallback(self, messages: list[dict[str, str]], json_mode: bool) -> str:
        """Respaldo determinista de alta calidad cuando no hay LLM online ni local disponible."""
        last_msg = messages[-1]["content"] if messages else ""
        if json_mode:
            return json.dumps({
                "explanation": "Análisis heurístico generado por el motor de reglas de OmniBreach.",
                "attack_vector": "Vector de ataque clasificado según matriz CWE y MITRE ATT&CK.",
                "business_impact": "Riesgo de exposición de datos confidenciales e interrupción operativa.",
                "exploit_difficulty": "medium",
                "recommended_action": "Aplicar validación estricta de entradas y principio de mínimo privilegio.",
                "before_code": "# Código sin validación de parámetros",
                "after_code": "# Código securizado con validación y sanitización",
                "language": "python",
                "overall_posture": "ALTA",
                "top_immediate_actions": [
                    "Implementar cabeceras de seguridad CSP y HSTS.",
                    "Parametrizar consultas a la base de datos.",
                    "Restringir políticas de CORS en endpoints sensibles."
                ],
                "compliance_status": {
                    "OWASP_Top_10": "Requiere revisión de controles A01 y A03",
                    "PCI_DSS_v4": "Revisión necesaria para Requisito 6.4 (Seguridad de Aplicaciones)"
                }
            }, ensure_ascii=False)

        return (
            f"Análisis OmniBreach (Modo Seguro Offline):\n"
            f"Se procesó la consulta sobre: '{last_msg[:80]}...'.\n"
            f"Recomendación: verificar registros en el reporte SARIF y consultar la base de conocimiento local CWE."
        )


# ─────────────────────────────────────────────────────────────
# MODO 1: Triage y Explicación Contextual de Vulnerabilidades
# ─────────────────────────────────────────────────────────────

class FindingTriager:
    """Traduce hallazgos técnicos en contexto de riesgo y capacidades de ataque reales."""

    def __init__(self, client: HybridLLMClient) -> None:
        self.client = client

    def triage_finding(self, finding: Finding) -> dict[str, Any]:
        """Genera el triaje contextual con severidad ajustada e impacto en el negocio."""
        evidence_str = ""
        if finding.evidence:
            evidence_str = (
                f"Método: {finding.evidence.request_method}, "
                f"URL: {finding.evidence.request_url}, "
                f"Payload: {finding.evidence.payload or 'N/A'}"
            )

        prompt = (
            f"Analiza este hallazgo de ciberseguridad y provee un triaje riguroso en formato JSON:\n"
            f"- Título: {finding.title}\n"
            f"- Categoría: {finding.category} | Severidad: {finding.severity}\n"
            f"- URL Afectada: {finding.affected_url or 'N/A'}\n"
            f"- Parámetro: {finding.parameter or 'N/A'}\n"
            f"- CWE: {finding.cwe_id} ({finding.cwe_name})\n"
            f"- MITRE: {finding.mitre_attack_id} ({finding.mitre_attack_name})\n"
            f"- Evidencia: {evidence_str}\n\n"
            f"Devuelve un objeto JSON con exactamente estas claves:\n"
            f"1. 'human_explanation': Explicación clara y técnica en español de qué significa esta falla.\n"
            f"2. 'attack_vector': Cómo un atacante externo o autenticado puede explotar esto paso a paso.\n"
            f"3. 'business_impact': Impacto financiero, legal o reputacional para la organización.\n"
            f"4. 'exploit_difficulty': 'low', 'medium' o 'high'.\n"
            f"5. 'recommended_severity': 'critical', 'high', 'medium', 'low' o 'info'."
        )

        messages = [
            {
                "role": "system",
                "content": "Eres el Lead Security Analyst de OmniBreach Enterprise. Tu misión es triajar vulnerabilidades con precisión quirúrgica sin falsos positivos."
            },
            {"role": "user", "content": prompt}
        ]

        raw, provider, latency = self.client.generate(messages, json_mode=True)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {
                "human_explanation": raw[:300],
                "attack_vector": "Vector de ataque directo sobre el endpoint expuesto.",
                "business_impact": "Posible compromiso de integridad o confidencialidad.",
                "exploit_difficulty": "medium",
                "recommended_severity": finding.severity,
            }

        data["provider_used"] = provider
        data["latency_ms"] = round(latency, 2)
        return data


# ─────────────────────────────────────────────────────────────
# MODO 2: Generador de Parches de Código Seguro
# ─────────────────────────────────────────────────────────────

class RemediationGenerator:
    """Genera fragmentos de código listos para producción para neutralizar la vulnerabilidad."""

    def __init__(self, client: HybridLLMClient) -> None:
        self.client = client

    def generate_patch(self, finding: Finding, tech_stack: list[str] | None = None) -> dict[str, Any]:
        stack_str = ", ".join(tech_stack) if tech_stack else "Python / FastAPI / Generic Web"
        prompt = (
            f"Genera un parche de código seguro listo para copiar y pegar para solucionar este hallazgo:\n"
            f"- Vulnerabilidad: {finding.title} ({finding.cwe_id})\n"
            f"- Categoría: {finding.category}\n"
            f"- Stack Tecnológico del Objetivo: {stack_str}\n"
            f"- Parámetro Vulnerable: {finding.parameter or 'N/A'}\n\n"
            f"Devuelve un objeto JSON con estas claves:\n"
            f"1. 'language': lenguaje de programación (ej: 'python', 'javascript', 'nginx').\n"
            f"2. 'filename_hint': nombre típico del archivo (ej: 'security_middleware.py', 'routes.py').\n"
            f"3. 'before_code': fragmento de código inseguro conceptual.\n"
            f"4. 'after_code': fragmento de código seguro con consultas parametrizadas, saneamiento o cabeceras.\n"
            f"5. 'explanation': explicación en español de qué técnica de mitigación se aplicó.\n"
            f"6. 'defense_in_depth': recomendación adicional (WAF, headers, validación en capas)."
        )

        messages = [
            {
                "role": "system",
                "content": "Eres un arquitecto de software seguro (DevSecOps). Generas código defensivo robusto, limpio y sin bugs para mitigar vulnerabilidades."
            },
            {"role": "user", "content": prompt}
        ]

        raw, provider, latency = self.client.generate(messages, json_mode=True)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {
                "language": "python",
                "filename_hint": "security_fix.py",
                "before_code": "# Código vulnerable detectado",
                "after_code": "# Código seguro sugerido por OmniBreach",
                "explanation": raw[:250],
                "defense_in_depth": "Revisar políticas de seguridad y validadores de esquema."
            }

        data["provider_used"] = provider
        data["latency_ms"] = round(latency, 2)
        return data


# ─────────────────────────────────────────────────────────────
# MODO 3: Motor de Auto-Corrección Local y Auto-PR con Guardrails
# ─────────────────────────────────────────────────────────────

@dataclass
class PatchResult:
    """Resultado de la aplicación de un parche de seguridad sobre código fuente."""
    success: bool
    file_path: str
    applied: bool
    diff: str
    backup_path: str | None = None
    error: str | None = None


class AutoPatcher:
    """
    Audita y aplica parches seguros directamente sobre archivos de código fuente.
    Incluye guardrails: validación sintáctica con AST, creación de backups (.bak)
    y generación de diffs unificados reversibles.
    """

    def __init__(self, client: HybridLLMClient) -> None:
        self.client = client

    def patch_code_snippet(self, original_code: str, finding: Finding, language: str = "python") -> tuple[str, str]:
        """
        Solicita a la IA la versión securizada de un código y valida su sintaxis antes de devolverla.
        Retorna: (codigo_securizado, diff_unificado).
        """
        prompt = (
            f"Modifica el siguiente código para neutralizar de raíz la vulnerabilidad de seguridad descrita.\n"
            f"- Vulnerabilidad: {finding.title} ({finding.cwe_id})\n"
            f"- Parámetro vulnerable: {finding.parameter or 'N/A'}\n"
            f"- Instrucción estricta: Mantén EXACTAMENTE los mismos nombres de funciones, variables y lógica de negocio. "
            f"Solo securiza la entrada, salida o configuración vulnerable.\n\n"
            f"CÓDIGO ORIGINAL:\n```\n{original_code}\n```\n\n"
            f"Devuelve un JSON con exactamente esta clave:\n"
            f"'patched_code': el código completo resultante listo para compilar sin texto adicional."
        )

        messages = [
            {
                "role": "system",
                "content": "Eres un compilador y refactorizador de código seguro automático. Devuelves únicamente código válido y libre de errores sintácticos."
            },
            {"role": "user", "content": prompt}
        ]

        raw, _, _ = self.client.generate(messages, json_mode=True)
        try:
            data = json.loads(raw)
            patched = cast(str, data.get("patched_code", original_code))
        except json.JSONDecodeError:
            # Si el modelo respondió en texto plano, limpiamos bloques de markdown
            patched = raw.strip()
            if patched.startswith("```"):
                lines = patched.splitlines()
                if len(lines) > 2:
                    patched = "\n".join(lines[1:-1])

        # Guardrail 1: Validación sintáctica en Python mediante AST
        if language.lower() in ("python", "py"):
            try:
                ast.parse(patched)
            except SyntaxError as err:
                raise ValueError(f"El parche generado por la IA contiene errores de sintaxis Python: {err}") from err

        # Generar Diff Unificado
        orig_lines = original_code.splitlines(keepends=True)
        patch_lines = patched.splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(
            orig_lines, patch_lines,
            fromfile="original/code", tofile="patched/secure_code"
        ))

        return patched, diff

    def patch_file(self, file_path: str, finding: Finding, dry_run: bool = True) -> PatchResult:
        """
        Aplica un parche sobre un archivo físico local con salvaguarda de backup.
        """
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            return PatchResult(
                success=False, file_path=abs_path, applied=False, diff="",
                error=f"El archivo no existe: {abs_path}"
            )

        try:
            with open(abs_path, encoding="utf-8") as f:
                content = f.read()
        except OSError as err:
            return PatchResult(
                success=False, file_path=abs_path, applied=False, diff="",
                error=f"Error leyendo archivo: {err}"
            )

        lang = "python" if abs_path.endswith((".py", ".pyw")) else "generic"

        try:
            patched_content, diff = self.patch_code_snippet(content, finding, language=lang)
        except Exception as err:
            return PatchResult(
                success=False, file_path=abs_path, applied=False, diff="",
                error=f"Fallo en generación o validación del parche: {err}"
            )

        if dry_run or not diff:
            return PatchResult(
                success=True, file_path=abs_path, applied=False, diff=diff,
                backup_path=None, error=None
            )

        # Guardrail 2: Crear copia de seguridad (.bak) antes de sobreescribir
        backup_path = f"{abs_path}.bak"
        try:
            shutil.copy2(abs_path, backup_path)
            with open(abs_path, "w", encoding="utf-8") as f:
                f.write(patched_content)
            return PatchResult(
                success=True, file_path=abs_path, applied=True, diff=diff,
                backup_path=backup_path, error=None
            )
        except OSError as err:
            return PatchResult(
                success=False, file_path=abs_path, applied=False, diff=diff,
                backup_path=backup_path, error=f"Error escribiendo archivo modificado: {err}"
            )


# ─────────────────────────────────────────────────────────────
# MODO 4: Resumen Ejecutivo y Cumplimiento Normativo CISO
# ─────────────────────────────────────────────────────────────

class ExecutiveSummaryGenerator:
    """Sintetiza la auditoría en un informe estratégico para directivos y CISOs."""

    def __init__(self, client: HybridLLMClient) -> None:
        self.client = client

    def generate_summary(self, findings: list[Finding], target_url: str) -> dict[str, Any]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1

        top_findings = [
            f"- [{f.severity.upper()}] {f.title} (CWE: {f.cwe_id}) en {f.affected_url or target_url}"
            for f in sorted(findings, key=lambda x: x.severity_rank)[:5]
        ]
        top_str = "\n".join(top_findings) if top_findings else "No se detectaron hallazgos de severidad alta."

        prompt = (
            f"Elabora el Resumen Ejecutivo de la auditoría de seguridad para el CISO y Comité Directivo:\n"
            f"- Objetivo auditado: {target_url}\n"
            f"- Estadísticas de vulnerabilidades: Críticas={counts['critical']}, Altas={counts['high']}, "
            f"Medias={counts['medium']}, Bajas={counts['low']}\n"
            f"- Principales riesgos detectados:\n{top_str}\n\n"
            f"Devuelve un objeto JSON con exactamente estas claves:\n"
            f"1. 'overall_posture': 'CRÍTICA', 'ALTA', 'MODERADA' o 'SEGURA'.\n"
            f"2. 'executive_summary': 2 párrafos formales en español resumiendo la exposición de la empresa.\n"
            f"3. 'top_immediate_actions': lista de 3 acciones prioritarias que deben ejecutarse de inmediato.\n"
            f"4. 'compliance_status': objeto con el impacto en 'OWASP_Top_10_2021' y 'PCI_DSS_v4'."
        )

        messages = [
            {
                "role": "system",
                "content": "Eres un CISO y auditor senior acreditado (CISSP, CISM). Redactas resúmenes ejecutivos estratégicos, directos y basados en riesgo de negocio."
            },
            {"role": "user", "content": prompt}
        ]

        raw, provider, latency = self.client.generate(messages, json_mode=True)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            posture = "CRÍTICA" if counts["critical"] > 0 else ("ALTA" if counts["high"] > 0 else "MODERADA")
            data = {
                "overall_posture": posture,
                "executive_summary": raw[:400],
                "top_immediate_actions": [
                    "Remediar vulnerabilidades críticas de inyección y autenticación.",
                    "Habilitar cabeceras de seguridad estrictas (HSTS, CSP).",
                    "Establecer monitoreo continuo de endpoints expuestos."
                ],
                "compliance_status": {
                    "OWASP_Top_10_2021": "No conforme en categorías A01 y A03",
                    "PCI_DSS_v4": "Revisión urgente de controles de protección de datos en tránsito."
                }
            }

        data["counts"] = counts
        data["target_url"] = target_url
        data["provider_used"] = provider
        data["latency_ms"] = round(latency, 2)
        return data


# ─────────────────────────────────────────────────────────────
# MODO 5: Chat Interactivo de Auditoría y Asistencia Técnica
# ─────────────────────────────────────────────────────────────

class InteractiveCopilot:
    """Asistente interactivo en tiempo real para consultas sobre el escaneo actual."""

    def __init__(self, client: HybridLLMClient) -> None:
        self.client = client

    def chat(
        self,
        query: str,
        findings: list[Finding],
        target_url: str,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """
        Responde preguntas interactivas del auditor basándose en los hallazgos reales.
        """
        # Contextualización resumida de hallazgos para la ventana de contexto
        findings_ctx = []
        for idx, f in enumerate(findings[:10], start=1):
            findings_ctx.append(
                f"#{idx} [{f.severity.upper()}] {f.title} (CWE: {f.cwe_id}) | "
                f"URL: {f.affected_url or target_url} | Param: {f.parameter or 'N/A'}"
            )
        ctx_str = "\n".join(findings_ctx) if findings_ctx else "No hay vulnerabilidades registradas."

        system_msg = (
            f"Eres el Copiloto de Seguridad Ofensiva y Remediación de OmniBreach.\n"
            f"Estás auditando el objetivo: '{target_url}'.\n"
            f"Vulnerabilidades detectadas en esta sesión:\n{ctx_str}\n\n"
            f"Tu tarea es responder preguntas técnicas con alta precisión: generar comandos cURL para reproducción, "
            f"explicar cómo mitigar con WAF o código, redactar tickets para Jira o priorizar remediaciones. "
            f"Responde de forma clara, profesional y en español."
        )

        messages: list[dict[str, str]] = [{"role": "system", "content": system_msg}]
        if history:
            messages.extend(history[-6:])  # Mantener últimas 3 interacciones
        messages.append({"role": "user", "content": query})

        raw_response, provider, latency = self.client.generate(messages, json_mode=False)

        # Sugerir 2 acciones rápidas de seguimiento
        suggested = [
            "¿Cómo mitigo este hallazgo usando un WAF?",
            "Genera el ticket de Jira para los desarrolladores."
        ]
        if "curl" not in query.lower():
            suggested[0] = "¿Cómo reproduzco este hallazgo con cURL?"

        return {
            "answer": raw_response,
            "provider_used": provider,
            "latency_ms": round(latency, 2),
            "suggested_actions": suggested,
        }


# ─────────────────────────────────────────────────────────────
# Fachada Principal del Copiloto (OmniBreach AICopilot)
# ─────────────────────────────────────────────────────────────

class AICopilot:
    """Punto de entrada unificado para los 5 modos del Copiloto de Seguridad."""

    def __init__(self, config: AIConfig | None = None) -> None:
        self.config = config or AIConfig()
        self.llm = HybridLLMClient(self.config)
        self.triager = FindingTriager(self.llm)
        self.remediator = RemediationGenerator(self.llm)
        self.patcher = AutoPatcher(self.llm)
        self.executive = ExecutiveSummaryGenerator(self.llm)
        self.assistant = InteractiveCopilot(self.llm)

    def triage(self, finding: Finding) -> dict[str, Any]:
        return self.triager.triage_finding(finding)

    def generate_remediation(self, finding: Finding, tech_stack: list[str] | None = None) -> dict[str, Any]:
        return self.remediator.generate_patch(finding, tech_stack)

    def autofix_file(self, file_path: str, finding: Finding, dry_run: bool = True) -> PatchResult:
        return self.patcher.patch_file(file_path, finding, dry_run=dry_run)

    def executive_summary(self, findings: list[Finding], target_url: str) -> dict[str, Any]:
        return self.executive.generate_summary(findings, target_url)

    def chat(
        self,
        query: str,
        findings: list[Finding],
        target_url: str,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        return self.assistant.chat(query, findings, target_url, history=history)
