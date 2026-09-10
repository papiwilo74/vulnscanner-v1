"""
Módulo del Asesor de Inteligencia Artificial para Remediación a Medida (AI Remediation Advisor).
Transforma los hallazgos perimetrales (EASM, CISA KEV, Subdomain Takeover, Secret Leaks)
en un Runbook Técnico de Mitigación ejecutable con comandos exactos de firewall,
instrucciones de hardening y parches de código personalizados para el equipo de IT/SecOps.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger("OmniBreach.EASM.Advisor")


@dataclass
class RemediationRunbook:
    """Documento técnico y ejecutable con la guía de remediación a medida."""
    target_domain: str
    overall_risk_level: str
    executive_summary: str
    immediate_actions: list[str] = field(default_factory=list)
    short_term_actions: list[str] = field(default_factory=list)
    strategic_recommendations: list[str] = field(default_factory=list)
    executable_scripts: dict[str, str] = field(default_factory=dict)
    generated_by: str = "OmniBreach Deterministic Expert System"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "overall_risk_level": self.overall_risk_level,
            "executive_summary": self.executive_summary,
            "immediate_actions": self.immediate_actions,
            "short_term_actions": self.short_term_actions,
            "strategic_recommendations": self.strategic_recommendations,
            "executable_scripts": self.executable_scripts,
            "generated_by": self.generated_by,
        }

    def to_markdown(self) -> str:
        """Genera una versión en Markdown estructurada del Runbook."""
        lines = [
            f"# Runbook Técnico de Remediación a Medida — {self.target_domain}",
            f"**Nivel de Riesgo Global:** {self.overall_risk_level} | **Motor:** {self.generated_by}\n",
            "## 1. Resumen Ejecutivo de Impacto",
            self.executive_summary,
            "\n## 2. Acciones Inmediatas (Primeras 24 Horas — P0)",
        ]
        if self.immediate_actions:
            for act in self.immediate_actions:
                lines.append(f"- [ ] **[CRÍTICO]** {act}")
        else:
            lines.append("- [x] No se requieren acciones de emergencia P0 inmediatas.")

        lines.append("\n## 3. Acciones a Corto Plazo (1 a 7 Días — P1/P2)")
        if self.short_term_actions:
            for act in self.short_term_actions:
                lines.append(f"- [ ] {act}")
        else:
            lines.append("- [x] Perímetro estable sin acciones a corto plazo pendientes.")

        lines.append("\n## 4. Scripts y Comandos de Mitigación Inmediata")
        for name, script in self.executable_scripts.items():
            lines.append(f"### {name}")
            lines.append("```bash")
            lines.append(script.strip())
            lines.append("```\n")

        lines.append("## 5. Recomendaciones Estratégicas")
        for strat in self.strategic_recommendations:
            lines.append(f"- 💡 {strat}")

        return "\n".join(lines)


class AIRemediationAdvisor:
    """Generador de Runbooks de remediación personalizados con IA y Reglas de Ingeniería."""

    def __init__(self, llm_endpoint: str | None = None, api_key: str | None = None):
        self.llm_endpoint = llm_endpoint or os.environ.get("OMNIBREACH_LLM_HOST")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")

    def generate_runbook(
        self,
        domain: str,
        services: list[Any],
        cves: list[Any],
        takeovers: list[Any],
        secret_leaks: list[Any],
        identity_risk: dict[str, Any] | None = None
    ) -> RemediationRunbook:
        """
        Analiza todos los hallazgos perimetrales y sintetiza un plan de mitigación
        personalizado con comandos ejecutables.
        """
        immediate: list[str] = []
        short_term: list[str] = []
        strategic: list[str] = []
        scripts: dict[str, str] = {}

        # 1. Análisis de Puertos y Vectores de Ransomware
        fw_rules: list[str] = []
        for s in services:
            port = getattr(s, "port", None) or (s.get("port") if isinstance(s, dict) else None)
            name = getattr(s, "service_name", "") or (s.get("service_name", "") if isinstance(s, dict) else "")
            host = getattr(s, "host", "") or (s.get("host", "") if isinstance(s, dict) else "")
            unauth = getattr(s, "unauthenticated_access", False) or (s.get("unauthenticated_access", False) if isinstance(s, dict) else False)
            ransomware = getattr(s, "ransomware_vector", False) or (s.get("ransomware_vector", False) if isinstance(s, dict) else False)

            if unauth:
                immediate.append(
                    f"Cerrar inmediatamente acceso no autenticado a base de datos {name} en {host}:{port} (Riesgo de vaciado o secuestro de datos)."
                )
                fw_rules.append(f"# Bloquear acceso público a base de datos {name} ({port})\niptables -I INPUT -p tcp --dport {port} -j DROP")
            elif ransomware:
                immediate.append(
                    f"Aislar puerto de acceso remoto {name} ({port}) en {host} detrás de una VPN corporativa con MFA obligatorio."
                )
                fw_rules.append(f"# Restringir puerto {name} ({port})\niptables -A INPUT -p tcp --dport {port} -s 10.0.0.0/8 -j ACCEPT\niptables -A INPUT -p tcp --dport {port} -j DROP")

        if fw_rules:
            scripts["Reglas de Firewall Perimetral (iptables / UFW)"] = "\n".join(fw_rules)

        # 2. Análisis de Subdomain Takeover
        dns_actions: list[str] = []
        for t in takeovers:
            sub = getattr(t, "subdomain", "") or (t.get("subdomain", "") if isinstance(t, dict) else "")
            cname = getattr(t, "cname", "") or (t.get("cname", "") if isinstance(t, dict) else "")
            service = getattr(t, "service_name", "") or (t.get("service_name", "") if isinstance(t, dict) else "")

            immediate.append(
                f"SECUESTRO DE SUBDOMINIO: Eliminar registro DNS CNAME '{cname}' para '{sub}' antes de que un cibercriminal lo reclame en {service}."
            )
            dns_actions.append(f"# Eliminar registro CNAME huérfano para {sub}\n# Proveedor DNS: Eliminar CNAME {sub} -> {cname}")

        if dns_actions:
            scripts["Acciones DNS contra Subdomain Takeover"] = "\n".join(dns_actions)

        # 3. Análisis de Fugas de Secretos
        secret_actions: list[str] = []
        for sec in secret_leaks:
            sec_type = getattr(sec, "secret_type", "") or (sec.get("secret_type", "") if isinstance(sec, dict) else "")
            masked = getattr(sec, "masked_value", "") or (sec.get("masked_value", "") if isinstance(sec, dict) else "")
            source = getattr(sec, "source_repository", "") or (sec.get("source_repository", "") if isinstance(sec, dict) else "")

            immediate.append(
                f"FUGA DE IDENTIDAD: Revocar credencial '{sec_type}' ({masked}) encontrada en repositorio público '{source}'."
            )
            secret_actions.append(f"# 1. Revocar token en el proveedor ({sec_type})\n# 2. Reemplazar por secreto en AWS Secrets Manager o HashiCorp Vault\n# 3. Limpiar historial git: git filter-repo --invert-paths --path <archivo>")

        if secret_actions:
            scripts["Procedimiento de Revocación de Credenciales"] = "\n".join(secret_actions)

        # 4. Análisis de Vulnerabilidades CISA KEV
        patch_cmds: list[str] = []
        for cve in cves:
            cve_id = getattr(cve, "cve_id", "") or (cve.get("cve_id", "") if isinstance(cve, dict) else "")
            prod = getattr(cve, "affected_product", "") or (cve.get("affected_product", "") if isinstance(cve, dict) else "")
            remed = getattr(cve, "remediation_steps", "") or (cve.get("remediation_steps", "") if isinstance(cve, dict) else "")

            short_term.append(f"Parchear {cve_id} en {prod}: {remed}")
            if "openssh" in prod.lower():
                patch_cmds.append("sudo apt update && sudo apt install --only-upgrade openssh-server\nsudo systemctl restart ssh")
            elif "apache" in prod.lower():
                patch_cmds.append("sudo apt update && sudo apt install --only-upgrade apache2\nsudo systemctl restart apache2")

        if patch_cmds:
            scripts["Comandos de Actualización de Seguridad"] = "\n".join(patch_cmds)

        # 5. Recomendaciones Estratégicas
        strategic.extend([
            "Implementar escaneos continuos de superficie de ataque (CTEM) para detectar Shadow IT antes de los fines de semana.",
            "Desplegar autenticación resistente al phishing (FIDO2 / WebAuthn) para todas las conexiones remotas.",
            "Integrar pre-commit hooks con GitGuardian o Trivy en los repositorios de desarrollo para bloquear subidas de credenciales.",
            "Configurar auditorías de DNS automatizadas para alertar sobre CNAMEs cuyos servicios de destino hayan sido dados de baja.",
        ])

        # Severidad global
        if immediate:
            risk_level = "CRÍTICO"
            summary = (
                f"Se detectaron {len(immediate)} vectores de ataque de emergencia en el perímetro de {domain}. "
                "Existen puertos de ransomware, posibles secuestros de subdominios o credenciales expuestas que "
                "deben neutralizarse en las próximas 24 horas siguiendo los scripts adjuntos."
            )
        elif short_term:
            risk_level = "MEDIO"
            summary = (
                f"El perímetro de {domain} no presenta vectores inmediatos de ransomware, pero requiere "
                f"la aplicación de {len(short_term)} parches de software y mejoras en configuraciones de red."
            )
        else:
            risk_level = "BAJO / SALUDABLE"
            summary = f"El perímetro exterior de {domain} se encuentra hermético y cumple con las buenas prácticas de exposición externa."

        # Intentar enriquecimiento opcional con LLM local si está disponible
        runbook = RemediationRunbook(
            target_domain=domain,
            overall_risk_level=risk_level,
            executive_summary=summary,
            immediate_actions=immediate,
            short_term_actions=short_term,
            strategic_recommendations=strategic,
            executable_scripts=scripts,
            generated_by="OmniBreach AI Rule Engine"
        )

        if self.llm_endpoint:
            runbook = self._try_llm_enrichment(runbook)

        return runbook

    def _try_llm_enrichment(self, base_runbook: RemediationRunbook) -> RemediationRunbook:
        """Enriquece el resumen ejecutivo con un LLM local si está activo."""
        try:
            prompt = (
                f"Eres un CISO experto en ciberseguridad corporativa. Resume en 3 oraciones concisas el plan de acción "
                f"para el dominio {base_runbook.target_domain} con nivel de riesgo {base_runbook.overall_risk_level} "
                f"y los siguientes problemas: {', '.join(base_runbook.immediate_actions[:3])}."
            )
            resp = requests.post(
                f"{self.llm_endpoint}/api/generate",
                json={"model": "llama3", "prompt": prompt, "stream": False},
                timeout=4
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "").strip()
                if text:
                    base_runbook.executive_summary = text
                    base_runbook.generated_by = "OmniBreach Local LLM Advisor (Llama3)"
        except Exception as err:
            logger.debug("LLM local no respondió (%s). Utilizando motor de reglas determinista.", err)

        return base_runbook
