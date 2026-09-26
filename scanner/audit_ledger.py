"""
Registro de Auditoría Inmutable (Append-Only Hash-Chained Audit Ledger).
Proporciona trazabilidad criptográfica inmutable para todos los eventos del ciclo de escaneo
(inicio, hallazgos descubiertos, verificaciones quirúrgicas y finalización),
asegurando cumplimiento con SOC 2, ISO 27001 y PCI-DSS mediante cadenas de hash SHA-256.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger("OmniBreach.AuditLedger")

GENESIS_HASH = "0" * 64


def _canonical_json(data: dict[str, Any]) -> str:
    """Serializa un diccionario a JSON determinista y canónico para cálculo de hashes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def calculate_event_hash(
    index: int,
    timestamp: str,
    event_type: str,
    actor: str,
    data: dict[str, Any],
    previous_hash: str,
) -> str:
    """Calcula el hash criptográfico SHA-256 inmutable de un bloque de evento."""
    serialized_data = _canonical_json(data)
    content = f"{index}|{timestamp}|{event_type}|{actor}|{serialized_data}|{previous_hash}".encode()
    return hashlib.sha256(content).hexdigest()


class AuditLedger:
    """
    Libro mayor de auditoría append-only con encadenamiento de hashes SHA-256.
    Cualquier alteración, inserción o eliminación de registros invalida la cadena.
    """

    def __init__(self, ledger_file: str | None = None) -> None:
        self.ledger_file = ledger_file
        self.events: list[dict[str, Any]] = []
        if self.ledger_file and os.path.exists(self.ledger_file):
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Carga eventos existentes desde el archivo append-only JSONL."""
        if not self.ledger_file:
            return
        loaded: list[dict[str, Any]] = []
        try:
            with open(self.ledger_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        loaded.append(json.loads(line))
            self.events = loaded
            logger.info("[AuditLedger] Cargados %d eventos de auditoría desde %s.", len(loaded), self.ledger_file)
        except Exception as exc:
            logger.error("[AuditLedger] Error al leer archivo de auditoría: %s", exc)

    def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
        actor: str = "system",
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        """
        Registra un nuevo evento inmutable en el libro mayor encadenándolo al bloque anterior.
        """
        index = len(self.events)
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prev_hash = self.events[-1]["current_hash"] if self.events else GENESIS_HASH

        current_hash = calculate_event_hash(
            index=index,
            timestamp=ts,
            event_type=event_type,
            actor=actor,
            data=data,
            previous_hash=prev_hash,
        )

        event = {
            "index": index,
            "timestamp": ts,
            "event_type": event_type,
            "actor": actor,
            "data": data,
            "previous_hash": prev_hash,
            "current_hash": current_hash,
        }

        self.events.append(event)

        if self.ledger_file:
            try:
                with open(self.ledger_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            except Exception as exc:
                logger.error("[AuditLedger] Error guardando evento en disco: %s", exc)

        return event

    def verify_integrity(self) -> tuple[bool, str]:
        """
        Verifica criptográficamente la integridad del libro mayor.
        Garantiza que ningún registro ha sido modificado, inyectado o borrado retroactivamente.
        """
        if not self.events:
            return True, "Ledger vacío (0 eventos)."

        for i, event in enumerate(self.events):
            expected_index = i
            if event.get("index") != expected_index:
                return False, f"Violación de índice en bloque {i}: esperado {expected_index}, obtenido {event.get('index')}"

            expected_prev = GENESIS_HASH if i == 0 else self.events[i - 1]["current_hash"]
            if event.get("previous_hash") != expected_prev:
                return False, f"Ruptura de cadena en bloque {i}: previous_hash no coincide con bloque anterior"

            recomputed_hash = calculate_event_hash(
                index=event["index"],
                timestamp=event["timestamp"],
                event_type=event["event_type"],
                actor=event["actor"],
                data=event["data"],
                previous_hash=event["previous_hash"],
            )

            if event.get("current_hash") != recomputed_hash:
                return False, f"Alteración de datos detectada en bloque {i}: hash esperado {recomputed_hash}, registrado {event.get('current_hash')}"

        return True, f"Integridad verificada con éxito: {len(self.events)} eventos válidos e inmutables."

    def export_chain(self) -> list[dict[str, Any]]:
        """Retorna la lista de bloques de eventos de la cadena."""
        return list(self.events)

    def export_tamper_proof_report(self) -> dict[str, Any]:
        """
        Genera un reporte forense de auditoría inmutable apto para auditores SOC 2 / ISO 27001.
        """
        is_valid, msg = self.verify_integrity()
        first_event = self.events[0] if self.events else None
        last_event = self.events[-1] if self.events else None

        return {
            "compliance_standard": "SOC2-CC6.8 / ISO27001-A.12.4",
            "integrity_verified": is_valid,
            "verification_message": msg,
            "total_events": len(self.events),
            "genesis_hash": GENESIS_HASH,
            "root_head_hash": last_event["current_hash"] if last_event else None,
            "start_time": first_event["timestamp"] if first_event else None,
            "end_time": last_event["timestamp"] if last_event else None,
            "events": self.events,
        }
