"""
Módulo de Inferencia de Inteligencia Artificial y Active Learning Loop.
Clasifica cadenas y parámetros HTTP potencialmente maliciosos utilizando modelos n-gram
de caracteres y permite la recolección de retroalimentación de analistas (Active Learning).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import warnings
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

import joblib

logger = logging.getLogger("OmniBreach.AICheck")

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURR_DIR)
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "ai_model.joblib")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.joblib")
FEEDBACK_PATH = os.path.join(MODELS_DIR, "ai_feedback.jsonl")

_model: Any = None
_vectorizer: Any = None
_lock = threading.Lock()


def load_ai_model() -> bool:
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return False

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _model = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VECTORIZER_PATH)
        return True
    except (OSError, ValueError) as err:
        logger.debug("No se pudo cargar modelo IA: %s", err)
        return False


def predict_payload(val: str) -> tuple[float, bool]:
    """
    Evalúa un valor de payload.
    Retorna (probabilidad_maliciosa, is_high_uncertainty).
    """
    if not load_ai_model() or _vectorizer is None or _model is None:
        return 0.0, False

    try:
        vec_val = _vectorizer.transform([val])
        prob = _model.predict_proba(vec_val)[0]
        prob_malicious = float(prob[1])
        # Muestras inciertas para Active Learning (cerca de la frontera de decisión)
        is_uncertain = 0.40 <= prob_malicious <= 0.60
        return prob_malicious, is_uncertain
    except (ValueError, AttributeError):
        return 0.0, False


def record_analyst_feedback(
    payload: str,
    is_malicious: bool,
    category: str = "custom",
    analyst: str = "SecOps"
) -> bool:
    """
    Registra retroalimentación de analistas en ai_feedback.jsonl para Active Learning.
    Permite re-entrenar y refinar el modelo con casos de falsos positivos o falsos negativos.
    """
    clean_payload = payload.strip()
    if not clean_payload:
        return False

    os.makedirs(MODELS_DIR, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": clean_payload,
        "is_malicious": is_malicious,
        "label": 1 if is_malicious else 0,
        "category": category,
        "analyst": analyst,
    }

    with _lock:
        try:
            with open(FEEDBACK_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            logger.info("Feedback de analista registrado para Active Learning: '%s' -> %s", clean_payload[:30], is_malicious)
            return True
        except OSError as err:
            logger.error("Error guardando feedback de analista: %s", err)
            return False


def get_active_learning_feedback() -> list[dict[str, Any]]:
    """Lee todas las muestras de retroalimentación acumuladas."""
    samples: list[dict[str, Any]] = []
    if not os.path.exists(FEEDBACK_PATH):
        return samples

    try:
        with open(FEEDBACK_PATH, encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    samples.append(json.loads(line_str))
    except Exception as err:
        logger.debug("Error leyendo feedback de active learning: %s", err)

    return samples


def check_with_ai(url: str) -> list[dict[str, str]]:
    """Analiza los parámetros de una URL con el modelo de clasificación de IA."""
    results: list[dict[str, str]] = []

    if not load_ai_model() or _vectorizer is None or _model is None:
        return results

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param, values in params.items():
        for val in values:
            if not val or len(val) < 4 or val.isalnum():
                continue

            prob_malicious, is_uncertain = predict_payload(val)

            # Elevar umbral de confianza a 88% para eliminar alertas dudosas
            if prob_malicious >= 0.88:
                results.append({
                    "vuln": f"Alerta IA: Parámetro sospechoso '{param}'",
                    "risk": "Alto" if prob_malicious >= 0.94 else "Medio",
                    "detail": f"La IA predijo un {prob_malicious*100:.1f}% de probabilidad de payload malicioso. Valor analizado: {val}",
                })
            elif is_uncertain:
                logger.debug("[ACTIVE LEARNING] Muestra con alta incertidumbre detectada en param '%s': %s (P=%.2f)", param, val, prob_malicious)

    return results
