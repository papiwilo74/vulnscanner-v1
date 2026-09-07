import os
from urllib.parse import parse_qs, urlparse

import joblib

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURR_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "ai_model.joblib")
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "models", "vectorizer.joblib")

_model = None
_vectorizer = None

def load_ai_model() -> bool:
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return False

    try:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        return True
    except (OSError, ValueError):
        return False

def check_with_ai(url: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    if not load_ai_model() or _vectorizer is None or _model is None:
        return results

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param, values in params.items():
        for val in values:
            # Omitir valores demasiado cortos o alfanuméricos simples
            if not val or len(val) < 4 or val.isalnum():
                continue

            try:
                vec_val = _vectorizer.transform([val])
                prob = _model.predict_proba(vec_val)[0]
                prob_malicious = prob[1]

                # Elevar umbral de confianza a 88% para eliminar alertas dudosas
                if prob_malicious >= 0.88:
                    results.append({
                        "vuln": f"Alerta IA: Parámetro sospechoso '{param}'",
                        "risk": "Alto" if prob_malicious >= 0.94 else "Medio",
                        "detail": f"La IA predijo un {prob_malicious*100:.1f}% de probabilidad de payload malicioso. Valor analizado: {val}"
                    })
            except (ValueError, AttributeError):
                pass

    return results
