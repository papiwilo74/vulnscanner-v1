import os
import joblib
from urllib.parse import urlparse, parse_qs

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURR_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "ai_model.joblib")
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "models", "vectorizer.joblib")

_model = None
_vectorizer = None

def load_ai_model():
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return True
        
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return False
        
    try:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        return True
    except:
        return False

def check_with_ai(url):
    results = []
    
    if not load_ai_model():
        # Si la IA no está entrenada, omitir en silencio para no romper el escáner
        return results
        
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return results
        
    for param, values in params.items():
        for val in values:
            try:
                # Transformar el valor usando el vectorizador entrenado
                vec_val = _vectorizer.transform([val])
                # Obtener la probabilidad [[prob_benigno, prob_malicioso]]
                prob = _model.predict_proba(vec_val)[0]
                prob_malicious = prob[1]
                
                # Umbral de confianza del 75%
                if prob_malicious >= 0.75:
                    results.append({
                        "vuln": f"Alerta IA: Parámetro sospechoso '{param}'",
                        "risk": "Alto" if prob_malicious >= 0.90 else "Medio",
                        "detail": f"La IA predijo un {prob_malicious*100:.1f}% de probabilidad de payload malicioso (SQLi/XSS). Valor analizado: {val}"
                    })
            except:
                pass
                
    return results
