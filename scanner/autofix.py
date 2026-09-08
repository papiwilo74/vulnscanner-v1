"""Motor de Remediación Contextual y Generador de Parches de Código Seguro (Auto-Fix).

Detecta automáticamente el stack tecnológico de la aplicación web y genera fragmentos de código
exactos y listos para copiar y pegar (Copy-Paste Ready) para solucionar cada vulnerabilidad detectada.
"""
from typing import Any, Optional

from scanner.models import Finding


class TechFingerprinter:
    """Identifica el framework y tecnologías web a partir de cabeceras, cookies y cuerpo HTML."""

    @staticmethod
    def detect_stack(headers: Optional[dict[str, Any]] = None, html: str = "", cookies: Optional[dict[str, Any]] = None) -> list[str]:
        headers = headers or {}
        cookies = cookies or {}
        detected: list[str] = []

        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        cookies_str = " ".join(f"{k}={v}" for k, v in cookies.items()).lower()
        html_lower = html.lower()

        # 1. Frameworks Node.js / JavaScript
        if "next" in headers_str or "__next_data__" in html_lower or "_next/static" in html_lower or "id=\"__next\"" in html_lower:
            detected.append("Next.js")
        if "express" in headers_str or "connect.sid" in cookies_str or "x-powered-by: express" in headers_str:
            detected.append("Express.js")
        if "react" in html_lower or "data-reactroot" in html_lower or "_react" in html_lower:
            detected.append("React")

        # 2. Frameworks Python
        if "csrftoken" in cookies_str or "django" in headers_str or "sessionid" in cookies_str:
            detected.append("Django")
        if "uvicorn" in headers_str or "fastapi" in headers_str or "/openapi.json" in html_lower:
            detected.append("FastAPI")
        if "flask" in headers_str or "werkzeug" in headers_str or "session=" in cookies_str:
            detected.append("Flask")

        # 3. Frameworks PHP
        if "laravel" in cookies_str or "xsrf-token" in cookies_str or "x-powered-by: php" in headers_str:
            detected.append("Laravel / PHP")
        if "php" in headers_str or "phpsessid" in cookies_str:
            detected.append("PHP")

        # 4. Servidores Web / Proxies
        if "nginx" in headers_str:
            detected.append("Nginx")
        elif "apache" in headers_str:
            detected.append("Apache")
        elif "cloudflare" in headers_str or "cf-ray" in headers_str:
            detected.append("Cloudflare")

        return detected if detected else ["General (Framework Agnóstico)"]


# ─────────────────────────────────────────────────────────────
# Base de Conocimiento de Parches de Código Seguro
# ─────────────────────────────────────────────────────────────

PATCH_KNOWLEDGE_BASE: dict[str, dict[str, dict[str, str]]] = {
    "headers": {
        "Nginx": {
            "lang": "nginx",
            "file": "/etc/nginx/conf.d/security_headers.conf",
            "code": """# Cabeceras de Seguridad Recomendadas en Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;""",
            "desc": "Añade este bloque dentro de tu directiva 'server { ... }' en Nginx y recarga la configuración (nginx -s reload)."
        },
        "Express.js": {
            "lang": "javascript",
            "file": "server.js / app.js",
            "code": """// Instalar: npm install helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// Configuración de cabeceras seguras con Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));""",
            "desc": "Integra el middleware oficial 'helmet' al inicio de tu cadena de middlewares en Express."
        },
        "Django": {
            "lang": "python",
            "file": "settings.py",
            "code": """# Añadir en settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_BROWSER_XSS_FILTER = True

# Para CSP instala django-csp: pip install django-csp
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    # ... otros middlewares
]
CSP_DEFAULT_SRC = ("'self'",)""",
            "desc": "Habilita las directivas nativas de seguridad de Django en el archivo de configuración settings.py."
        },
        "Next.js": {
            "lang": "javascript",
            "file": "next.config.js",
            "code": """// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';" },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};""",
            "desc": "Define las cabeceras HTTP de seguridad globalmente en tu archivo next.config.js."
        },
    },
    "cors": {
        "Express.js": {
            "lang": "javascript",
            "file": "server.js",
            "code": """// Instalar: npm install cors
const cors = require('cors');

const allowedOrigins = ['https://tudominio.com', 'https://app.tudominio.com'];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origen (como apps móviles o curl) o en la lista blanca
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Bloqueado por política CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));""",
            "desc": "Usa una lista blanca explícita de dominios autorizados y nunca reflejes el origen dinámicamente con credenciales."
        },
        "FastAPI": {
            "lang": "python",
            "file": "main.py",
            "code": """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "https://tudominio.com",
    "https://admin.tudominio.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)""",
            "desc": "Configura CORSMiddleware en FastAPI restringiendo los orígenes a URLs de confianza sin comodines."
        },
        "Django": {
            "lang": "python",
            "file": "settings.py",
            "code": """# pip install django-cors-headers
INSTALLED_APPS = [
    # ...
    'corsheaders',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    # ... debe ir antes de CommonMiddleware
]

CORS_ALLOWED_ORIGINS = [
    "https://tudominio.com",
    "https://app.tudominio.com",
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False  # NUNCA activar en producción""",
            "desc": "Usa django-cors-headers declarando únicamente los dominios necesarios en CORS_ALLOWED_ORIGINS."
        },
    },
    "sqli": {
        "Express.js": {
            "lang": "javascript",
            "file": "controllers/user.js",
            "code": """// FORMA SEGURA: Consultas Parametrizadas (Prepared Statements) con pg / mysql2
// ❌ INSEGURO: db.query(`SELECT * FROM users WHERE id = '${userId}'`)

// ✅ SEGURO con PostgreSQL (pg):
const query = 'SELECT id, username, email FROM users WHERE id = $1 AND status = $2';
const result = await db.query(query, [userId, 'active']);

// ✅ SEGURO con ORM (Prisma):
const user = await prisma.user.findUnique({
  where: { id: parseInt(userId) },
});""",
            "desc": "Sustituye la concatenación de variables en strings SQL por parámetros posicionales ($1, ?) o métodos seguros de tu ORM."
        },
        "Python": {
            "lang": "python",
            "file": "database.py / views.py",
            "code": """# ❌ INSEGURO: cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# ✅ SEGURO con SQLite / PostgreSQL / MySQL:
cursor.execute("SELECT id, email FROM users WHERE username = %s AND active = %s", (username, True))

# ✅ SEGURO con SQLAlchemy (ORM):
from sqlalchemy import select
stmt = select(User).where(User.username == username)
user = session.scalars(stmt).first()

# ✅ SEGURO con Django ORM:
user = User.objects.filter(username=username).first()""",
            "desc": "Pasa los parámetros como tupla independiente al método execute(), permitiendo que el driver de base de datos los escape nativamente."
        },
    },
    "xss": {
        "React": {
            "lang": "javascript",
            "file": "components/Display.jsx",
            "code": """// ❌ INSEGURO: <div dangerouslySetInnerHTML={{ __html: userInput }} />

// ✅ SEGURO: React escapa strings automáticamente en JSX
return <div>{userInput}</div>;

// ✅ Si requieres renderizar HTML de forma obligatoria, usa DOMPurify:
// npm install dompurify
import DOMPurify from 'dompurify';

const CleanHTML = ({ rawHtml }) => {
  const sanitized = DOMPurify.sanitize(rawHtml, { USE_PROFILES: { html: true } });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
};""",
            "desc": "Usa la sintaxis nativa de llaves de React {} para auto-escapar o desinfecta el HTML con DOMPurify antes de renderizar."
        },
        "Express.js": {
            "lang": "javascript",
            "file": "utils/security.js",
            "code": """// Instalar: npm install xss
const xss = require('xss');

// Sanitizar entradas de usuario antes de almacenarlas o reflejarlas
const safeOutput = xss(untrustedUserInput, {
  whiteList: { b: [], i: [], strong: [], em: [] }, // Solo etiquetas seguras
  stripIgnoreTag: true,
});

res.send(`<h1>Hola, ${safeOutput}</h1>`);""",
            "desc": "Aplica Contextual Output Encoding y bibliotecas de sanitización como 'xss' o 'DOMPurify' en Node.js."
        },
    },
    "cookies": {
        "Express.js": {
            "lang": "javascript",
            "file": "auth.js",
            "code": """// Configuración segura de cookies de sesión en Express
res.cookie('session_token', tokenValue, {
  httpOnly: true,                 // Previene acceso desde scripts JS (mitiga XSS)
  secure: process.env.NODE_ENV === 'production', // Solo transmite por HTTPS
  sameSite: 'lax',                // Mitiga ataques CSRF
  maxAge: 24 * 60 * 60 * 1000,    // 24 horas de expiración
  path: '/',
});""",
            "desc": "Activa las banderas httpOnly, secure y sameSite en todas las cookies que contengan tokens o IDs de sesión."
        },
        "Django": {
            "lang": "python",
            "file": "settings.py",
            "code": """# Configuración estricta de cookies en Django
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'""",
            "desc": "Forza el uso de HTTPS y banderas de protección de sesión en settings.py."
        },
        "FastAPI": {
            "lang": "python",
            "file": "routes/auth.py",
            "code": """from fastapi import Response

@app.post("/login")
def login(response: Response):
    # Generar token...
    response.set_cookie(
        key="session_id",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400
    )
    return {"message": "Sesión iniciada"}""",
            "desc": "Declara explícitamente httponly=True, secure=True y samesite='lax' al responder con set_cookie()."
        },
    },
    "jwt": {
        "Express.js": {
            "lang": "javascript",
            "file": "middleware/auth.js",
            "code": """// Instalar: npm install jsonwebtoken
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  try {
    // ⚠️ CRÍTICO: Especificar explícitamente el algoritmo permitido
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // NUNCA permitir 'none'
      maxAge: '2h',
    });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }
}""",
            "desc": "Fija obligatoriamente los algoritmos permitidos (algorithms: ['HS256'] o RS256) al llamar a jwt.verify()."
        },
        "Python": {
            "lang": "python",
            "file": "security.py",
            "code": """# pip install pyjwt cryptography
import jwt

def decode_token(token: str, secret_key: str):
    try:
        # CRÍTICO: Declarar 'algorithms' como lista fija
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],  # Rechaza automáticamente tokens 'none' o algoritmos cruzados
            options={"require": ["exp", "iat"]}
        )
        return payload
    except jwt.PyJWTError as e:
        raise ValueError("Token JWT inválido o manipulado") from e""",
            "desc": "Usa PyJWT pasando siempre el parámetro algorithms=['HS256'] para prevenir ataques de degradación de algoritmo."
        },
    },
}


class AutoFixEngine:
    """Orquestador que asocia hallazgos con parches de código según el stack detectado."""

    @staticmethod
    def generate_patch(category: str, tech_stack: list[str]) -> Optional[dict[str, Any]]:
        category_patches = PATCH_KNOWLEDGE_BASE.get(category.lower())
        if not category_patches:
            return None

        # 1. Intentar coincidir con una tecnología detectada
        for tech in tech_stack:
            if tech in category_patches:
                data = category_patches[tech]
                return {
                    "technology": tech,
                    "language": data["lang"],
                    "filename": data["file"],
                    "code_snippet": data["code"],
                    "explanation": data["desc"],
                }

        # 2. Si no coincide exactamente, usar el primer parche disponible como plantilla
        first_tech = next(iter(category_patches))
        data = category_patches[first_tech]
        return {
            "technology": first_tech,
            "language": data["lang"],
            "filename": data["file"],
            "code_snippet": data["code"],
            "explanation": data["desc"],
        }


def enrich_findings_with_autofix(findings: list[Finding], tech_stack: Optional[list[str]] = None) -> list[Finding]:
    """Enriquece una lista de hallazgos con los parches de código seguros correspondientes."""
    stack = tech_stack or ["General"]
    for f in findings:
        if not f.autofix:
            patch = AutoFixEngine.generate_patch(f.category, stack)
            if patch:
                f.autofix = patch
    return findings
