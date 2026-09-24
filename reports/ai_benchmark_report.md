# Reporte de Evaluación Cuantitativa de Precisión: Motor Solo vs. Motor + IA
**Fecha de Evaluación:** `2026-09-24T05:44:55.474991+00:00`  
**Corpus de Referencia:** `1.0.0` (`26` muestras etiquetadas)  
**Herramienta:** OmniBreach v3.8 AI Copilot Evaluation Harness

---

## 1. Tabla Comparativa de Rendimiento

| Métrica de Calidad | Motor Solo (Línea Base DAST) | Motor + IA (Híbrido + Guardrails) | Impacto / Delta |
| :--- | :---: | :---: | :---: |
| **Precisión (Precision)** | **50.0%** | **100.0%** | **+50.0%** 🚀 |
| **Recall (Sensibilidad)** | **100.0%** | **100.0%** | Preservación de vulnerabilidades |
| **F1-Score** | **0.6667** | **1.0000** | **+33.3%** |
| **Verdaderos Positivos (TP)** | 13 | 13 | Cobertura total confirmada |
| **Falsos Positivos (FP)** | 13 | 0 | Ruido descartado |
| **Verdaderos Negativos (TN)** | 0 | 13 | Descarte certero de ruido |
| **Falsos Negativos (FN)** | 0 | 0 | 0 vulnerabilidades ocultas |

---

## 2. Evidencia Cuantitativa de Seguridad y Robustez

- **Falsos Positivos Reducidos:** **13 de 13** (100.0% de reducción de fatiga de alertas).
- **Alucinaciones Bloqueadas por Guardrails:** **1** intentos interceptados exitosamente (escaladas injustificadas de severidad, descarte de exploits comprobados y trampas de prompt injection).
- **Privacidad de Datos:** 100% de muestras sanitizadas con `DataSanitizer` (redacción de tokens JWT, credenciales y topología de red RFC 1918).

---

## 3. Conclusión de Ingeniería
El triaje híbrido de OmniBreach v3.8 demuestra empíricamente que la IA, cuando está respaldada por guardrails deterministas bidireccionales, incrementa la precisión sin sacrificar la capacidad de detección (Recall = 100%), eliminando de raíz el principal problema de los escáneres DAST convencionales: la sobrecarga de falsos positivos.
