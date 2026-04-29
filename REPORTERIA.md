# 📊 Módulo de Reportería - NoSQL Tool

El módulo de reportería proporciona un **web server Flask** que permite visualizar, gestionar y exportar los reportes de detección de inyecciones NoSQL.

## 🚀 Características

- ✅ **Dashboard Interactivo**: Visualiza todos los reportes generados
- ✅ **Detalles de Reportes**: Inspecciona vulnerabilidades encontradas por endpoint y parámetro
- ✅ **Exportación**: Descarga reportes en formatos JSON y HTML
- ✅ **API REST**: Endpoints para integración con otras herramientas
- ✅ **Estadísticas**: Resumen de escaneos y vulnerabilidades
- ✅ **Interfaz Responsiva**: Compatible con dispositivos desktop y móviles

## 📋 Estructura del Módulo

```
NoSQLTool/reports/
├── __init__.py              # Exporta ReportManager y create_app
├── report_manager.py        # Gestión de lectura de reportes
├── app.py                   # Aplicación Flask con rutas
├── server.py               # Script para ejecutar el servidor
├── templates/              # Plantillas HTML Jinja2
│   ├── base.html          # Plantilla base
│   ├── index.html         # Dashboard
│   ├── report.html        # Detalle de reporte
│   └── 404.html          # Página de error
└── static/                 # Recursos estáticos (CSS, JS)
```

## 🏃 Ejecución

### Opción 1: Directamente con Python

```bash
# Servidor de reportes (port 5000)
python -m NoSQLTool --server

# Con variables de entorno personalizadas
FLASK_PORT=8080 REPORTS_DIR=/mi/ruta/reportes python -m NoSQLTool --server
```

### Opción 2: Con Docker

```bash
# Construir imagen
docker build -t nosqltool .

# Ejecutar servidor de reportes
docker run -p 5000:5000 -v /ruta/local/reports:/tmp/reports nosqltool python -m NoSQLTool --server

# Ejecutar CLI interactivo (por defecto)
docker run -it nosqltool
```

### Opción 3: Modo Desarrollo

```bash
# Activar modo debug y auto-reload
FLASK_DEBUG=1 python -m NoSQLTool --server
```

## 🌐 Endpoints Disponibles

### Rutas Web (HTML)

| Ruta | Descripción |
|------|-------------|
| `/` | Dashboard principal con historial de reportes |
| `/report/<filename>` | Detalle completo de un reporte |
| `/health` | Health check del servidor |

### API REST (JSON)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/reports` | Lista todos los reportes |
| `GET` | `/api/reports/stats` | Estadísticas consolidadas |
| `GET` | `/api/reports/<filename>` | Datos completos de un reporte |
| `GET` | `/api/reports/<filename>/summary` | Resumen de vulnerabilidades |
| `GET` | `/api/reports/<filename>/export?format=json\|html` | Exportar reporte |

## 💾 Gestión de Reportes

### Ubicación de Reportes

Los reportes se almacenan en: `/tmp/reports`

Formato de nombres:
```
nosql_report_YYYYMMDD_HHMMSS.json
Ejemplo: nosql_report_20260429_010538.json
```

### Estructura de un Reporte

```json
{
  "metadata": {
    "engine": "mongo",
    "engine_label": "MongoDB",
    "base_url": "http://localhost:3000",
    "swagger_path": "/path/to/swagger.json",
    "executed_at": "2026-04-29T01:05:38",
    "total_tests": 150,
    "detection_type": "all"
  },
  "vulnerabilities": {
    "/api/users": {
      "id": [
        "{\"$ne\": null}",
        "{\"$gt\": \"a\"}"
      ]
    },
    "/api/products/{id}": {
      "name": [
        "{\"$regex\": \".*\"}"
      ]
    }
  }
}
```

## 🔧 Variables de Entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `REPORTS_DIR` | `/tmp/reports` | Directorio de almacenamiento de reportes |
| `FLASK_HOST` | `0.0.0.0` | Host del servidor |
| `FLASK_PORT` | `5000` | Puerto del servidor |
| `FLASK_DEBUG` | `False` | Activar modo debug |

## 📈 Estadísticas

El dashboard muestra:
- **Escaneos Realizados**: Total de reportes generados
- **Vulnerabilidades**: Total de endpoints vulnerables encontrados
- **Motores Probados**: BD NoSQL diferentes utilizadas (MongoDB, Neo4j, CouchDB)
- **Último Escaneo**: Fecha del reporte más reciente

## 🎨 Interfaz de Usuario

### Dashboard
- Tarjetas de estadísticas principales
- Tabla de historial con filtros y acciones rápidas
- Enlaces a detalle de cada reporte

### Vista de Reporte
- Información metadata del escaneo
- Endpoints vulnerables organizados por parámetro
- Payloads que provocaron comportamiento anómalo
- Botones de descarga en JSON y HTML

## 🔗 Integración

### Desde CLI de Detección

El módulo se ejecuta de forma independiente:

```bash
# Terminal 1: Ejecutar detección
python -m NoSQLTool

# Terminal 2: Iniciar servidor de reportes
python -m NoSQLTool --server
```

Los reportes generados por el CLI se sirven automáticamente en el servidor.

### Desde Código Python

```python
from NoSQLTool.reports import ReportManager, create_app

# Acceder a reportes programáticamente
manager = ReportManager("/tmp/reports")
reports = manager.get_all_reports()
stats = manager.get_summary_stats()

# Crear app para servir
app = create_app("/tmp/reports")
app.run(host="0.0.0.0", port=5000)
```

## 📦 Dependencias Agregadas

- `Flask==3.0.0`: Framework web
- `Jinja2==3.1.2`: Motor de plantillas
- `python-dateutil==2.8.2`: Manejo de fechas

## 🐛 Troubleshooting

### El servidor no inicia en port 5000

```bash
# Usar puerto diferente
FLASK_PORT=8080 python -m NoSQLTool --server
```

### No se ven los reportes generados

Verifica que el directorio de reportes sea el correcto:
```bash
# Default
/tmp/reports

# Personalizado
REPORTS_DIR=/mi/directorio python -m NoSQLTool --server
```

### Los volumenes de Docker no sincronizan

Usa rutas absolutas:
```bash
docker run -v $(pwd)/reports:/tmp/reports -p 5000:5000 nosqltool python -m NoSQLTool --server
```

## 🔐 Notas de Seguridad

- El servidor por defecto escucha en `0.0.0.0` (accesible desde cualquier interfaz)
- En producción, usar un proxy inverso (nginx) con SSL/TLS
- Los reportes contienen payloads de prueba pero no ejecutan acciones maliciosas
- Mantener `/tmp/reports` con permisos restrictivos

## 📚 Ejemplo Completo

```bash
# 1. Construir la imagen
docker build -t nosqltool .

# 2. Crear directorio de reportes
mkdir -p ~/nosql-reports

# 3. Ejecutar servidor de reportes en background
docker run -d \
  -p 5000:5000 \
  -v ~/nosql-reports:/tmp/reports \
  --name nosql-reports \
  nosqltool python -m NoSQLTool --server

# 4. Ejecutar detección en otra instancia
docker run -it \
  -v ~/swagger:/tmp/swagger \
  -v ~/nosql-reports:/tmp/reports \
  nosqltool

# 5. Acceder a la web
# http://localhost:5000
```

## 🤝 Contribuciones

El módulo está diseñado para ser extensible. Se pueden agregar:
- Nuevos formatos de exportación
- Gráficos de vulnerabilidades
- Integración con sistemas de logging
- Autenticación y autorización

---

**Versión**: 1.0  
**Última actualización**: 2026-04-29
