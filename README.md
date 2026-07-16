# NoSQLTool

NoSQLTool es una herramienta de linea de comandos para apoyar pruebas
controladas de inyeccion NoSQL a partir de una especificacion Swagger/OpenAPI.
Permite ejecutar deteccion, revisar hallazgos, lanzar una fase de explotacion
sobre resultados vulnerables y generar reportes temporales en formato JSON o
TXT.

La herramienta esta pensada para entornos autorizados de evaluacion de
seguridad. Usala solo contra APIs propias, entornos controlados o sistemas
donde tengas permiso explicito.

## Caracteristicas

- Deteccion de posibles inyecciones NoSQL usando una especificacion Swagger.
- Soporte para motores `mongo`, `couchdb` y `neo4j`.
- Familias de payloads `boolean_based`, `error_based` y `time_based`.
- Ejecucion interactiva mediante CLI.
- Ejecucion directa por variables de entorno para automatizacion.
- Reportes en memoria servidos por HTTP mientras el CLI permanece activo.
- Contenedor Docker endurecido: usuario no root, filesystem de solo lectura,
  capabilities removidas y cache temporal en `tmpfs`.

## Requisitos

Para ejecutar con Docker:

- Docker Desktop o Docker Engine con Docker Compose.
- Un archivo Swagger/OpenAPI en formato JSON.
- Acceso de red desde el contenedor hacia la API objetivo.

Para ejecutar localmente:

- Python 3.11 o superior.
- Dependencias instaladas desde `requirements.txt`.

## Levantar con Docker Compose

Este es el flujo recomendado para usar la herramienta sin instalar dependencias
de Python en el host.

### 1. Preparar el Swagger

Ubica el archivo `swagger.json` de la API que quieres evaluar. En PowerShell,
guarda su ruta absoluta en la variable `SWAGGER_PATH`:

```powershell
$env:SWAGGER_PATH = (Resolve-Path ".\ruta\al\swagger.json").Path
```

### 2. Construir la imagen

```powershell
docker compose build
```

### 3. Iniciar el CLI

```powershell
docker compose run --rm --service-ports nosqltool
```

El contenedor montara el Swagger en `/tmp/swagger/swagger.json` y abrira el
menu interactivo de NoSQLTool.

Si la API objetivo esta ejecutandose en tu maquina host, usa esta forma de URL
base cuando el CLI la solicite:

```text
http://host.docker.internal:<puerto>
```

Ejemplo:

```text
http://host.docker.internal:3000
```

## Levantar con Docker directo

Si prefieres no usar Compose, puedes construir y ejecutar la imagen manualmente:

```powershell
$env:SWAGGER_PATH = (Resolve-Path ".\ruta\al\swagger.json").Path

docker build --tag nosqltool:local .

docker run --rm -it `
  -p 127.0.0.1:8000:8000 `
  -v "${env:SWAGGER_PATH}:/tmp/swagger/swagger.json:ro" `
  nosqltool:local `
  python -m NoSQLTool.cli
```

## Ejecutar localmente con Python

Usa este modo si quieres depurar o ejecutar la herramienta fuera de Docker.

### 1. Crear entorno virtual

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Instalar dependencias

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Ejecutar el CLI

```powershell
python -m NoSQLTool.cli
```

Tambien puedes ejecutar el archivo directamente desde el IDE:

```powershell
python .\NoSQLTool\cli.py
```

## Guia de uso del CLI

Al iniciar, el menu principal muestra:

```text
1) Deteccion
2) Generar reporte (Deteccion)
3) Explotacion
4) Generar reporte (Explotacion)
5) Salir
```

### 1. Ejecutar deteccion

Selecciona `Deteccion` y completa los datos solicitados:

- Motor de base de datos: `Neo4j`, `CouchDB` o `MongoDB`.
- Ruta del directorio Swagger: por defecto `/tmp/swagger` en Docker.
- Nombre del archivo Swagger: por defecto `swagger.json`.
- URL base de la API objetivo.
- Endpoint especifico, si quieres limitar la prueba a una ruta concreta.
- Concurrencia de pruebas.
- Tipo de deteccion: `boolean_based`, `error_based`, `time_based` o todos.

Al finalizar, el CLI imprime un resumen con los endpoints, parametros y
payloads que generaron comportamiento sospechoso.

### 2. Generar reporte de deteccion

Despues de ejecutar una deteccion, selecciona `Generar reporte (Deteccion)`.
Puedes elegir:

- `JSON`
- `TXT`

El reporte no se escribe en disco. Se publica temporalmente en memoria y el CLI
mostrara una URL similar a:

```text
http://localhost:8000/reports/<id>
```

Tambien se expone una version raw:

```text
http://localhost:8000/reports/<id>/raw
```

El reporte estara disponible solo mientras el proceso del CLI siga activo.

### 3. Ejecutar explotacion

La opcion `Explotacion` usa los resultados vulnerables encontrados en la ultima
deteccion. Si no hay resultados en memoria, primero debes ejecutar una
deteccion.

Durante esta fase, la herramienta intenta extraer evidencia adicional desde los
puntos vulnerables y muestra un resumen por endpoint.

### 4. Generar reporte de explotacion

Despues de una explotacion exitosa, selecciona `Generar reporte (Explotacion)`
y elige el formato `JSON` o `TXT`.

## Ejecucion por variables de entorno

Tambien puedes ejecutar el motor principal sin el menu interactivo. Este modo es
util para pruebas repetibles o automatizacion.

```powershell
$env:SWAGGER_PATH = (Resolve-Path ".\ruta\al\swagger.json").Path
$env:BASE_URL = "http://localhost:3000"
$env:ENGINE = "mongo"
$env:MODE = "detection"
$env:PAYLOAD_FILE = "boolean_based"
$env:TARGET_PATH = "/api/users"
$env:MAX_WORKERS = "10"

python -m NoSQLTool.NoSQLTool
```

`PAYLOAD_FILE` y `TARGET_PATH` son opcionales. Si no defines `PAYLOAD_FILE`, se
cargara el archivo general del motor y modo seleccionados.

## Variables de configuracion

| Variable | Requerida | Descripcion |
| --- | --- | --- |
| `SWAGGER_PATH` | Si | Ruta completa al archivo Swagger/OpenAPI. |
| `BASE_URL` | Si en modo directo | URL base de la API objetivo. |
| `ENGINE` | Si en modo directo | Motor NoSQL: `mongo`, `couchdb` o `neo4j`. |
| `MODE` | Si en modo directo | Modo de ejecucion. Actualmente se usa `detection`. |
| `PAYLOAD_FILE` | No | Familia de payloads: `boolean_based`, `error_based` o `time_based`. |
| `TARGET_PATH` | No | Endpoint especifico que se quiere probar. |
| `MAX_WORKERS` | No | Numero de pruebas concurrentes. Por defecto `10`. |
| `PAYLOAD_BASE_URL` | No | URL base desde donde se descargan los payloads. |
| `CACHE_DIR` | No | Directorio local de cache de payloads. |
| `REPORT_HOST` | No | Host del servidor de reportes. Por defecto `0.0.0.0`. |
| `REPORT_PORT` | No | Puerto interno del servidor de reportes. Por defecto `8000`. |
| `REPORT_PUBLIC_URL` | No | URL publica mostrada por el CLI para acceder a reportes. |
| `REQUEST_TIMEOUT` | No | Timeout de peticiones hacia la API objetivo. Por defecto `15`. |
| `FETCH_TIMEOUT` | No | Timeout para descargar payloads. Por defecto `5`. |

## Payloads

Por defecto, NoSQLTool descarga los payloads desde el repositorio configurado en
`PAYLOAD_BASE_URL`. La estructura esperada es:

```text
<PAYLOAD_BASE_URL>/<engine>/<mode>.json
<PAYLOAD_BASE_URL>/<engine>/<mode>/<payload_file>.json
```

Ejemplos:

```text
mongo/detection.json
mongo/detection/boolean_based.json
couchdb/detection/error_based.json
neo4j/detection/time_based.json
```

Si trabajas sin internet o con un repositorio propio de payloads, publica esos
archivos en una URL accesible y define:

```powershell
$env:PAYLOAD_BASE_URL = "http://localhost:8080/payloads"
```

## Reportes

Los reportes se mantienen en memoria y se eliminan cuando termina el proceso.
Esto evita dejar evidencia sensible escrita en disco por accidente.

En Docker Compose, el puerto de reportes se publica en:

```text
http://localhost:8000
```

Si cambias `REPORT_PORT`, ajusta tambien el mapeo de puertos en
`compose.yaml`.

## Estructura del proyecto

```text
NoSQLTool/
  cli.py                  # Menu interactivo
  NoSQLTool.py            # Ejecucion principal por variables de entorno
  config.py               # Configuracion general
  detection/              # Modulos de deteccion por motor
  exploitation/           # Modulos de explotacion por motor
  payloads/               # Resolucion, descarga y cache de payloads
  reporting/              # Generacion y servidor de reportes
Dockerfile
compose.yaml
requirements.txt
```

## Solucion de problemas

### No se encuentra el Swagger

Verifica que `SWAGGER_PATH` apunte a un archivo existente:

```powershell
Test-Path $env:SWAGGER_PATH
```

Con Docker Compose, recuerda definir `SWAGGER_PATH` antes de ejecutar el
servicio.

### La API no responde desde Docker

Si la API corre en tu maquina host, no uses `localhost` dentro del contenedor.
Usa:

```text
http://host.docker.internal:<puerto>
```

### No se descargan los payloads

Revisa conectividad hacia `PAYLOAD_BASE_URL` o configura una URL propia.
Tambien valida que el contenedor tenga permiso de escritura en `CACHE_DIR`.

### El puerto de reportes esta ocupado

Cambia el puerto publicado en `compose.yaml` o libera el puerto `8000` antes de
iniciar la herramienta.

### No aparecen vulnerabilidades

Confirma que el Swagger describe los endpoints correctos, que `BASE_URL` apunta
a la API esperada y que el endpoint objetivo, si fue definido, coincide con la
ruta documentada.
