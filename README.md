# NoSQLTool
Avances Tesis

## Arquitectura de deteccion modular

El modulo central de deteccion vive en [NoSQLTool/detection.py](NoSQLTool/detection.py) y concentra la logica comun reutilizable:

- Carga y parseo de `swagger.json`.
- Extraccion de endpoints y parametros (`query` y `body`).
- Generacion de casos de prueba.
- Ejecucion concurrente de pruebas HTTP.
- Analisis de comportamiento `error_based`, `time_based` y `boolean_based`.
- Resumen final de hallazgos.

Los comportamientos especificos por motor de base de datos se desacoplan en perfiles dentro de [NoSQLTool/engines](NoSQLTool/engines):

- [NoSQLTool/engines/neo4j.py](NoSQLTool/engines/neo4j.py)
- [NoSQLTool/engines/mongo.py](NoSQLTool/engines/mongo.py)
- [NoSQLTool/engines/couchdb.py](NoSQLTool/engines/couchdb.py)
- Registro central: [NoSQLTool/engines/registry.py](NoSQLTool/engines/registry.py)

Cada perfil define parametros especializados del motor:

- Keywords de error del engine.
- Marcadores de payloads booleanos y temporales.
- Umbrales de deteccion.
- Tipos de deteccion por defecto.

De esta forma, nuevos modulos de motores NoSQL pueden reutilizar el motor comun agregando solo un nuevo perfil y registrandolo, sin duplicar la logica base.
