# NoSQLTool
Avances Tesis

## Ejecucion con servidor de reportes

Los reportes se publican en memoria desde el contenedor y no se escriben en una
carpeta local. Expone el puerto del servidor y monta solo el `swagger.json`:

```powershell
docker rmi nosqltool
docker build -t nosqltool .
docker run -it --rm -p 127.0.0.1:8000:8000 -v "C:\Users\hmpla\OneDrive\Documentos\API_MongoDB\backend\src\swagger.json:/tmp/swagger/swagger.json:ro" nosqltool python -m NoSQLTool.cli
```

Al elegir `Generar reporte`, el CLI mostrara una URL como:

```text
http://localhost:8000/reports/<id>
```

El reporte estara disponible solo mientras el proceso del CLI siga activo.
