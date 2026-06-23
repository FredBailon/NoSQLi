FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar codigo fuente
COPY NoSQLTool ./NoSQLTool

# Crear carpeta temporal para subir swagger.json con permisos restringidos
RUN mkdir -p /tmp/swagger \
    && chmod 700 /tmp/swagger

ENV PYTHONUNBUFFERED=1 \
    SWAGGER_DIR=/tmp/swagger \
    SWAGGER_FILENAME=swagger.json \
    REPORT_HOST=0.0.0.0 \
    REPORT_PORT=8000

EXPOSE 8000

# Comando por defecto: ejecutar el main del paquete
CMD ["python", "-m", "NoSQLTool.main"]
