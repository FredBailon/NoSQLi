FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar codigo fuente
COPY NoSQLTool ./NoSQLTool

# Crear carpeta temporal para subir swagger.json con permisos restringidos
RUN mkdir -p /tmp/swagger /tmp/reports \
    && chmod 700 /tmp/swagger \
    && chmod 755 /tmp/reports

ENV PYTHONUNBUFFERED=1 \
    SWAGGER_DIR=/tmp/swagger \
    SWAGGER_FILENAME=swagger.json \
    REPORTS_DIR=/tmp/reports \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000

# Modo por defecto: CLI interactivo
# Para servidor de reportes: docker run -p 5000:5000 nosqltool python -m NoSQLTool --server
CMD ["python", "-m", "NoSQLTool"]
