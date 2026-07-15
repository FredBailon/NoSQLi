FROM python:3.11-slim-bookworm

ARG APP_UID=10001
ARG APP_GID=10001

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SWAGGER_DIR=/tmp/swagger \
    SWAGGER_FILENAME=swagger.json \
    CACHE_DIR=/var/cache/nosqltool/payloads \
    REPORT_HOST=0.0.0.0 \
    REPORT_PORT=8000

# Instalar dependencias antes de copiar el codigo conserva la cache de capas.
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --requirement requirements.txt

# El proceso no necesita privilegios de root. Los identificadores fijos facilitan
# aplicar la misma identidad desde Docker Compose y plataformas de orquestacion.
RUN groupadd --gid "${APP_GID}" nosqltool \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" \
        --no-create-home --shell /usr/sbin/nologin nosqltool \
    && install -d --owner="${APP_UID}" --group="${APP_GID}" --mode=0700 \
        /tmp/swagger /var/cache/nosqltool \
    && install --owner="${APP_UID}" --group="${APP_GID}" --mode=0400 \
        /dev/null /tmp/swagger/swagger.json

COPY --chown=${APP_UID}:${APP_GID} NoSQLTool ./NoSQLTool

USER ${APP_UID}:${APP_GID}

EXPOSE 8000

CMD ["python", "-m", "NoSQLTool.NoSQLTool"]
