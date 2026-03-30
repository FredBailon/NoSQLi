import os
import requests
from .detection import run_detection, summarize_vulnerabilities


def _is_time_based_requested(mode: str, payload_file: str) -> bool:
    if mode.lower() != "detection":
        return False

    if not payload_file:
        # En detection sin payload_file especifico se ejecutan todos los tipos por defecto.
        return True

    return payload_file.replace(".json", "").strip().lower() == "time_based"


def _check_neo4j_apoc() -> tuple[bool, str]:
    """Valida disponibilidad de APOC en Neo4j via endpoint HTTP transactional.

    Variables de entorno utilizadas:
    - NEO4J_HTTP_URL (default: http://host.docker.internal:7474)
    - NEO4J_DATABASE (default: neo4j)
    - NEO4J_USER (default: neo4j)
    - NEO4J_PASSWORD (obligatoria para validar)
    """
    neo4j_http_url = os.getenv("NEO4J_HTTP_URL", "http://host.docker.internal:7474").rstrip("/")
    neo4j_database = os.getenv("NEO4J_DATABASE", "neo4j")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD")

    if not neo4j_password:
        return False, (
            "No se pudo validar APOC: falta NEO4J_PASSWORD para consultar Neo4j. "
            "Se omite deteccion time_based para evitar resultados no confiables."
        )

    url = f"{neo4j_http_url}/db/{neo4j_database}/tx/commit"
    payload = {
        "statements": [
            {"statement": "RETURN apoc.version() AS version"}
        ]
    }

    try:
        response = requests.post(
            url,
            json=payload,
            auth=(neo4j_user, neo4j_password),
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, (
            "No se pudo validar APOC por error de conexion a Neo4j: "
            f"{exc}. Se omite deteccion time_based."
        )

    if response.status_code != 200:
        return False, (
            "No se pudo validar APOC: Neo4j respondio con "
            f"HTTP {response.status_code}. Se omite deteccion time_based."
        )

    try:
        data = response.json()
    except ValueError:
        return False, "No se pudo validar APOC: respuesta no JSON de Neo4j. Se omite deteccion time_based."

    errors = data.get("errors") or []
    if errors:
        details = " | ".join(str(e.get("message", "")) for e in errors)
        lower_details = details.lower()

        if "unknown function" in lower_details or "apoc" in lower_details:
            return False, "APOC no esta instalado o no esta habilitado en Neo4j. Se omite deteccion time_based."

        return False, f"No se pudo validar APOC: {details}. Se omite deteccion time_based."

    results = data.get("results") or []
    if results and isinstance(results[0], dict):
        rows = results[0].get("data") or []
        if rows:
            return True, "APOC validado correctamente en Neo4j."

    return False, "No se pudo confirmar version de APOC en Neo4j. Se omite deteccion time_based."


def main() -> None:
    # Directorio temporal dentro del contenedor para subir el swagger.json
    # Por defecto: /tmp/swagger, pero puede cambiarse con SWAGGER_DIR
    swagger_path_env = os.getenv("SWAGGER_PATH")
    swagger_dir = os.getenv("SWAGGER_DIR", "/tmp/swagger")
    swagger_filename = os.getenv("SWAGGER_FILENAME", "swagger.json")

    if swagger_path_env:
        swagger_path = swagger_path_env
    else:
        # Creamos el directorio si no existe y restringimos permisos
        os.makedirs(swagger_dir, exist_ok=True)
        try:
            # 0o700 -> solo el propietario puede leer/escribir/entrar en la carpeta
            os.chmod(swagger_dir, 0o700)
        except PermissionError:
            # En algunos entornos (p.ej. volumenes montados) puede no permitirse cambiar permisos
            pass

        swagger_path = os.path.join(swagger_dir, swagger_filename)

    base_url = os.getenv("BASE_URL", "http://localhost:3000")
    engine = os.getenv("ENGINE", "neo4j")
    mode = os.getenv("MODE", "detection")
    payload_file = os.getenv("PAYLOAD_FILE", "boolean_based") or None

    # target_path = "/ruta" para probar solo un endpoint concreto
    target_path = os.getenv("TARGET_PATH") or None

    if "neo4j" in engine.lower() and _is_time_based_requested(mode, payload_file):
        apoc_ok, apoc_message = _check_neo4j_apoc()
        print(apoc_message)
        if not apoc_ok:
            return

    # Si usamos la carpeta temporal interna, la marcaremos para limpieza al final
    cleanup_file = None
    cleanup_dir = None
    if not swagger_path_env:
        cleanup_file = swagger_path
        cleanup_dir = swagger_dir

    try:
        results = run_detection(
            swagger_path=swagger_path,
            engine=engine,
            mode=mode,
            payload_file=payload_file,
            target_path=target_path,
            max_workers=10,
            base_url_override=base_url,
        )

        summary = summarize_vulnerabilities(results)

        if not summary:
            return

        print("\nResumen de posibles endpoints vulnerables:\n")
        for endpoint_key, params in summary.items():
            print(f"[+] Endpoint: {endpoint_key}")
            for param_name, payloads in params.items():
                print(f"    Parametro vulnerable: {param_name}")
                print("    Payloads que provocaron comportamiento sospechoso:")
                for p in payloads:
                    print(f"        - {p}")
    finally:
        # Eliminamos el archivo swagger y la carpeta temporal (si se crearon internamente)
        if cleanup_file and os.path.exists(cleanup_file):
            try:
                os.remove(cleanup_file)
            except OSError:
                pass

        if cleanup_dir and os.path.isdir(cleanup_dir):
            try:
                os.rmdir(cleanup_dir)
            except OSError:
                # Si la carpeta no esta vacia o es un volumen, no la forzamos
                pass


if __name__ == "__main__":
    main()
