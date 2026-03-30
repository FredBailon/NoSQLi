import os
from .detection import run_detection, summarize_vulnerabilities


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
    engine = os.getenv("ENGINE")
    mode = os.getenv("MODE", "detection")
    payload_file = os.getenv("PAYLOAD_FILE") or None

    # target_path = "/ruta" para probar solo un endpoint concreto
    target_path = os.getenv("TARGET_PATH") or None

    print("Iniciando deteccion de posibles inyecciones NoSQL...")

    if not engine:
        raise ValueError("Debe definir la variable de entorno ENGINE (mongodb/mongo, couchdb o neo4j)")

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
            print("No se detectaron posibles vulnerabilidades con los criterios actuales.")
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
