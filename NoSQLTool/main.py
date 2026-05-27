import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .detection.detection import TestResult, run_detection, summarize_vulnerabilities


@dataclass
class ScanConfig:
    swagger_path: str
    base_url: str
    engine: str
    mode: str = "detection"
    payload_file: Optional[str] = None
    target_path: Optional[str] = None
    max_workers: int = 10
    cleanup_file: Optional[str] = None
    cleanup_dir: Optional[str] = None


@dataclass
class ScanRunResult:
    results: List[TestResult]
    summary: Dict[str, Dict[str, List[str]]]
    executed: bool
    message: Optional[str] = None


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ValueError(f"Falta variable de entorno obligatoria: {name}")
    return value.strip()


def run_scan(config: ScanConfig) -> ScanRunResult:
    try:
        results = run_detection(
            swagger_path=config.swagger_path,
            engine=config.engine,
            mode=config.mode,
            payload_file=config.payload_file,
            target_path=config.target_path,
            max_workers=config.max_workers,
            base_url_override=config.base_url,
        )

        summary = summarize_vulnerabilities(results)
        return ScanRunResult(results=results, summary=summary, executed=True, message=None)
    finally:
        if config.cleanup_file and os.path.exists(config.cleanup_file):
            try:
                os.remove(config.cleanup_file)
            except OSError:
                pass

        if config.cleanup_dir and os.path.isdir(config.cleanup_dir):
            try:
                os.rmdir(config.cleanup_dir)
            except OSError:
                pass


def main() -> None:
    # SWAGGER_PATH directo o combinacion SWAGGER_DIR + SWAGGER_FILENAME.
    # Estas variables deben venir configuradas desde el CLI o el entorno.
    swagger_path_env = os.getenv("SWAGGER_PATH")
    swagger_dir = os.getenv("SWAGGER_DIR")
    swagger_filename = os.getenv("SWAGGER_FILENAME")

    if swagger_path_env:
        swagger_path = swagger_path_env
    else:
        if not swagger_dir or not swagger_filename:
            raise ValueError(
                "Debe definir SWAGGER_PATH o ambas SWAGGER_DIR y SWAGGER_FILENAME."
            )

        # Creamos el directorio si no existe y restringimos permisos
        os.makedirs(swagger_dir, exist_ok=True)
        try:
            # 0o700 -> solo el propietario puede leer/escribir/entrar en la carpeta
            os.chmod(swagger_dir, 0o700)
        except PermissionError:
            # En algunos entornos (p.ej. volumenes montados) puede no permitirse cambiar permisos
            pass

        swagger_path = os.path.join(swagger_dir, swagger_filename)

    base_url = _required_env("BASE_URL")
    engine = _required_env("ENGINE")
    mode = _required_env("MODE")
    payload_file = os.getenv("PAYLOAD_FILE") or None

    # target_path = "/ruta" para probar solo un endpoint concreto
    target_path = os.getenv("TARGET_PATH") or None

    # Si usamos la carpeta temporal interna, la marcaremos para limpieza al final
    cleanup_file = None
    cleanup_dir = None
    if not swagger_path_env:
        cleanup_file = swagger_path
        cleanup_dir = swagger_dir

    run_result = run_scan(
        ScanConfig(
            swagger_path=swagger_path,
            base_url=base_url,
            engine=engine,
            mode=mode,
            payload_file=payload_file,
            target_path=target_path,
            max_workers=int(os.getenv("MAX_WORKERS", "10")),
            cleanup_file=cleanup_file,
            cleanup_dir=cleanup_dir,
        )
    )

    if run_result.message:
        print(run_result.message)

    if not run_result.executed:
        return

    if not run_result.summary:
        return

    print("\nResumen de posibles endpoints vulnerables:\n")
    for endpoint_key, params in run_result.summary.items():
        print(f"[+] Endpoint: {endpoint_key}")
        for param_name, payloads in params.items():
            print(f"    Parametro vulnerable: {param_name}")
            print("    Payloads que provocaron comportamiento sospechoso:")
            for p in payloads:
                print(f"        - {p}")


if __name__ == "__main__":
    main()
