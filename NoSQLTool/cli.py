import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .detection.detection import TestResult
from .exploitation.exploitation import ExploitationResult, run_exploitation
from .NoSQLTool import ScanConfig, run_scan
from .reporting import InMemoryReportRepository, ReportHttpServer, ReportService

ENGINE_OPTIONS: Dict[str, Tuple[str, str]] = {
    "1": ("neo4j", "Neo4j"),
    "2": ("couchdb", "CouchDB"),
    "3": ("mongo", "Mongo"),
}

DETECTION_OPTIONS: Dict[str, Optional[str]] = {
    "1": "boolean_based",
    "2": "error_based",
    "3": "time_based",
    "4": None,
}

def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _prompt_non_empty(prompt: str, default: Optional[str] = None) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        if default is not None:
            return default
        print("El valor no puede estar vacio.")


def _prompt_optional(prompt: str, default: Optional[str] = None) -> Optional[str]:
    value = input(prompt).strip()
    if value:
        return value
    return default


def _prompt_choice(prompt: str, choices: Dict[str, object]) -> str:
    valid = set(choices.keys())
    while True:
        value = input(prompt).strip()
        if value in valid:
            return value
        print(f"Opcion invalida. Opciones permitidas: {', '.join(sorted(valid))}")


def _get_report_port() -> int:
    raw_port = os.getenv("REPORT_PORT", "8000")
    try:
        return int(raw_port)
    except ValueError:
        print(f"REPORT_PORT invalido ({raw_port}). Se utilizara 8000.")
        return 8000


def _build_report_server(repository: InMemoryReportRepository) -> ReportHttpServer:
    port = _get_report_port()
    return ReportHttpServer(
        repository=repository,
        host=os.getenv("REPORT_HOST", "0.0.0.0"),
        port=port,
        public_url=os.getenv("REPORT_PUBLIC_URL", f"http://localhost:{port}"),
    )


def _prompt_report_format(title: str) -> str:
    print(f"\n{title}")
    print("  1) JSON")
    print("  2) TXT")
    format_choice = _prompt_choice("Selecciona formato [1-2]: ", {"1": "json", "2": "txt"})
    return "json" if format_choice == "1" else "txt"


def _publish_report(report_server: ReportHttpServer, report) -> None:
    report_server.start()
    report_url = report_server.url_for(report)
    raw_url = f"{report_url}/raw"

    print(f"\nReporte disponible en: {report_url}")
    print(f"Contenido raw: {raw_url}")
    print("No se guardo en disco; estara en memoria mientras el CLI siga activo.")
    input("\nPresiona Enter para continuar...")


def _build_swagger_path() -> str:
    print("\nConfiguracion de Swagger")
    swagger_dir = _prompt_non_empty("Ruta del directorio Swagger [/tmp/swagger]: ", "/tmp/swagger")
    swagger_filename = _prompt_non_empty("Nombre del archivo Swagger [swagger.json]: ", "swagger.json")

    swagger_path = Path(swagger_dir) / swagger_filename
    if not swagger_path.exists():
        raise FileNotFoundError(
            f"No se encontro el archivo Swagger en: {swagger_path}. "
            "Asegura que el volumen este montado correctamente en Docker."
        )

    return str(swagger_path)


def _configure_engine_specific(engine: str) -> None:
    print("\nConfiguraciones por base de datos")

    print("- No hay validaciones previas obligatorias por motor.")


def _collect_detection_config(engine: str) -> Dict[str, object]:
    print("\n=== Configuraciones necesarias para deteccion ===")
    swagger_path = _build_swagger_path()
    base_url = _prompt_non_empty(
        "Ruta base de la API [http://host.docker.internal:3000]: ",
        os.getenv("BASE_URL", "http://host.docker.internal:3000"),
    )
    target_path = _prompt_optional("Ruta especifica del endpoint (opcional, ej: /users): ", None)
    max_workers_raw = _prompt_non_empty("Concurrencia de pruebas [10]: ", "10")

    try:
        max_workers = max(1, int(max_workers_raw))
    except ValueError:
        print("Valor invalido de concurrencia. Se utilizara 10.")
        max_workers = 10

    _configure_engine_specific(engine)

    os.environ["SWAGGER_PATH"] = swagger_path
    os.environ["BASE_URL"] = base_url
    os.environ["ENGINE"] = engine
    os.environ["MODE"] = "detection"
    os.environ["MAX_WORKERS"] = str(max_workers)
    if target_path:
        os.environ["TARGET_PATH"] = target_path
    else:
        os.environ.pop("TARGET_PATH", None)

    return {
        "swagger_path": swagger_path,
        "base_url": base_url,
        "target_path": target_path,
        "max_workers": max_workers,
    }


def _prompt_detection_type() -> Optional[str]:
    print("\nTipos de deteccion disponibles")
    print("  1) boolean_based")
    print("  2) error_based")
    print("  3) time_based")
    print("  4) todos")

    selected = _prompt_choice("Selecciona tipo de deteccion [1-4]: ", DETECTION_OPTIONS)
    return DETECTION_OPTIONS[selected]


def _print_summary(summary: Dict[str, Dict[str, List[str]]]) -> None:
    if not summary:
        print("\nNo se detectaron endpoints vulnerables con la configuracion actual.")
        return

    print("\nResumen de posibles endpoints vulnerables:\n")
    for endpoint_key, params in summary.items():
        print(f"[+] Endpoint: {endpoint_key}")
        for param_name, payloads in params.items():
            print(f"    Parametro vulnerable: {param_name}")
            print("    Payloads que provocaron comportamiento sospechoso:")
            for payload in payloads:
                print(f"      - {payload}")


def _run_detection_flow() -> Tuple[Optional[List[TestResult]], Optional[Dict[str, Dict[str, List[str]]]], Optional[dict]]:
    _clear_screen()
    print("=== Modulo de Deteccion NoSQL ===")
    print("\nSelecciona la base de datos objetivo")
    print("  1) Neo4j")
    print("  2) CouchDB")
    print("  3) MongoDB")

    engine_choice = _prompt_choice("Base de datos [1-3]: ", ENGINE_OPTIONS)
    engine, engine_label = ENGINE_OPTIONS[engine_choice]
    config = _collect_detection_config(engine)
    swagger_path = str(config["swagger_path"])
    base_url = str(config["base_url"])
    target_path = config["target_path"]
    max_workers = int(config["max_workers"])

    detection_type = _prompt_detection_type()
    if detection_type:
        os.environ["PAYLOAD_FILE"] = detection_type
    else:
        os.environ.pop("PAYLOAD_FILE", None)

    print("\nEjecutando deteccion...")
    print(f"Motor: {engine_label}")
    print(f"Swagger: {swagger_path}")
    print(f"API: {base_url}")
    if target_path:
        print(f"Endpoint objetivo: {target_path}")
    print(f"Tipo de deteccion: {detection_type or 'todos'}")
    print(f"Concurrencia: {max_workers}")

    run_result = run_scan(
        ScanConfig(
            swagger_path=swagger_path,
            base_url=base_url,
            engine=engine,
            mode="detection",
            payload_file=detection_type,
            target_path=target_path,
            max_workers=max_workers,
        )
    )

    if run_result.message:
        print(f"\n{run_result.message}")

    if not run_result.executed:
        return None, None, None

    results = run_result.results
    summary = run_result.summary
    _print_summary(summary)

    metadata = {
        "engine": engine,
        "engine_label": engine_label,
        "swagger_path": swagger_path,
        "base_url": base_url,
        "target_path": target_path,
        "detection_type": detection_type or "all",
        "executed_at": datetime.now().isoformat(timespec="seconds"),
        "total_tests": len(results),
        "total_findings": sum(len(payloads) for endpoint in summary.values() for payloads in endpoint.values()),
    }

    return results, summary, metadata


def _generate_report_flow(
    last_results: Optional[List[TestResult]],
    last_summary: Optional[Dict[str, Dict[str, List[str]]]],
    last_metadata: Optional[dict],
    report_service: ReportService,
    report_server: ReportHttpServer,
) -> None:
    _clear_screen()
    print("=== Generador de Reportes ===")

    if last_results is None or last_summary is None or last_metadata is None:
        print("\nNo hay resultados de deteccion en memoria.")
        print("Ejecuta primero una deteccion para poder generar el reporte.")
        input("\nPresiona Enter para continuar...")
        return

    format_name = _prompt_report_format("Formato de reporte")
    report = report_service.create_detection_report(
        format_name,
        last_results,
        last_summary,
        last_metadata,
    )
    _publish_report(report_server, report)


def _run_exploitation_flow(
    last_results: Optional[List[TestResult]],
    last_metadata: Optional[dict],
    base_url: Optional[str] = None,
) -> Optional[List[ExploitationResult]]:
    """Ejecuta explotación en endpoints vulnerables identificados."""
    _clear_screen()
    print("=== Modulo de Explotacion ===")

    if last_results is None or last_metadata is None:
        print("\nNo hay resultados de deteccion en memoria.")
        print("Ejecuta primero una deteccion para poder explotar.")
        input("\nPresiona Enter para continuar...")
        return None

    if not base_url:
        base_url = _prompt_non_empty(
            f"URL base de la API [{last_metadata.get('base_url', 'http://localhost:3000')}]: ",
            last_metadata.get('base_url', 'http://localhost:3000')
        )

    # Filtrar solo resultados vulnerables
    vulnerable_results = [r for r in last_results if r.vulnerable]
    
    if not vulnerable_results:
        print("\nNo hay endpoints vulnerables en los resultados.")
        input("\nPresiona Enter para continuar...")
        return None

    print(f"\nEncontrados {len(vulnerable_results)} puntos vulnerables.")
    print("Iniciando explotacion...")
    print("(Esto puede tomar varios minutos)")

    try:
        exploitation_results = run_exploitation(
            vulnerable_results,
            base_url=base_url,
            engine=last_metadata.get('engine', 'neo4j'),
            max_workers=5,
        )

        if exploitation_results:
            print(f"\n✓ Explotacion completada")
            print(f"✓ Información extraída de {len(exploitation_results)} puntos")
            
            # Mostrar resumen de resultados
            for expl_result in exploitation_results:
                print(f"\n[+] {expl_result.endpoint.method} {expl_result.endpoint.path}")
                print(f"    Parámetro: {expl_result.param_name}")
                print(f"    Tipo: {expl_result.exploitation_type}")
                print(f"    Confianza: {expl_result.metrics.confidence:.1%}")
                print(f"    Datos: {len(expl_result.metrics.data_extracted)} caracteres extraídos")
        else:
            print("\nNo se pudo extraer información de los endpoints vulnerables.")

        input("\nPresiona Enter para continuar...")
        return exploitation_results

    except Exception as exc:
        print(f"\nError durante la explotacion: {exc}")
        input("\nPresiona Enter para continuar...")
        return None


def _generate_exploitation_report(
    exploitation_results: Optional[List[ExploitationResult]],
    detection_metadata: Optional[dict],
    report_service: ReportService,
    report_server: ReportHttpServer,
) -> None:
    """Genera reporte de explotación con evidencia detallada."""
    _clear_screen()
    print("=== Generador de Reportes - Explotacion ===")

    if exploitation_results is None or not exploitation_results:
        print("\nNo hay resultados de explotacion.")
        input("\nPresiona Enter para continuar...")
        return

    format_name = _prompt_report_format("Formato de reporte")
    report = report_service.create_exploitation_report(
        format_name,
        exploitation_results,
        detection_metadata,
    )
    _publish_report(report_server, report)


def run_cli() -> None:
    last_results: Optional[List[TestResult]] = None
    last_summary: Optional[Dict[str, Dict[str, List[str]]]] = None
    last_metadata: Optional[dict] = None
    last_exploitation_results: Optional[List[ExploitationResult]] = None
    last_base_url: Optional[str] = None
    report_repository = InMemoryReportRepository()
    report_service = ReportService(report_repository)
    report_server = _build_report_server(report_repository)

    while True:
        _clear_screen()
        print("=== NoSQLTool CLI ===")
        print("  1) Deteccion")
        print("  2) Generar reporte (Deteccion)")
        print("  3) Explotacion")
        print("  4) Generar reporte (Explotacion)")
        print("  5) Salir")

        option = _prompt_choice("Selecciona una opcion [1-5]: ", {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5})

        if option == "1":
            try:
                results, summary, metadata = _run_detection_flow()
                if results is not None and summary is not None and metadata is not None:
                    last_results = results
                    last_summary = summary
                    last_metadata = metadata
                    last_base_url = metadata.get('base_url')
            except Exception as exc:
                print(f"\nError durante la deteccion: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "2":
            try:
                _generate_report_flow(
                    last_results,
                    last_summary,
                    last_metadata,
                    report_service,
                    report_server,
                )
            except Exception as exc:
                print(f"\nError al generar el reporte: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "3":
            try:
                expl_results = _run_exploitation_flow(last_results, last_metadata, last_base_url)
                if expl_results is not None:
                    last_exploitation_results = expl_results
            except Exception as exc:
                print(f"\nError durante la explotacion: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "4":
            try:
                _generate_exploitation_report(
                    last_exploitation_results,
                    last_metadata,
                    report_service,
                    report_server,
                )
            except Exception as exc:
                print(f"\nError al generar el reporte de explotacion: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "5":
            print("\nSaliendo de NoSQLTool CLI.")
            break


def main() -> None:
    run_cli()


if __name__ == "__main__":
    main()
