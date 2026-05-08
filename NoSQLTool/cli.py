import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .detection import TestResult
from .exploitation import ExploitResult, run_exploitation, summarize_exploitation
from .main import ScanConfig, run_scan

ENGINE_OPTIONS: Dict[str, Tuple[str, str]] = {
    "1": ("neo4j", "Neo4j"),
    "2": ("couchdb", "CouchDB"),
    "3": ("mongodb", "MongoDB"),
}

DETECTION_OPTIONS: Dict[str, Optional[str]] = {
    "1": "boolean_based",
    "2": "error_based",
    "3": "time_based",
    "4": None,
}

REPORT_DIR_DEFAULT = "/tmp/reports"
EXPLOIT_MAX_WORKERS_DEFAULT = 5


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


def _prompt_exploitation_category() -> Optional[List[str]]:
    print("\nCategorias de explotacion disponibles")
    print("  1) boolean_based")
    print("  2) error_based")
    print("  3) time_based")
    print("  4) todos")

    selected = _prompt_choice("Selecciona categoria [1-4]: ", DETECTION_OPTIONS)
    category = DETECTION_OPTIONS[selected]
    if category:
        return [category]
    return None


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


def _print_exploitation_summary(summary: Dict[str, Dict[str, List[str]]]) -> None:
    if not summary:
        print("\nNo se confirmaron impactos durante la explotacion.")
        return

    print("\nResumen de impactos confirmados:\n")
    for endpoint_key, params in summary.items():
        print(f"[+] Endpoint: {endpoint_key}")
        for param_name, payloads in params.items():
            print(f"    Parametro explotado: {param_name}")
            print("    Payloads con impacto confirmado:")
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


def _run_exploitation_flow(
    last_results: Optional[List[TestResult]],
    last_metadata: Optional[dict],
) -> Tuple[Optional[List[ExploitResult]], Optional[Dict[str, Dict[str, List[str]]]], Optional[dict]]:
    _clear_screen()
    print("=== Modulo de Explotacion NoSQL ===")

    if not last_results or not last_metadata:
        print("\nNo hay resultados de deteccion para usar como base.")
        print("Ejecuta primero una deteccion para poder explotar.")
        return None, None, None

    payload_file = _prompt_optional("Archivo de payloads (opcional, ej: cypher.json): ", None)
    categories = _prompt_exploitation_category()
    max_workers_raw = _prompt_non_empty(
        f"Concurrencia de explotacion [{EXPLOIT_MAX_WORKERS_DEFAULT}]: ",
        str(EXPLOIT_MAX_WORKERS_DEFAULT),
    )

    try:
        max_workers = max(1, int(max_workers_raw))
    except ValueError:
        print("Valor invalido de concurrencia. Se utilizara 5.")
        max_workers = EXPLOIT_MAX_WORKERS_DEFAULT

    print("\nEjecutando explotacion...")
    print(f"Motor: {last_metadata['engine_label']}")
    print(f"Swagger: {last_metadata['swagger_path']}")
    print(f"API: {last_metadata['base_url']}")
    if last_metadata.get("target_path"):
        print(f"Endpoint objetivo: {last_metadata['target_path']}")
    print(f"Categorias: {', '.join(categories) if categories else 'todas'}")
    if payload_file:
        print(f"Payload file: {payload_file}")
    print(f"Concurrencia: {max_workers}")

    results = run_exploitation(
        swagger_path=last_metadata["swagger_path"],
        engine=last_metadata["engine"],
        payload_file=payload_file,
        categories=categories,
        target_path=last_metadata.get("target_path"),
        max_workers=max_workers,
        base_url_override=last_metadata["base_url"],
        findings=last_results,
    )

    summary = summarize_exploitation(results)
    _print_exploitation_summary(summary)

    metadata = {
        "engine": last_metadata["engine"],
        "engine_label": last_metadata["engine_label"],
        "swagger_path": last_metadata["swagger_path"],
        "base_url": last_metadata["base_url"],
        "target_path": last_metadata.get("target_path"),
        "category": ",".join(categories) if categories else "all",
        "payload_file": payload_file or "default",
        "executed_at": datetime.now().isoformat(timespec="seconds"),
        "total_tests": len(results),
        "total_confirmed": sum(len(payloads) for endpoint in summary.values() for payloads in endpoint.values()),
    }

    return results, summary, metadata


def _generate_report_flow(
    last_results: Optional[List[TestResult]],
    last_summary: Optional[Dict[str, Dict[str, List[str]]]],
    last_metadata: Optional[dict],
    last_exploit_results: Optional[List[ExploitResult]],
    last_exploit_summary: Optional[Dict[str, Dict[str, List[str]]]],
    last_exploit_metadata: Optional[dict],
) -> None:
    _clear_screen()
    print("=== Generador de Reportes ===")

    print("\nTipo de reporte")
    print("  1) Deteccion")
    print("  2) Explotacion")
    report_type = _prompt_choice("Selecciona tipo [1-2]: ", {"1": "detection", "2": "exploitation"})

    if report_type == "detection":
        if last_results is None or last_summary is None or last_metadata is None:
            print("\nNo hay resultados de deteccion en memoria.")
            print("Ejecuta primero una deteccion para poder generar el reporte.")
            return
    else:
        if last_exploit_results is None or last_exploit_summary is None or last_exploit_metadata is None:
            print("\nNo hay resultados de explotacion en memoria.")
            print("Ejecuta primero una explotacion para poder generar el reporte.")
            return

    print("\nFormato de reporte")
    print("  1) JSON")
    print("  2) TXT")
    format_choice = _prompt_choice("Selecciona formato [1-2]: ", {"1": "json", "2": "txt"})

    report_dir = Path(_prompt_non_empty(f"Directorio de salida [{REPORT_DIR_DEFAULT}]: ", REPORT_DIR_DEFAULT))
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if report_type == "detection":
        if format_choice == "1":
            report_path = report_dir / f"nosql_report_{timestamp}.json"
            report_payload = {
                "metadata": last_metadata,
                "summary": last_summary,
                "vulnerable_cases": [
                    {
                        "endpoint": f"{r.endpoint.method} {r.endpoint.path}",
                        "parameter": r.param_name,
                        "payload": r.payload,
                        "payload_source": r.payload_source,
                        "reason": r.reason,
                        "status_baseline": r.baseline.status_code,
                        "status_injected": r.injected.status_code,
                        "elapsed_baseline": r.baseline.elapsed,
                        "elapsed_injected": r.injected.elapsed,
                    }
                    for r in last_results
                    if r.vulnerable
                ],
            }
            report_path.write_text(json.dumps(report_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            report_path = report_dir / f"nosql_report_{timestamp}.txt"
            lines: List[str] = []
            lines.append("REPORTE DE DETECCION NOSQL")
            lines.append("=" * 32)
            lines.append("")
            lines.append(f"Fecha: {last_metadata['executed_at']}")
            lines.append(f"Motor: {last_metadata['engine_label']}")
            lines.append(f"API: {last_metadata['base_url']}")
            lines.append(f"Swagger: {last_metadata['swagger_path']}")
            lines.append(f"Tipo de deteccion: {last_metadata['detection_type']}")
            lines.append(f"Total de casos evaluados: {last_metadata['total_tests']}")
            lines.append("")

            if not last_summary:
                lines.append("No se detectaron hallazgos vulnerables.")
            else:
                lines.append("Hallazgos:")
                for endpoint_key, params in last_summary.items():
                    lines.append(f"- Endpoint: {endpoint_key}")
                    for param_name, payloads in params.items():
                        lines.append(f"  Parametro: {param_name}")
                        for payload in payloads:
                            lines.append(f"    * {payload}")

            report_path.write_text("\n".join(lines), encoding="utf-8")
    else:
        if format_choice == "1":
            report_path = report_dir / f"nosql_exploit_report_{timestamp}.json"
            report_payload = {
                "metadata": last_exploit_metadata,
                "summary": last_exploit_summary,
                "confirmed_cases": [
                    {
                        "endpoint": f"{r.endpoint.method} {r.endpoint.path}",
                        "parameter": r.param_name,
                        "payload_id": r.exploit.payload_id,
                        "category": r.exploit.category,
                        "verification_type": r.exploit.verification_type,
                        "reason": r.reason,
                        "status_baseline": r.baseline.status_code,
                        "status_injected": r.injected.status_code,
                        "elapsed_baseline": r.baseline.elapsed,
                        "elapsed_injected": r.injected.elapsed,
                    }
                    for r in last_exploit_results
                    if r.verified
                ],
            }
            report_path.write_text(json.dumps(report_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            report_path = report_dir / f"nosql_exploit_report_{timestamp}.txt"
            lines: List[str] = []
            lines.append("REPORTE DE EXPLOTACION NOSQL")
            lines.append("=" * 33)
            lines.append("")
            lines.append(f"Fecha: {last_exploit_metadata['executed_at']}")
            lines.append(f"Motor: {last_exploit_metadata['engine_label']}")
            lines.append(f"API: {last_exploit_metadata['base_url']}")
            lines.append(f"Swagger: {last_exploit_metadata['swagger_path']}")
            lines.append(f"Categoria: {last_exploit_metadata['category']}")
            lines.append(f"Payload file: {last_exploit_metadata['payload_file']}")
            lines.append(f"Total de casos evaluados: {last_exploit_metadata['total_tests']}")
            lines.append("")

            if not last_exploit_summary:
                lines.append("No se confirmaron impactos durante la explotacion.")
            else:
                lines.append("Impactos confirmados:")
                for endpoint_key, params in last_exploit_summary.items():
                    lines.append(f"- Endpoint: {endpoint_key}")
                    for param_name, payloads in params.items():
                        lines.append(f"  Parametro: {param_name}")
                        for payload in payloads:
                            lines.append(f"    * {payload}")

                lines.append("")
                lines.append("Detalles de casos confirmados:")
                for result in last_exploit_results:
                    if not result.verified:
                        continue
                    lines.append(f"- Endpoint: {result.endpoint.method} {result.endpoint.path}")
                    lines.append(f"  Parametro: {result.param_name}")
                    lines.append(f"  Payload ID: {result.exploit.payload_id}")
                    lines.append(f"  Categoria: {result.exploit.category}")
                    lines.append(f"  Verificacion: {result.exploit.verification_type}")
                    if result.reason:
                        lines.append(f"  Motivo: {result.reason}")
                    lines.append(
                        "  Status/tiempo: "
                        f"base={result.baseline.status_code} ({result.baseline.elapsed:.2f}s), "
                        f"inyectado={result.injected.status_code} ({result.injected.elapsed:.2f}s)"
                    )
                    lines.append("")

            report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"\nReporte generado en: {report_path}")


def run_cli() -> None:
    last_results: Optional[List[TestResult]] = None
    last_summary: Optional[Dict[str, Dict[str, List[str]]]] = None
    last_metadata: Optional[dict] = None
    last_exploit_results: Optional[List[ExploitResult]] = None
    last_exploit_summary: Optional[Dict[str, Dict[str, List[str]]]] = None
    last_exploit_metadata: Optional[dict] = None

    while True:
        _clear_screen()
        print("=== NoSQLTool CLI ===")
        print("  1) Deteccion")
        print("  2) Explotacion")
        print("  3) Generar reporte")
        print("  4) Salir")

        option = _prompt_choice("Selecciona una opcion [1-4]: ", {"1": 1, "2": 2, "3": 3, "4": 4})

        if option == "1":
            try:
                results, summary, metadata = _run_detection_flow()
                if results is not None and summary is not None and metadata is not None:
                    last_results = results
                    last_summary = summary
                    last_metadata = metadata
            except Exception as exc:
                print(f"\nError durante la deteccion: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "2":
            try:
                results, summary, metadata = _run_exploitation_flow(last_results, last_metadata)
                if results is not None and summary is not None and metadata is not None:
                    last_exploit_results = results
                    last_exploit_summary = summary
                    last_exploit_metadata = metadata
            except Exception as exc:
                print(f"\nError durante la explotacion: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "3":
            try:
                _generate_report_flow(
                    last_results,
                    last_summary,
                    last_metadata,
                    last_exploit_results,
                    last_exploit_summary,
                    last_exploit_metadata,
                )
            except Exception as exc:
                print(f"\nError al generar el reporte: {exc}")
                input("\nPresiona Enter para continuar...")

        elif option == "4":
            print("\nSaliendo de NoSQLTool CLI.")
            break


def main() -> None:
    run_cli()


if __name__ == "__main__":
    main()
