import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .detection.detection import TestResult
from .exploitation.exploitation import ExploitationResult, run_exploitation
from .main import ScanConfig, run_scan

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

REPORT_DIR_DEFAULT = "/tmp/reports"


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


def _build_flag_based_report(
    last_results: List[TestResult],
    last_summary: Dict[str, Dict[str, List[str]]],
) -> Dict[str, object]:
    """Construye un reporte basado en banderas (flags).
    
    Agrupa endpoints vulnerables por tipo de detección, mostrando de forma
    simplificada qué endpoints son vulnerables a qué tipo de ataque.
    """
    # Estructura: endpoint -> set de tipos de detección vulnerables
    vulnerable_endpoints: Dict[str, Dict[str, object]] = {}
    
    # Procesar resultados vulnerables
    for result in last_results:
        if not result.vulnerable:
            continue
            
        endpoint_key = f"{result.endpoint.method} {result.endpoint.path}"
        
        if endpoint_key not in vulnerable_endpoints:
            vulnerable_endpoints[endpoint_key] = {
                "endpoint": endpoint_key,
                "vulnerabilities": set(),
                "vulnerable_parameters": {}
            }
        
        # Agregar tipo de detección
        vuln_entry = vulnerable_endpoints[endpoint_key]
        vuln_entry["vulnerabilities"].add(result.payload_source)
        
        # Rastrear parámetros por tipo de detección
        if result.param_name not in vuln_entry["vulnerable_parameters"]:
            vuln_entry["vulnerable_parameters"][result.param_name] = set()
        vuln_entry["vulnerable_parameters"][result.param_name].add(result.payload_source)
    
    # Convertir sets a listas ordenadas para JSON
    flag_report = {
        "vulnerable_endpoints": []
    }
    
    for endpoint_key in sorted(vulnerable_endpoints.keys()):
        entry = vulnerable_endpoints[endpoint_key]
        flag_report["vulnerable_endpoints"].append({
            "endpoint": entry["endpoint"],
            "vulnerabilities": sorted(list(entry["vulnerabilities"])),
            "vulnerable_parameters": {
                param: sorted(list(detections))
                for param, detections in entry["vulnerable_parameters"].items()
            }
        })
    
    return flag_report


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
) -> None:
    _clear_screen()
    print("=== Generador de Reportes ===")

    if last_results is None or last_summary is None or last_metadata is None:
        print("\nNo hay resultados de deteccion en memoria.")
        print("Ejecuta primero una deteccion para poder generar el reporte.")
        return

    print("\nFormato de reporte")
    print("  1) JSON")
    print("  2) TXT")
    format_choice = _prompt_choice("Selecciona formato [1-2]: ", {"1": "json", "2": "txt"})

    report_dir = Path(_prompt_non_empty(f"Directorio de salida [{REPORT_DIR_DEFAULT}]: ", REPORT_DIR_DEFAULT))
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ====== REPORTE POR BANDERAS ======
    flag_report = _build_flag_based_report(last_results, last_summary)
    
    if format_choice == "1":
        report_path = report_dir / f"nosql_report_{timestamp}.json"
        report_payload = {
            "metadata": last_metadata,
            "flags_report": flag_report
        }
        report_path.write_text(json.dumps(report_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        report_path = report_dir / f"nosql_report_{timestamp}.txt"
        lines: List[str] = []
        lines.append("REPORTE DE DETECCION NOSQL - BANDERAS (FLAGS)")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Fecha: {last_metadata['executed_at']}")
        lines.append(f"Motor: {last_metadata['engine_label']}")
        lines.append(f"API: {last_metadata['base_url']}")
        lines.append(f"Tipo de deteccion: {last_metadata['detection_type']}")
        lines.append("")

        if not flag_report["vulnerable_endpoints"]:
            lines.append("No se detectaron endpoints vulnerables.")
        else:
            lines.append(f"Total endpoints vulnerables: {len(flag_report['vulnerable_endpoints'])}")
            lines.append("")
            
            for endpoint_entry in flag_report["vulnerable_endpoints"]:
                lines.append(f"[*] {endpoint_entry['endpoint']}")
                lines.append(f"    Vulnerable a: {', '.join(endpoint_entry['vulnerabilities'])}")
                
                if endpoint_entry['vulnerable_parameters']:
                    lines.append("    Parámetros afectados:")
                    for param, vuln_types in endpoint_entry['vulnerable_parameters'].items():
                        lines.append(f"      - {param}: {', '.join(vuln_types)}")
                lines.append("")

        report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"\nReporte generado en: {report_path}")


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
) -> None:
    """Genera reporte de explotación con evidencia detallada."""
    _clear_screen()
    print("=== Generador de Reportes - Explotacion ===")

    if exploitation_results is None or not exploitation_results:
        print("\nNo hay resultados de explotacion.")
        return

    print("\nFormato de reporte")
    print("  1) JSON (Detallado con evidencia)")
    print("  2) TXT (Legible)")
    format_choice = _prompt_choice("Selecciona formato [1-2]: ", {"1": "json", "2": "txt"})

    report_dir = Path(_prompt_non_empty(f"Directorio de salida [{REPORT_DIR_DEFAULT}]: ", REPORT_DIR_DEFAULT))
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_choice == "1":
        report_path = report_dir / f"nosql_exploitation_{timestamp}.json"
        
        report_data = {
            "metadata": {
                **detection_metadata,
                "exploitation_timestamp": timestamp,
                "total_exploited": len(exploitation_results),
            },
            "exploitation_results": [
                {
                    "endpoint": f"{r.endpoint.method} {r.endpoint.path}",
                    "parameter": r.param_name,
                    "exploitation_type": r.exploitation_type,
                    "successful": r.successful,
                    "metrics": {
                        "extraction_type": r.metrics.extraction_type,
                        "data_extracted": r.metrics.data_extracted[:200],  # Limitar tamaño
                        "data_length": r.metrics.data_length,
                        "confidence": round(r.metrics.confidence, 3),
                        "validity_score": round(r.metrics.validity_score, 3),
                        "attempts": r.metrics.attempts,
                        "elapsed_time": round(r.metrics.elapsed_time, 2),
                        "extracted_fields": r.metrics.extracted_fields,
                        "confirmation_signals": r.metrics.confirmation_signals,
                    },
                    "evidence": [
                        {
                            "baseline": {
                                "status_code": e.baseline_response.status_code,
                                "response_size": e.baseline_response.response_size,
                                "elapsed_time": round(e.baseline_response.elapsed_time, 3),
                                "snippet": e.baseline_response.snippet[:200],
                            },
                            "injected": {
                                "status_code": e.injected_response.status_code,
                                "response_size": e.injected_response.response_size,
                                "elapsed_time": round(e.injected_response.elapsed_time, 3),
                                "snippet": e.injected_response.snippet[:200],
                            },
                            "payload": e.payload_used,
                            "injection_point": e.injection_point,
                            "difference": e.difference_description,
                        }
                        for e in r.metrics.evidence_list
                    ],
                    "data_samples": r.data_samples[:3],
                    "description": r.description,
                }
                for r in exploitation_results
            ]
        }
        
        report_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
    
    else:
        report_path = report_dir / f"nosql_exploitation_{timestamp}.txt"
        lines: List[str] = []
        
        lines.append("REPORTE DE EXPLOTACION NOSQL - EVIDENCIA DETALLADA")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Fecha: {detection_metadata['executed_at']}")
        lines.append(f"Motor: {detection_metadata['engine_label']}")
        lines.append(f"API: {detection_metadata['base_url']}")
        lines.append(f"Total de endpoints explotados: {len(exploitation_results)}")
        lines.append(f"Timestamp de explotación: {timestamp}")
        lines.append("")
        
        for idx, expl_result in enumerate(exploitation_results, 1):
            lines.append(f"\n{'=' * 80}")
            lines.append(f"[{idx}] {expl_result.endpoint.method} {expl_result.endpoint.path}")
            lines.append(f"{'=' * 80}")
            lines.append("")
            
            lines.append(f"Parámetro objetivo: {expl_result.param_name}")
            lines.append(f"Tipo de explotación: {expl_result.exploitation_type.upper()}")
            lines.append(f"Estado: {'✓ EXITOSA' if expl_result.successful else '✗ FALLIDA'}")
            lines.append("")
            
            # Métricas principales
            lines.append("MÉTRICAS DE EXPLOTACIÓN:")
            lines.append(f"  • Confianza: {expl_result.metrics.confidence:.1%}")
            lines.append(f"  • Validez de datos: {expl_result.metrics.validity_score:.1%}")
            lines.append(f"  • Datos extraídos: {expl_result.metrics.data_length} caracteres")
            lines.append(f"  • Intentos realizados: {expl_result.metrics.attempts}")
            lines.append(f"  • Tiempo total: {expl_result.metrics.elapsed_time:.2f} segundos")
            if expl_result.metrics.confirmation_signals:
                signal_text = ", ".join(
                    f"{name}={count}"
                    for name, count in expl_result.metrics.confirmation_signals.items()
                )
                lines.append(f"  • Señales de confirmación: {signal_text}")
            lines.append("")
            
            # Evidencia detallada
            if expl_result.metrics.evidence_list:
                lines.append("EVIDENCIA TÉCNICA:")
                for evi_idx, evidence in enumerate(expl_result.metrics.evidence_list[:3], 1):
                    lines.append(f"\n  Intento #{evi_idx}:")
                    lines.append(f"  ├─ Payload: {evidence.payload_used[:80]}")
                    lines.append(f"  ├─ Punto de inyección: {evidence.injection_point}")
                    lines.append(f"  │")
                    lines.append(f"  ├─ RESPUESTA BASE (sin inyección):")
                    lines.append(f"  │  • HTTP Status: {evidence.baseline_response.status_code}")
                    lines.append(f"  │  • Tamaño: {evidence.baseline_response.response_size} bytes")
                    lines.append(f"  │  • Tiempo: {evidence.baseline_response.elapsed_time:.3f} segundos")
                    lines.append(f"  │  • Snippet: {evidence.baseline_response.snippet[:100]}...")
                    lines.append(f"  │")
                    lines.append(f"  ├─ RESPUESTA INYECTADA:")
                    lines.append(f"  │  • HTTP Status: {evidence.injected_response.status_code}")
                    lines.append(f"  │  • Tamaño: {evidence.injected_response.response_size} bytes")
                    lines.append(f"  │  • Tiempo: {evidence.injected_response.elapsed_time:.3f} segundos")
                    lines.append(f"  │  • Snippet: {evidence.injected_response.snippet[:100]}...")
                    lines.append(f"  │")
                    lines.append(f"  └─ ANÁLISIS:")
                    lines.append(f"     {evidence.difference_description}")
                lines.append("")
            
            # Datos extraídos
            if expl_result.metrics.data_extracted:
                lines.append("DATOS EXTRAÍDOS:")
                extracted = expl_result.metrics.data_extracted
                display = extracted[:150] + "..." if len(extracted) > 150 else extracted
                lines.append(f"  {display}")
                lines.append("")
            
            # Descripción
            lines.append(f"DESCRIPCIÓN: {expl_result.description}")
            lines.append("")
        
        report_path.write_text("\n".join(lines), encoding="utf-8")
    
    print(f"\n✓ Reporte generado en: {report_path}")


def run_cli() -> None:
    last_results: Optional[List[TestResult]] = None
    last_summary: Optional[Dict[str, Dict[str, List[str]]]] = None
    last_metadata: Optional[dict] = None
    last_exploitation_results: Optional[List[ExploitationResult]] = None
    last_base_url: Optional[str] = None

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
                _generate_report_flow(last_results, last_summary, last_metadata)
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
                _generate_exploitation_report(last_exploitation_results, last_metadata)
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
