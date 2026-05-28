import json
from typing import Dict, List, Optional, Protocol

from ..detection.detection import TestResult
from ..exploitation.exploitation import ExploitationResult


class DetectionReportRenderer(Protocol):
    format: str
    extension: str
    content_type: str

    def render(
        self,
        results: List[TestResult],
        summary: Dict[str, Dict[str, List[str]]],
        metadata: dict,
    ) -> str:
        ...


class ExploitationReportRenderer(Protocol):
    format: str
    extension: str
    content_type: str

    def render(
        self,
        results: List[ExploitationResult],
        metadata: Optional[dict],
    ) -> str:
        ...


def build_flag_based_report(
    results: List[TestResult],
    summary: Dict[str, Dict[str, List[str]]],
) -> Dict[str, object]:
    vulnerable_endpoints: Dict[str, Dict[str, object]] = {}

    for result in results:
        if not result.vulnerable:
            continue

        endpoint_key = f"{result.endpoint.method} {result.endpoint.path}"
        if endpoint_key not in vulnerable_endpoints:
            vulnerable_endpoints[endpoint_key] = {
                "endpoint": endpoint_key,
                "vulnerabilities": set(),
                "vulnerable_parameters": {},
            }

        entry = vulnerable_endpoints[endpoint_key]
        entry["vulnerabilities"].add(result.payload_source)

        vulnerable_parameters = entry["vulnerable_parameters"]
        if result.param_name not in vulnerable_parameters:
            vulnerable_parameters[result.param_name] = set()
        vulnerable_parameters[result.param_name].add(result.payload_source)

    report = {"vulnerable_endpoints": []}
    for endpoint_key in sorted(vulnerable_endpoints.keys()):
        entry = vulnerable_endpoints[endpoint_key]
        report["vulnerable_endpoints"].append(
            {
                "endpoint": entry["endpoint"],
                "vulnerabilities": sorted(list(entry["vulnerabilities"])),
                "vulnerable_parameters": {
                    param: sorted(list(detections))
                    for param, detections in entry["vulnerable_parameters"].items()
                },
            }
        )

    return report


class DetectionJsonRenderer:
    format = "json"
    extension = "json"
    content_type = "application/json; charset=utf-8"

    def render(
        self,
        results: List[TestResult],
        summary: Dict[str, Dict[str, List[str]]],
        metadata: dict,
    ) -> str:
        return json.dumps(
            {
                "metadata": metadata,
                "flags_report": build_flag_based_report(results, summary),
            },
            indent=2,
            ensure_ascii=False,
        )


class DetectionTextRenderer:
    format = "txt"
    extension = "txt"
    content_type = "text/plain; charset=utf-8"

    def render(
        self,
        results: List[TestResult],
        summary: Dict[str, Dict[str, List[str]]],
        metadata: dict,
    ) -> str:
        flag_report = build_flag_based_report(results, summary)
        lines: List[str] = []
        lines.append("REPORTE DE DETECCION NOSQL - BANDERAS (FLAGS)")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Fecha: {metadata['executed_at']}")
        lines.append(f"Motor: {metadata['engine_label']}")
        lines.append(f"API: {metadata['base_url']}")
        lines.append(f"Tipo de deteccion: {metadata['detection_type']}")
        lines.append("")

        if not flag_report["vulnerable_endpoints"]:
            lines.append("No se detectaron endpoints vulnerables.")
        else:
            vulnerable_endpoints = flag_report["vulnerable_endpoints"]
            lines.append(f"Total endpoints vulnerables: {len(vulnerable_endpoints)}")
            lines.append("")

            for endpoint_entry in vulnerable_endpoints:
                lines.append(f"[*] {endpoint_entry['endpoint']}")
                lines.append(
                    f"    Vulnerable a: {', '.join(endpoint_entry['vulnerabilities'])}"
                )

                if endpoint_entry["vulnerable_parameters"]:
                    lines.append("    Parametros afectados:")
                    for param, vulnerability_types in endpoint_entry[
                        "vulnerable_parameters"
                    ].items():
                        lines.append(
                            f"      - {param}: {', '.join(vulnerability_types)}"
                        )
                lines.append("")

        return "\n".join(lines)


class ExploitationJsonRenderer:
    format = "json"
    extension = "json"
    content_type = "application/json; charset=utf-8"

    def render(
        self,
        results: List[ExploitationResult],
        metadata: Optional[dict],
    ) -> str:
        safe_metadata = metadata or {}
        report_data = {
            "metadata": {
                **safe_metadata,
                "total_exploited": len(results),
            },
            "exploitation_results": [
                {
                    "endpoint": f"{result.endpoint.method} {result.endpoint.path}",
                    "parameter": result.param_name,
                    "exploitation_type": result.exploitation_type,
                    "successful": result.successful,
                    "metrics": {
                        "extraction_type": result.metrics.extraction_type,
                        "data_extracted": result.metrics.data_extracted[:200],
                        "data_length": result.metrics.data_length,
                        "confidence": round(result.metrics.confidence, 3),
                        "validity_score": round(result.metrics.validity_score, 3),
                        "attempts": result.metrics.attempts,
                        "elapsed_time": round(result.metrics.elapsed_time, 2),
                        "extracted_fields": result.metrics.extracted_fields,
                        "confirmation_signals": result.metrics.confirmation_signals,
                    },
                    "evidence": [
                        {
                            "baseline": {
                                "status_code": evidence.baseline_response.status_code,
                                "response_size": evidence.baseline_response.response_size,
                                "elapsed_time": round(
                                    evidence.baseline_response.elapsed_time,
                                    3,
                                ),
                                "snippet": evidence.baseline_response.snippet[:200],
                            },
                            "injected": {
                                "status_code": evidence.injected_response.status_code,
                                "response_size": evidence.injected_response.response_size,
                                "elapsed_time": round(
                                    evidence.injected_response.elapsed_time,
                                    3,
                                ),
                                "snippet": evidence.injected_response.snippet[:200],
                            },
                            "payload": evidence.payload_used,
                            "injection_point": evidence.injection_point,
                            "difference": evidence.difference_description,
                        }
                        for evidence in result.metrics.evidence_list
                    ],
                    "data_samples": result.data_samples[:3],
                    "description": result.description,
                }
                for result in results
            ],
        }

        return json.dumps(report_data, indent=2, ensure_ascii=False)


class ExploitationTextRenderer:
    format = "txt"
    extension = "txt"
    content_type = "text/plain; charset=utf-8"

    def render(
        self,
        results: List[ExploitationResult],
        metadata: Optional[dict],
    ) -> str:
        safe_metadata = metadata or {}
        lines: List[str] = []

        lines.append("REPORTE DE EXPLOTACION NOSQL - EVIDENCIA DETALLADA")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Fecha: {safe_metadata.get('executed_at', 'n/a')}")
        lines.append(f"Motor: {safe_metadata.get('engine_label', 'n/a')}")
        lines.append(f"API: {safe_metadata.get('base_url', 'n/a')}")
        lines.append(f"Total de endpoints explotados: {len(results)}")
        lines.append("")

        for index, result in enumerate(results, 1):
            lines.append(f"\n{'=' * 80}")
            lines.append(f"[{index}] {result.endpoint.method} {result.endpoint.path}")
            lines.append(f"{'=' * 80}")
            lines.append("")
            lines.append(f"Parametro objetivo: {result.param_name}")
            lines.append(f"Tipo de explotacion: {result.exploitation_type.upper()}")
            lines.append(f"Estado: {'EXITOSA' if result.successful else 'FALLIDA'}")
            lines.append("")
            lines.append("METRICAS DE EXPLOTACION:")
            lines.append(f"  - Confianza: {result.metrics.confidence:.1%}")
            lines.append(f"  - Validez de datos: {result.metrics.validity_score:.1%}")
            lines.append(
                f"  - Datos extraidos: {result.metrics.data_length} caracteres"
            )
            lines.append(f"  - Intentos realizados: {result.metrics.attempts}")
            lines.append(
                f"  - Tiempo total: {result.metrics.elapsed_time:.2f} segundos"
            )
            if result.metrics.confirmation_signals:
                signal_text = ", ".join(
                    f"{name}={count}"
                    for name, count in result.metrics.confirmation_signals.items()
                )
                lines.append(f"  - Senales de confirmacion: {signal_text}")
            lines.append("")

            if result.metrics.evidence_list:
                lines.append("EVIDENCIA TECNICA:")
                for evidence_index, evidence in enumerate(
                    result.metrics.evidence_list[:3],
                    1,
                ):
                    lines.append(f"\n  Intento #{evidence_index}:")
                    lines.append(f"  - Payload: {evidence.payload_used[:80]}")
                    lines.append(
                        f"  - Punto de inyeccion: {evidence.injection_point}"
                    )
                    lines.append("  - RESPUESTA BASE:")
                    lines.append(
                        f"    HTTP Status: {evidence.baseline_response.status_code}"
                    )
                    lines.append(
                        f"    Tamano: {evidence.baseline_response.response_size} bytes"
                    )
                    lines.append(
                        "    Tiempo: "
                        f"{evidence.baseline_response.elapsed_time:.3f} segundos"
                    )
                    lines.append(
                        f"    Snippet: {evidence.baseline_response.snippet[:100]}..."
                    )
                    lines.append("  - RESPUESTA INYECTADA:")
                    lines.append(
                        f"    HTTP Status: {evidence.injected_response.status_code}"
                    )
                    lines.append(
                        f"    Tamano: {evidence.injected_response.response_size} bytes"
                    )
                    lines.append(
                        "    Tiempo: "
                        f"{evidence.injected_response.elapsed_time:.3f} segundos"
                    )
                    lines.append(
                        f"    Snippet: {evidence.injected_response.snippet[:100]}..."
                    )
                    lines.append("  - ANALISIS:")
                    lines.append(f"    {evidence.difference_description}")
                lines.append("")

            if result.metrics.data_extracted:
                lines.append("DATOS EXTRAIDOS:")
                extracted = result.metrics.data_extracted
                display = extracted[:150] + "..." if len(extracted) > 150 else extracted
                lines.append(f"  {display}")
                lines.append("")

            lines.append(f"DESCRIPCION: {result.description}")
            lines.append("")

        return "\n".join(lines)
