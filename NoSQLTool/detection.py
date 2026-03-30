import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .config import (
    GITHUB_RAW_BASE, CACHE_DIR, FETCH_TIMEOUT,
)
from .payloads.resolver import resolve_payload_url
from .payloads.cache import download_if_updated
from .payloads.loader import load_payloads
from .engines import get_engine_strategy
from .base_analysis import ResponseInfo as BaseResponseInfo

# Re-export ResponseInfo para compatibilidad
ResponseInfo = BaseResponseInfo

DEFAULT_DETECTION_TYPES = ("error_based", "time_based", "boolean_based")


@dataclass
class Endpoint:
    path: str
    method: str
    query_params: List[str]
    body_fields: List[str]


@dataclass
class TestCase:
    endpoint: Endpoint
    param_name: str
    payload: str
    param_location: str  # "query" o "body"
    payload_source: str


@dataclass
class TestResult:
    endpoint: Endpoint
    param_name: str
    payload: str
    payload_source: str
    vulnerable: bool
    reason: Optional[str]
    baseline: ResponseInfo
    injected: ResponseInfo


def load_swagger_from_file(swagger_path: str) -> Dict[str, Any]:
    with open(swagger_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _build_base_url(spec: Dict[str, Any]) -> str:
    # OpenAPI 3.x style
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url")
        if isinstance(url, str) and url:
            return url.rstrip("/")

    # Swagger 2.0 style
    scheme = "https"
    schemes = spec.get("schemes")
    if isinstance(schemes, list) and schemes:
        scheme = schemes[0]

    host = spec.get("host", "")
    base_path = spec.get("basePath", "").rstrip("/")

    if host:
        return f"{scheme}://{host}{base_path}"

    raise ValueError("No se pudo determinar la URL base de la API desde el swagger.json")


def _extract_body_fields_from_schema(schema: Dict[str, Any]) -> List[str]:
    """Extrae nombres de campos de primer nivel del cuerpo JSON.

    Se centra en esquemas tipo object y propiedades simples (string, number, etc.).
    """
    fields: List[str] = []

    if not isinstance(schema, dict):
        return fields

    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        for name, prop in schema["properties"].items():
            if not isinstance(prop, dict):
                continue
            prop_type = prop.get("type")
            if prop_type in {"string", "number", "integer", "boolean", None}:
                fields.append(name)

    return fields


def extract_endpoints(spec: Dict[str, Any], target_path: Optional[str] = None) -> List[Endpoint]:
    paths = spec.get("paths", {})
    endpoints: List[Endpoint] = []

    for path, methods in paths.items():
        if target_path and path != target_path:
            continue

        if not isinstance(methods, dict):
            continue

        for method, meta in methods.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch"}:
                continue

            params = meta.get("parameters", [])
            query_params = [
                p["name"]
                for p in params
                if p.get("in") == "query" and isinstance(p.get("name"), str)
            ]

            # Swagger 2.0: cuerpo en parametros "in": "body"
            body_fields: List[str] = []
            for p in params:
                if p.get("in") == "body" and isinstance(p.get("schema"), dict):
                    body_fields.extend(_extract_body_fields_from_schema(p["schema"]))

            # OpenAPI 3.x: requestBody -> content -> application/json
            if isinstance(meta, dict) and isinstance(meta.get("requestBody"), dict):
                rb = meta["requestBody"]
                content = rb.get("content", {})
                if isinstance(content, dict):
                    json_media = None
                    if "application/json" in content:
                        json_media = content["application/json"]
                    else:
                        # tomar el primero que parezca JSON
                        for k, v in content.items():
                            if "json" in k:
                                json_media = v
                                break
                    if isinstance(json_media, dict) and isinstance(json_media.get("schema"), dict):
                        body_fields.extend(_extract_body_fields_from_schema(json_media["schema"]))

            if not query_params and not body_fields:
                continue

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    query_params=query_params,
                    body_fields=list(dict.fromkeys(body_fields)),  # sin duplicados
                )
            )

    return endpoints


def _get_engine_strategy(engine: str):
    """Obtiene la estrategia especializada para un motor NoSQL.
    
    Soporta importación dinámica de estrategias especializadas como CouchDB.
    
    Args:
        engine: Nombre del motor NoSQL
        
    Returns:
        Instancia de NoSQLEngineStrategy
    """
    engine_lower = engine.lower()
    
    # Importación dinámica de CouchDB si es necesario
    if "couchdb" in engine_lower or "couch" in engine_lower:
        from .couchdb_detection import CouchDBStrategy
        return CouchDBStrategy()
    
    # Para otros motores, usar la función estándar
    return get_engine_strategy(engine)


def _send_request(
    base_url: str,
    endpoint: Endpoint,
    params: Dict[str, str],
    json_body: Optional[Dict[str, Any]] = None,
) -> ResponseInfo:
    url = f"{base_url}{endpoint.path}"
    start = time.time()
    try:
        resp = requests.request(
            endpoint.method,
            url,
            params=params,
            json=json_body,
            timeout=FETCH_TIMEOUT,
        )
        elapsed = time.time() - start
        return ResponseInfo(status_code=resp.status_code, body=resp.text or "", elapsed=elapsed)
    except requests.RequestException as e:
        elapsed = time.time() - start
        return ResponseInfo(status_code=0, body=str(e), elapsed=elapsed)


def _load_payloads_for_engine(engine: str, mode: str, payload_file: Optional[str] = None) -> List[str]:
    url = resolve_payload_url(GITHUB_RAW_BASE, engine, mode, payload_file=payload_file)

    if payload_file:
        safe_name = payload_file.replace(".json", "").strip()
        cache_file = f"{CACHE_DIR}/{engine}_{mode}_{safe_name}.json"
    else:
        cache_file = f"{CACHE_DIR}/{engine}_{mode}.json"

    etag_file = f"{cache_file}.etag"

    download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)

    data = load_payloads(cache_file)

    # Se espera una lista de strings; si son objetos, intentar extraer campo "payload"
    payloads: List[str] = []
    for item in data:
        if isinstance(item, str):
            payloads.append(item)
        elif isinstance(item, dict):
            value = item.get("payload")
            if isinstance(value, str):
                payloads.append(value)

    return payloads


def _load_payload_sets(
    engine: str,
    mode: str,
    payload_file: Optional[str] = None,
    detection_types: Optional[List[str]] = None,
) -> Dict[str, List[str]]:
    if payload_file:
        source = payload_file.replace(".json", "").strip()
        return {source: _load_payloads_for_engine(engine, mode, payload_file=payload_file)}

    if mode.lower() == "detection":
        selected_types = detection_types or list(DEFAULT_DETECTION_TYPES)
        payload_sets: Dict[str, List[str]] = {}

        for detection_type in selected_types:
            normalized = detection_type.replace(".json", "").strip()
            payload_sets[normalized] = _load_payloads_for_engine(
                engine,
                mode,
                payload_file=normalized,
            )

        return payload_sets

    # Compatibilidad con modos donde exista un solo archivo por modo
    return {"default": _load_payloads_for_engine(engine, mode, payload_file=None)}


def build_test_cases(endpoints: List[Endpoint], payload_sets: Dict[str, List[str]]) -> List[TestCase]:
    cases: List[TestCase] = []
    for ep in endpoints:
        for payload_source, payloads in payload_sets.items():
            # parametros en query
            for param in ep.query_params:
                for payload in payloads:
                    cases.append(
                        TestCase(
                            endpoint=ep,
                            param_name=param,
                            payload=payload,
                            param_location="query",
                            payload_source=payload_source,
                        )
                    )

            # campos en body JSON
            for field in ep.body_fields:
                for payload in payloads:
                    cases.append(
                        TestCase(
                            endpoint=ep,
                            param_name=field,
                            payload=payload,
                            param_location="body",
                            payload_source=payload_source,
                        )
                    )
    return cases


def _run_single_test_case(base_url: str, test_case: TestCase, engine: str = "neo4j") -> TestResult:
    """Ejecuta un caso de prueba de inyección NoSQL.
    
    Delega el análisis a la estrategia especializada del motor.
    """
    strategy = _get_engine_strategy(engine)
    
    # Valores base genéricos
    baseline_params = {name: "test" for name in test_case.endpoint.query_params}
    baseline_body = {name: "test" for name in test_case.endpoint.body_fields}

    # Petición baseline
    baseline_resp = _send_request(base_url, test_case.endpoint, baseline_params, baseline_body or None)

    # Petición con payload
    injected_params = baseline_params.copy()
    injected_body = baseline_body.copy()

    if test_case.param_location == "query":
        injected_params[test_case.param_name] = test_case.payload
    else:
        injected_body[test_case.param_name] = test_case.payload

    injected_resp = _send_request(base_url, test_case.endpoint, injected_params, injected_body or None)

    vulnerable = False
    reason = None
    
    # Análisis delegado a la estrategia
    if test_case.payload_source == "boolean_based":
        true_payload, false_payload = strategy.generate_boolean_pair(test_case.payload)
        
        if true_payload and false_payload:
            neutral_payload = strategy.generate_neutral_payload(test_case.payload)
            
            # Preparar variantes
            true_params = baseline_params.copy()
            true_body = baseline_body.copy()
            false_params = baseline_params.copy()
            false_body = baseline_body.copy()
            neutral_params = baseline_params.copy()
            neutral_body = baseline_body.copy()
            
            param_attr = test_case.param_name
            if test_case.param_location == "query":
                true_params[param_attr] = true_payload
                false_params[param_attr] = false_payload
                neutral_params[param_attr] = neutral_payload
            else:
                true_body[param_attr] = true_payload
                false_body[param_attr] = false_payload
                neutral_body[param_attr] = neutral_payload
            
            true_resp = _send_request(base_url, test_case.endpoint, true_params, true_body or None)
            false_resp = _send_request(base_url, test_case.endpoint, false_params, false_body or None)
            neutral_resp = _send_request(base_url, test_case.endpoint, neutral_params, neutral_body or None)
            
            # Análisis avanzado boolean-based (comparando TRUE vs FALSE)
            vulnerable, reason = strategy.analyze_boolean_based_advanced(
                neutral_resp, true_resp, false_resp
            )
            
            if vulnerable:
                return TestResult(
                    endpoint=test_case.endpoint,
                    param_name=test_case.param_name,
                    payload=test_case.payload,
                    payload_source=test_case.payload_source,
                    vulnerable=True,
                    reason=f"[ADVANCED] {reason}",
                    baseline=neutral_resp,
                    injected=true_resp,
                )
        else:
            # Si no hay par TRUE/FALSE dinámico, no se reporta ruido en consola.
            pass
    
    elif test_case.payload_source == "error_based":
        vulnerable, reason = strategy.analyze_error_based(baseline_resp, injected_resp)
    
    elif test_case.payload_source == "time_based":
        vulnerable, reason = strategy.analyze_time_based(baseline_resp, injected_resp)
    
    else:
        # Análisis genérico
        if baseline_resp.status_code != injected_resp.status_code:
            vulnerable = True
            reason = f"Cambio de status code: {baseline_resp.status_code} -> {injected_resp.status_code}"

    return TestResult(
        endpoint=test_case.endpoint,
        param_name=test_case.param_name,
        payload=test_case.payload,
        payload_source=test_case.payload_source,
        vulnerable=vulnerable,
        reason=reason,
        baseline=baseline_resp,
        injected=injected_resp,
    )


def run_detection(
    swagger_path: str,
    engine: str = "neo4j",
    mode: str = "detection",
    payload_file: Optional[str] = None,
    detection_types: Optional[List[str]] = None,
    target_path: Optional[str] = None,
    max_workers: int = 10,
    base_url_override: Optional[str] = None,
) -> List[TestResult]:
    spec = load_swagger_from_file(swagger_path)
    if base_url_override:
        base_url = base_url_override.rstrip("/")
    else:
        base_url = _build_base_url(spec)

    endpoints = extract_endpoints(spec, target_path=target_path)
    if not endpoints:
        raise ValueError("No se encontraron endpoints con parametros query/body para probar")

    payload_sets = _load_payload_sets(
        engine,
        mode,
        payload_file=payload_file,
        detection_types=detection_types,
    )

    if not payload_sets or not any(payload_sets.values()):
        raise ValueError("No se cargaron payloads para el motor/modo especificados")

    test_cases = build_test_cases(endpoints, payload_sets)

    results: List[TestResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_case = {
            executor.submit(_run_single_test_case, base_url, case, engine): case
            for case in test_cases
        }

        for future in as_completed(future_to_case):
            result = future.result()
            results.append(result)

    return results


def summarize_vulnerabilities(results: List[TestResult]) -> Dict[str, Dict[str, List[str]]]:
    """Agrupa resultados vulnerables por endpoint y parametro.

    Devuelve un dict de la forma:
    {
      "GET /users": {
          "filter": ["payload1", "payload2"]
      }
    }
    """
    summary: Dict[str, Dict[str, List[str]]] = {}

    for r in results:
        if not r.vulnerable:
            continue

        key = f"{r.endpoint.method} {r.endpoint.path}"
        if key not in summary:
            summary[key] = {}

        if r.param_name not in summary[key]:
            summary[key][r.param_name] = []

        payload_label = r.payload
        if r.payload_source and r.payload_source != "default":
            payload_label = f"[{r.payload_source}] {r.payload}"

        if payload_label not in summary[key][r.param_name]:
            summary[key][r.param_name].append(payload_label)

    return summary