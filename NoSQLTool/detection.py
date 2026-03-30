import json
import os
import re
import time
from difflib import SequenceMatcher
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .config import GITHUB_RAW_BASE, CACHE_DIR, FETCH_TIMEOUT
from .payloads.resolver import normalize_engine, resolve_payload_urls
from .payloads.cache import download_if_updated
from .payloads.loader import load_payloads
from .engines.base import EngineProfile
from .engines.registry import get_engine_profile

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
class BooleanPairCase:
    endpoint: Endpoint
    param_name: str
    param_location: str  # "query" o "body"
    true_payload: str
    false_payload: str
    payload_source: str = "boolean_based"


@dataclass
class ResponseInfo:
    status_code: int
    body: str
    elapsed: float


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


def _infer_boolean_intent(payload: str, profile: EngineProfile) -> Optional[str]:
    normalized = payload.lower().replace(" ", "")
    true_markers = profile.boolean_true_markers
    false_markers = profile.boolean_false_markers

    if any(marker in normalized for marker in true_markers):
        return "true"
    if any(marker in normalized for marker in false_markers):
        return "false"
    return None


def _relative_body_diff(base_len: int, inj_len: int) -> float:
    denominator = max(base_len, 1)
    return abs(inj_len - base_len) / denominator


def _normalized_response_text(body: str) -> str:
    content = body or ""
    try:
        parsed = json.loads(content)
        return json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return " ".join(content.split())


def _response_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _normalized_response_text(a), _normalized_response_text(b)).ratio()


def _extract_top_level_json_keys(body: str) -> Optional[set]:
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    if isinstance(parsed, dict):
        return {str(k) for k in parsed.keys()}
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        keys = set()
        for item in parsed[:20]:
            if isinstance(item, dict):
                keys.update(str(k) for k in item.keys())
        return keys or None
    return None


def _json_structure_similarity(a: str, b: str) -> Optional[float]:
    keys_a = _extract_top_level_json_keys(a)
    keys_b = _extract_top_level_json_keys(b)

    if keys_a is None or keys_b is None:
        return None

    union = keys_a.union(keys_b)
    if not union:
        return 1.0

    return len(keys_a.intersection(keys_b)) / len(union)


def _average(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _representative_response(samples: List[ResponseInfo]) -> ResponseInfo:
    if not samples:
        return ResponseInfo(status_code=0, body="", elapsed=0.0)

    ordered = sorted(samples, key=lambda r: r.elapsed)
    return ordered[len(ordered) // 2]


def _build_boolean_pairs(payloads: List[str], profile: EngineProfile) -> List[Tuple[str, str]]:
    true_payloads: List[str] = []
    false_payloads: List[str] = []

    for payload in payloads:
        intent = _infer_boolean_intent(payload, profile)
        if intent == "true":
            true_payloads.append(payload)
        elif intent == "false":
            false_payloads.append(payload)

    if true_payloads and not false_payloads:
        for true_payload in true_payloads:
            generated_false = _generate_false_payload_from_true(true_payload)
            if generated_false:
                false_payloads.append(generated_false)

    pair_count = min(len(true_payloads), len(false_payloads))
    return [(true_payloads[i], false_payloads[i]) for i in range(pair_count)]


def _generate_false_payload_from_true(payload: str) -> Optional[str]:
    if not payload:
        return None

    transformed = payload
    replacements = [
        (r"(?i)\b1\s*=\s*1\b", "1=0"),
        (r"(?i)'1'\s*=\s*'1'", "'1'='0'"),
        (r'(?i)"1"\s*==\s*"1"', '"1"=="0"'),
        (r"(?i)\bor\s+true\b", "OR false"),
        (r"(?i)\band\s+true\b", "AND false"),
        (r"(?i)\breturn\s+true\b", "RETURN false"),
        (r"(?i)\balways\s+true\b", "always false"),
        (r"\|\|\s*true", "||false"),
        (r"&&\s*true", "&&false"),
        (r"(?i)\bor1\s*=\s*1\b", "or1=0"),
        (r"\"\$ne\"\s*:\s*\"([^\"]+)\"", r'"$eq":"\1"'),
        (r"\"\$ne\"\s*:\s*([0-9]+)", r'"$eq":\1'),
        (r"\"\$gt\"\s*:\s*([0-9]+)", r'"$lt":\1'),
        (r"\"\$gte\"\s*:\s*([0-9]+)", r'"$lte":\1'),
        (r"\"\$regex\"\s*:\s*\"[^\"]*\"", r'"$regex":"a^"'),
        (r"\"\$exists\"\s*:\s*true", r'"$exists":false'),
        (r"\"\$where\"\s*:\s*\"[^\"]*\"", r'"$where":"false"'),
        (r"\$ne", "$eq"),
        (r"\$gt", "$lt"),
        (r"\$gte", "$lte"),
    ]

    for pattern, replacement in replacements:
        transformed = re.sub(pattern, replacement, transformed)

    if transformed == payload:
        return None

    return transformed


def _count_boolean_intents(payloads: List[str], profile: EngineProfile) -> Tuple[int, int, int]:
    true_count = 0
    false_count = 0
    neutral_count = 0

    for payload in payloads:
        intent = _infer_boolean_intent(payload, profile)
        if intent == "true":
            true_count += 1
        elif intent == "false":
            false_count += 1
        else:
            neutral_count += 1

    return true_count, false_count, neutral_count


def _analyze_boolean_pair(
    baseline_samples: List[ResponseInfo],
    true_response: ResponseInfo,
    false_response: ResponseInfo,
    profile: EngineProfile,
) -> Tuple[bool, Optional[str]]:
    if not baseline_samples:
        return False, None

    true_vs_baseline = _average([
        _response_similarity(sample.body, true_response.body)
        for sample in baseline_samples
    ])
    false_vs_baseline = _average([
        _response_similarity(sample.body, false_response.body)
        for sample in baseline_samples
    ])
    true_vs_false = _response_similarity(true_response.body, false_response.body)

    true_struct_vs_baseline_values: List[float] = []
    false_struct_vs_baseline_values: List[float] = []
    for sample in baseline_samples:
        true_struct = _json_structure_similarity(sample.body, true_response.body)
        false_struct = _json_structure_similarity(sample.body, false_response.body)
        if true_struct is not None:
            true_struct_vs_baseline_values.append(true_struct)
        if false_struct is not None:
            false_struct_vs_baseline_values.append(false_struct)

    true_struct_vs_baseline = _average(true_struct_vs_baseline_values)
    false_struct_vs_baseline = _average(false_struct_vs_baseline_values)
    struct_available = bool(true_struct_vs_baseline_values and false_struct_vs_baseline_values)

    similarity_gap = true_vs_baseline - false_vs_baseline

    strong_text_signal = (
        true_vs_baseline >= profile.boolean_true_baseline_min_similarity
        and false_vs_baseline <= profile.boolean_false_baseline_max_similarity
        and true_vs_false <= profile.boolean_true_false_max_similarity
        and similarity_gap >= profile.boolean_min_similarity_gap
    )

    strong_struct_signal = (
        struct_available
        and true_struct_vs_baseline >= profile.boolean_true_baseline_min_similarity
        and false_struct_vs_baseline <= profile.boolean_false_baseline_max_similarity
        and (true_struct_vs_baseline - false_struct_vs_baseline) >= profile.boolean_min_similarity_gap
    )

    if strong_text_signal or strong_struct_signal:
        return (
            True,
            (
                "Posible inyeccion NoSQL (boolean-based pareado: TRUE se parece al baseline "
                f"({true_vs_baseline:.2f}) y FALSE diverge ({false_vs_baseline:.2f}))"
            ),
        )

    return False, None


def _looks_like_time_payload(payload: str, profile: EngineProfile) -> bool:
    normalized = (payload or "").lower()
    time_markers = profile.time_markers
    return any(marker in normalized for marker in time_markers)


def _extract_error_score(response: ResponseInfo, profile: EngineProfile) -> int:
    score = 0

    if response.status_code >= 500:
        score += 5
    elif response.status_code >= 400:
        score += 2
    elif response.status_code == 0:
        score += 1

    text = (response.body or "").lower()

    for keyword in profile.error_keywords:
        if keyword in text:
            score += 2

    for hint in profile.error_hints:
        if hint in text:
            score += 1

    # Si la respuesta parece JSON de error, sumar evidencia extra.
    try:
        parsed = json.loads(response.body)
        if isinstance(parsed, dict):
            error_keys = {"error", "errors", "exception", "message", "stack", "stacktrace", "code"}
            matched = error_keys.intersection({k.lower() for k in parsed.keys()})
            if matched:
                score += 2
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    return score


def _analyze_error_based(
    baseline: ResponseInfo,
    injected: ResponseInfo,
    profile: EngineProfile,
) -> Tuple[bool, Optional[str]]:
    # Regla fuerte 1: error interno nuevo tras inyeccion.
    if baseline.status_code < 500 <= injected.status_code:
        return True, "Posible inyeccion NoSQL (error-based: 5xx nuevo en respuesta inyectada)"

    base_score = _extract_error_score(baseline, profile)
    inj_score = _extract_error_score(injected, profile)
    score_delta = inj_score - base_score

    # Regla fuerte 2: salto consistente de evidencia de error.
    if inj_score >= 7 and score_delta >= 3:
        return True, "Posible inyeccion NoSQL (error-based: fuerte evidencia de error de BD tras payload)"

    # Regla fuerte 3: misma clase HTTP pero aparece texto de error de base de datos.
    base_text = (baseline.body or "").lower()
    inj_text = (injected.body or "").lower()
    inj_has_db_error = any(k in inj_text for k in profile.error_keywords)
    base_has_db_error = any(k in base_text for k in profile.error_keywords)
    if inj_has_db_error and not base_has_db_error:
        return True, "Posible inyeccion NoSQL (error-based: mensaje de error de motor/consulta)"

    # Fallback robusto (no generico): diferencia material de error aunque no haya 5xx.
    if score_delta >= 5:
        return True, "Posible inyeccion NoSQL (error-based: incremento material de señales de error)"

    return False, None


def _analyze_responses(
    baseline: ResponseInfo,
    injected: ResponseInfo,
    payload_source: str,
    payload: str,
    profile: EngineProfile,
) -> Tuple[bool, Optional[str]]:
    source = (payload_source or "").lower()

    # Heuristica especifica: error-based
    if source == "error_based":
        return _analyze_error_based(baseline, injected, profile)

    # Heuristica especifica: time-based
    if source == "time_based":
        if baseline.status_code != 0 and injected.status_code != 0:
            delta = injected.elapsed - baseline.elapsed
            min_delay = max(profile.time_min_delay_seconds, baseline.elapsed * profile.time_min_factor)
            if _looks_like_time_payload(payload, profile):
                min_delay = max(0.5, baseline.elapsed * 1.5)

            if delta >= min_delay:
                return True, "Posible inyeccion NoSQL (time-based: incremento anomalo de latencia)"

    # Heuristica especifica: boolean-based
    if source == "boolean_based":
        base_len = len(baseline.body)
        inj_len = len(injected.body)
        diff_ratio = _relative_body_diff(base_len, inj_len)
        intent = _infer_boolean_intent(payload, profile)

        if baseline.status_code != injected.status_code:
            return True, "Posible inyeccion NoSQL (boolean-based: cambio de codigo HTTP)"

        if intent == "true" and base_len > 0 and inj_len >= int(base_len * 1.2):
            return True, "Posible inyeccion NoSQL (boolean-based: condicion TRUE altera el resultado)"

        if intent == "false" and base_len > 0 and inj_len <= int(base_len * 0.8):
            return True, "Posible inyeccion NoSQL (boolean-based: condicion FALSE altera el resultado)"

        if diff_ratio >= profile.boolean_diff_ratio:
            return True, "Posible inyeccion NoSQL (boolean-based: diferencia relevante en respuesta)"

    # Cambios importantes en longitud de respuesta
    base_len = len(baseline.body)
    inj_len = len(injected.body)

    if base_len == 0 and inj_len > 0:
        return True, "Posible inyeccion NoSQL (respuesta vacia vs no vacia)"

    if base_len > 0 and inj_len / base_len > 1.5:
        return True, "Posible inyeccion NoSQL (respuesta significativamente mas grande)"

    # Cambios de codigo HTTP relevantes
    if baseline.status_code != injected.status_code:
        return True, "Posible inyeccion NoSQL (cambio de codigo HTTP)"

    return False, None


def _run_single_test_case(base_url: str, test_case: TestCase, profile: EngineProfile) -> TestResult:
    # valores base genericos
    baseline_params = {name: "test" for name in test_case.endpoint.query_params}
    baseline_body = {name: "test" for name in test_case.endpoint.body_fields}

    # peticion base sin payload malicioso
    baseline_resp = _send_request(base_url, test_case.endpoint, baseline_params, baseline_body or None)

    # peticion con payload en el parametro especifico
    injected_params = baseline_params.copy()
    injected_body = baseline_body.copy()

    if test_case.param_location == "query":
        injected_params[test_case.param_name] = test_case.payload
    else:
        injected_body[test_case.param_name] = test_case.payload

    injected_resp = _send_request(base_url, test_case.endpoint, injected_params, injected_body or None)

    vulnerable, reason = _analyze_responses(
        baseline_resp,
        injected_resp,
        test_case.payload_source,
        test_case.payload,
        profile,
    )

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


def _run_boolean_pair_test_case(
    base_url: str,
    test_case: BooleanPairCase,
    profile: EngineProfile,
) -> TestResult:
    baseline_params = {name: "test" for name in test_case.endpoint.query_params}
    baseline_body = {name: "test" for name in test_case.endpoint.body_fields}

    baseline_samples: List[ResponseInfo] = []
    for _ in range(profile.boolean_baseline_samples):
        baseline_samples.append(
            _send_request(base_url, test_case.endpoint, baseline_params, baseline_body or None)
        )

    true_params = baseline_params.copy()
    true_body = baseline_body.copy()
    false_params = baseline_params.copy()
    false_body = baseline_body.copy()

    if test_case.param_location == "query":
        true_params[test_case.param_name] = test_case.true_payload
        false_params[test_case.param_name] = test_case.false_payload
    else:
        true_body[test_case.param_name] = test_case.true_payload
        false_body[test_case.param_name] = test_case.false_payload

    true_resp = _send_request(base_url, test_case.endpoint, true_params, true_body or None)
    false_resp = _send_request(base_url, test_case.endpoint, false_params, false_body or None)

    vulnerable, reason = _analyze_boolean_pair(baseline_samples, true_resp, false_resp, profile)

    baseline_repr = _representative_response(baseline_samples)
    pair_payload_label = f"TRUE: {test_case.true_payload} || FALSE: {test_case.false_payload}"

    return TestResult(
        endpoint=test_case.endpoint,
        param_name=test_case.param_name,
        payload=pair_payload_label,
        payload_source=test_case.payload_source,
        vulnerable=vulnerable,
        reason=reason,
        baseline=baseline_repr,
        injected=true_resp,
    )


def _load_payloads_for_engine(engine: str, mode: str, payload_file: Optional[str] = None) -> List[str]:
    canonical_engine = normalize_engine(engine)
    urls = resolve_payload_urls(GITHUB_RAW_BASE, canonical_engine, mode, payload_file=payload_file)

    if payload_file:
        safe_name = payload_file.replace(".json", "").strip()
        cache_file = f"{CACHE_DIR}/{canonical_engine}_{mode}_{safe_name}.json"
    else:
        cache_file = f"{CACHE_DIR}/{canonical_engine}_{mode}.json"

    etag_file = f"{cache_file}.etag"

    last_error: Optional[Exception] = None
    downloaded = False
    for url in urls:
        try:
            download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)
            downloaded = True
            break
        except Exception as ex:
            last_error = ex

    if not downloaded and not os.path.exists(cache_file):
        raise RuntimeError(
            f"No se pudieron descargar payloads para engine='{engine}' (probados: {', '.join(urls)})."
        ) from last_error

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
    default_detection_types: Optional[Tuple[str, ...]] = None,
) -> Dict[str, List[str]]:
    if payload_file:
        source = payload_file.replace(".json", "").strip()
        return {source: _load_payloads_for_engine(engine, mode, payload_file=payload_file)}

    if mode.lower() == "detection":
        selected_types = detection_types or list(default_detection_types or DEFAULT_DETECTION_TYPES)
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


def build_boolean_pair_cases(
    endpoints: List[Endpoint],
    payloads: List[str],
    profile: EngineProfile,
    payload_source: str = "boolean_based",
) -> List[BooleanPairCase]:
    pairs = _build_boolean_pairs(payloads, profile)
    cases: List[BooleanPairCase] = []

    for ep in endpoints:
        for true_payload, false_payload in pairs:
            for param in ep.query_params:
                cases.append(
                    BooleanPairCase(
                        endpoint=ep,
                        param_name=param,
                        param_location="query",
                        true_payload=true_payload,
                        false_payload=false_payload,
                        payload_source=payload_source,
                    )
                )

            for field in ep.body_fields:
                cases.append(
                    BooleanPairCase(
                        endpoint=ep,
                        param_name=field,
                        param_location="body",
                        true_payload=true_payload,
                        false_payload=false_payload,
                        payload_source=payload_source,
                    )
                )

    return cases


def run_detection(
    swagger_path: str,
    engine: Optional[str] = None,
    mode: str = "detection",
    payload_file: Optional[str] = None,
    detection_types: Optional[List[str]] = None,
    target_path: Optional[str] = None,
    max_workers: int = 10,
    base_url_override: Optional[str] = None,
) -> List[TestResult]:
    """Ejecuta la deteccion de posibles inyecciones NoSQL.

    - swagger_path: ruta local al archivo swagger.json
    - engine: motor NoSQL obligatorio (mongodb/mongo, couchdb, neo4j)
    - mode: tipo de payloads (detection / exploitation)
        - payload_file: nombre del json dentro de engine/mode (ej. "error_based" o "error_based.json")
            Si se indica, solo se usa ese archivo.
        - detection_types: lista de tipos de deteccion a usar cuando mode="detection"
            (por defecto: error_based, time_based, boolean_based).
    - target_path: si se indica, solo prueba ese endpoint (por ejemplo, "/users")
    - max_workers: numero maximo de hilos en paralelo
    - base_url_override: si se indica, se usara esta URL base
      en lugar de la definida en el swagger (ej. "http://localhost:3000")
    """

    if not engine or not engine.strip():
        raise ValueError("Debe indicar el motor NoSQL en 'engine' (mongodb/mongo, couchdb o neo4j)")

    profile = get_engine_profile(engine)
    spec = load_swagger_from_file(swagger_path)
    if base_url_override:
        base_url = base_url_override.rstrip("/")
    else:
        base_url = _build_base_url(spec)

    endpoints = extract_endpoints(spec, target_path=target_path)
    if not endpoints:
        raise ValueError("No se encontraron endpoints con parametros query/body para probar")

    payload_sets = _load_payload_sets(
        profile.canonical_name,
        mode,
        payload_file=payload_file,
        detection_types=detection_types,
        default_detection_types=profile.default_detection_types,
    )

    if not payload_sets or not any(payload_sets.values()):
        raise ValueError("No se cargaron payloads para el motor/modo especificados")

    boolean_payloads = payload_sets.pop("boolean_based", None)
    test_cases = build_test_cases(endpoints, payload_sets)
    boolean_pair_cases: List[BooleanPairCase] = []
    if boolean_payloads:
        boolean_pair_cases = build_boolean_pair_cases(
            endpoints,
            boolean_payloads,
            profile=profile,
            payload_source="boolean_based",
        )

        # Modo estricto para boolean-based: requiere pares TRUE/FALSE.
        if not boolean_pair_cases:
            true_count, false_count, neutral_count = _count_boolean_intents(boolean_payloads, profile)
            raise ValueError(
                "boolean_based requiere payloads pareados TRUE/FALSE. "
                f"Detectados -> true: {true_count}, false: {false_count}, neutros: {neutral_count}."
            )

    if not test_cases and not boolean_pair_cases:
        raise ValueError("No se generaron casos de prueba para los payloads seleccionados")

    results: List[TestResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_case = {
            executor.submit(_run_single_test_case, base_url, case, profile): case
            for case in test_cases
        }

        future_to_case.update(
            {
                executor.submit(_run_boolean_pair_test_case, base_url, case, profile): case
                for case in boolean_pair_cases
            }
        )

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
