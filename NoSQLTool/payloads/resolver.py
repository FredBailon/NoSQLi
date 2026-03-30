SUPPORTED_ENGINES = {"couchdb", "mongo", "neo4j"}
SUPPORTED_MODES = {"detection", "exploitation"}

ENGINE_ALIASES = {
    "mongodb": "mongo",
    "mongo": "mongo",
    "couch": "couchdb",
    "couchdb": "couchdb",
    "neo": "neo4j",
    "neo4j": "neo4j",
}

ENGINE_URL_VARIANTS = {
    "mongo": ["mongo", "mongodb"],
    "couchdb": ["couchdb", "couch"],
    "neo4j": ["neo4j"],
}


def normalize_engine(engine):
    normalized = (engine or "").strip().lower()
    canonical = ENGINE_ALIASES.get(normalized)
    if canonical not in SUPPORTED_ENGINES:
        raise ValueError(f"Motor NoSQL no soportado: {engine}")
    return canonical


def _normalize_mode(mode):
    normalized = (mode or "").strip().lower()
    if normalized not in SUPPORTED_MODES:
        raise ValueError(f"Modo no soportado: {mode}")
    return normalized


def resolve_payload_url(base, engine, mode, payload_file=None):
    canonical_engine = normalize_engine(engine)
    normalized_mode = _normalize_mode(mode)

    if payload_file:
        payload_file = payload_file.strip()
        if payload_file.endswith(".json"):
            payload_name = payload_file
        else:
            payload_name = f"{payload_file}.json"
        return f"{base}/{canonical_engine}/{normalized_mode}/{payload_name}"

    return f"{base}/{canonical_engine}/{normalized_mode}.json"


def resolve_payload_urls(base, engine, mode, payload_file=None):
    canonical_engine = normalize_engine(engine)
    normalized_mode = _normalize_mode(mode)

    if payload_file:
        payload_file = payload_file.strip()
        if payload_file.endswith(".json"):
            payload_name = payload_file
        else:
            payload_name = f"{payload_file}.json"
        return [
            f"{base}/{engine_variant}/{normalized_mode}/{payload_name}"
            for engine_variant in ENGINE_URL_VARIANTS[canonical_engine]
        ]

    return [
        f"{base}/{engine_variant}/{normalized_mode}.json"
        for engine_variant in ENGINE_URL_VARIANTS[canonical_engine]
    ]