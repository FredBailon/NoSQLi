SUPPORTED_ENGINES = {"couchdb", "mongo", "neo4j"}
ENGINE_ALIASES = {
    "mongodb": "mongo",
    "mongo": "mongo",
    "couch": "couchdb",
    "couchdb": "couchdb",
    "neo4j": "neo4j",
}
SUPPORTED_MODES = {"detection", "exploitation"}


def normalize_engine(engine):
    return ENGINE_ALIASES.get(engine.lower().strip())


def resolve_payload_url(base, engine, mode, payload_file=None):
    original_engine = engine
    engine = normalize_engine(engine)
    mode = mode.lower()

    if engine not in SUPPORTED_ENGINES:
        supported = ", ".join(sorted(ENGINE_ALIASES))
        raise ValueError(
            f"Motor NoSQL no soportado: {original_engine}. "
            f"Motores soportados: {supported}"
        )

    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Modo no soportado: {mode}")

    if payload_file:
        payload_file = payload_file.strip()
        if payload_file.endswith(".json"):
            payload_name = payload_file
        else:
            payload_name = f"{payload_file}.json"
        return f"{base}/{engine}/{mode}/{payload_name}"

    return f"{base}/{engine}/{mode}.json"
