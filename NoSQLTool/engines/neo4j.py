from .base import (
    COMMON_BOOLEAN_FALSE_MARKERS,
    COMMON_BOOLEAN_TRUE_MARKERS,
    COMMON_DEFAULT_DETECTION_TYPES,
    COMMON_ERROR_HINTS,
    COMMON_TIME_MARKERS,
    EngineProfile,
)


NEO4J_PROFILE = EngineProfile(
    canonical_name="neo4j",
    default_detection_types=COMMON_DEFAULT_DETECTION_TYPES,
    error_keywords=(
        "neo4j",
        "cypher",
        "clientexception",
        "neo.clienterror",
        "stack trace",
        "syntaxerror",
        "databaseerror",
    ),
    error_hints=COMMON_ERROR_HINTS,
    boolean_true_markers=COMMON_BOOLEAN_TRUE_MARKERS,
    boolean_false_markers=COMMON_BOOLEAN_FALSE_MARKERS,
    time_markers=COMMON_TIME_MARKERS,
)
