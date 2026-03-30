from .base import (
    COMMON_BOOLEAN_FALSE_MARKERS,
    COMMON_BOOLEAN_TRUE_MARKERS,
    COMMON_DEFAULT_DETECTION_TYPES,
    COMMON_ERROR_HINTS,
    COMMON_TIME_MARKERS,
    EngineProfile,
)


MONGO_PROFILE = EngineProfile(
    canonical_name="mongo",
    default_detection_types=COMMON_DEFAULT_DETECTION_TYPES,
    error_keywords=(
        "mongo",
        "mongodb",
        "bson",
        "$where",
        "mapreduce",
        "nosqlexception",
        "mongodbdriver",
        "syntaxerror",
        "databaseerror",
    ),
    error_hints=COMMON_ERROR_HINTS,
    boolean_true_markers=COMMON_BOOLEAN_TRUE_MARKERS,
    boolean_false_markers=COMMON_BOOLEAN_FALSE_MARKERS,
    time_markers=COMMON_TIME_MARKERS,
)
