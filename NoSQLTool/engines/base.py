from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class EngineProfile:
    canonical_name: str
    default_detection_types: Tuple[str, ...]
    error_keywords: Tuple[str, ...]
    error_hints: Tuple[str, ...]
    boolean_true_markers: Tuple[str, ...]
    boolean_false_markers: Tuple[str, ...]
    time_markers: Tuple[str, ...]
    time_min_delay_seconds: float = 1.0
    time_min_factor: float = 2.0
    boolean_diff_ratio: float = 0.35
    boolean_baseline_samples: int = 3
    boolean_true_baseline_min_similarity: float = 0.88
    boolean_false_baseline_max_similarity: float = 0.78
    boolean_true_false_max_similarity: float = 0.80
    boolean_min_similarity_gap: float = 0.12


COMMON_DEFAULT_DETECTION_TYPES = ("error_based", "time_based", "boolean_based")
COMMON_ERROR_HINTS = (
    "error",
    "errors",
    "traceback",
    "failed",
    "invalid input",
    "query cannot be",
    "unexpected",
)
COMMON_BOOLEAN_TRUE_MARKERS = (
    "true",
    "or1=1",
    "1=1",
    "'1'='1",
    '"1"=="1"',
    "||true",
    "ortrue",
    "$ne",
    "$gt",
    "$gte",
    "$regex",
    "$exists:true",
    "$where",
    "this.",
    "always true",
    "returntrue",
)
COMMON_BOOLEAN_FALSE_MARKERS = (
    "false",
    "or1=0",
    "1=0",
    "'1'='0",
    '"1"=="0"',
    "&&false",
    "orfalse",
    "$eq",
    "$lt",
    "$lte",
    "$nin",
    "$exists:false",
    "always false",
    "returnfalse",
)
COMMON_TIME_MARKERS = (
    "sleep",
    "delay",
    "apoc.util.sleep",
    "benchmark",
    "busyloop",
    "while(true)",
    "max_time_ms",
    "maxtimems",
)
