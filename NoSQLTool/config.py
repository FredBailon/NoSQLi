import os


def _get_float(name: str, default: str) -> float:
    return float(os.getenv(name, default))


def _get_int(name: str, default: str) -> int:
    return int(os.getenv(name, default))


GITHUB_RAW_BASE = os.getenv(
    "PAYLOAD_BASE_URL",
    "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL/refs/heads/main"
)

CACHE_DIR = os.getenv("CACHE_DIR", ".cache/payloads")

FETCH_TIMEOUT = _get_int("FETCH_TIMEOUT", "5")

# Timeout de peticiones a la API objetivo durante detección.
# Debe ser mayor al sleep de payloads time_based (p.ej. 10s).
REQUEST_TIMEOUT = _get_int("REQUEST_TIMEOUT", "15")

# Umbrales para detección booleana avanzada
SIMILAR_STATUS_REQUIRED = 1.0
SIMILAR_LEN_DIFF_MAX = 0.2
SIMILAR_TEXT_MIN = 0.8

DIFFERENT_STATUS_ALLOWED = 0.0
DIFFERENT_LEN_DIFF_MIN = 0.35
DIFFERENT_TEXT_MAX = 0.6

# Umbrales de explotación. OWASP WSTG y PortSwigger documentan las señales
# esperadas (diferencias booleanas, errores y delays); los valores concretos
# dependen del entorno y por eso son configurables.
BOOLEAN_SIMILARITY_TRUE_BASELINE = _get_float("BOOLEAN_SIMILARITY_TRUE_BASELINE", "0.98")
BOOLEAN_DIFF_TRUE_FALSE = _get_float("BOOLEAN_DIFF_TRUE_FALSE", "0.05")
MIN_BODY_DIFF_BYTES = _get_int("MIN_BODY_DIFF_BYTES", "10")
MIN_BODY_DIFF_RATIO = _get_float("MIN_BODY_DIFF_RATIO", "0.05")

ERROR_MIN_STATUS = _get_int("ERROR_MIN_STATUS", "400")
ERROR_MIN_PATTERN_MATCHES = _get_int("ERROR_MIN_PATTERN_MATCHES", "1")
ERROR_MIN_MESSAGE_LENGTH = _get_int("ERROR_MIN_MESSAGE_LENGTH", "30")

TIME_DELAY_SECONDS = _get_float("TIME_DELAY_SECONDS", "5.0")
TIME_MIN_VALID_DELAY = _get_float("TIME_MIN_VALID_DELAY", "0.5")
TIME_BASELINE_SAMPLES = _get_int("TIME_BASELINE_SAMPLES", "30")
TIME_STDEV_COEFF = _get_float("TIME_STDEV_COEFF", "7")
TIME_REPETITIONS = _get_int("TIME_REPETITIONS", "3")
TIME_MIN_CONFIRMATIONS = _get_int("TIME_MIN_CONFIRMATIONS", "2")
TIME_JITTER_WARNING_STD = _get_float("TIME_JITTER_WARNING_STD", "0.5")
