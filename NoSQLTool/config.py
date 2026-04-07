import os

GITHUB_RAW_BASE = os.getenv(
    "PAYLOAD_BASE_URL",
    "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL/refs/heads/main"
)

CACHE_DIR = os.getenv("CACHE_DIR", ".cache/payloads")

FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "5"))

# Timeout de peticiones a la API objetivo durante detección.
# Debe ser mayor al sleep de payloads time_based (p.ej. 10s).
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))

# Umbrales para detección booleana avanzada
SIMILAR_STATUS_REQUIRED = 1.0
SIMILAR_LEN_DIFF_MAX = 0.2
SIMILAR_TEXT_MIN = 0.8

DIFFERENT_STATUS_ALLOWED = 0.0
DIFFERENT_LEN_DIFF_MIN = 0.35
DIFFERENT_TEXT_MAX = 0.6
