"""Detección especializada para CouchDB.

Este módulo contiene la estrategia específica para detectar inyecciones NoSQL
en CouchDB usando el lenguaje Mango Query con análisis especializados.
"""

import json
import copy
from typing import Any, Optional, Tuple

from .engines import NoSQLEngineStrategy
from .detection import ResponseInfo

# Palabras clave y pistas específicas para errores de CouchDB
COUCHDB_ERROR_KEYWORDS = (
    "couchdb",
    "mango",
    "selector",
    "bad_request",
    "invalid_json",
    "invalid_operator",
    "no_usable_index",
    "badmatch",
    "not_found",
    "file_not_found",
    "key_error",
    "index_error",
)

COUCHDB_ERROR_HINTS = (
    "error",
    "errors",
    "failed",
    "invalid",
    "malformed",
    "bad",
    "unexpected",
    "missing",
    "docid",
    "database_error",
    "execution_stats",
    "use_index",
    "allow_fallback",
)


class CouchDBStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para CouchDB (Mango Query).
    
    CouchDB utiliza Mango Query Language con operadores específicos.
    Esta implementación proporciona análisis adaptados a CouchDB.
    """

    def supports_body_raw_payloads(self) -> bool:
        return True

    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE y FALSE para CouchDB (Mango).

        CouchDB utiliza operadores como $eq, $ne, $gt, $lt, $regex, etc.
        Esta función intercambia operadores para crear variantes booleanas.

        Args:
            payload: El payload JSON para Mango Query

        Returns:
            Tupla (true_variant_json, false_variant_json) o (None, None)
        """
        try:
            payload_dict = json.loads(payload)
            true_variant = self._boolean_variant(payload_dict, True)
            false_variant = self._boolean_variant(payload_dict, False)
            if true_variant == false_variant:
                return (None, None)
            return (json.dumps(true_variant), json.dumps(false_variant))
        except (json.JSONDecodeError, TypeError):
            return (None, None)

    def generate_neutral_payload(self, payload: str) -> str:
        """Elimina condiciones booleanas en CouchDB.

        Genera una versión neutral del payload removiendo operadores
        de comparación y condiciones booleadas.

        Args:
            payload: El payload JSON para Mango Query

        Returns:
            Payload neutral en formato JSON o "test"
        """
        try:
            payload_dict = json.loads(payload)
            neutral = self._neutral_variant(payload_dict)
            return json.dumps(neutral) if neutral else "test"
        except (json.JSONDecodeError, TypeError):
            return "test"
    
    def analyze_error_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis especializado de error-based para CouchDB.
        
        Detecta palabras clave específicas de CouchDB en respuestas.
        
        Args:
            baseline: Respuesta sin inyección
            injected: Respuesta con payload inyectado
            
        Returns:
            Tupla (vulnerable, reason)
        """
        # Análisis base: cambios en status code
        if baseline.status_code < 500 <= injected.status_code:
            return True, "error-based: 5xx nuevo en respuesta CouchDB"

        # Análisis especializado: buscar palabras clave de CouchDB
        base_text = (baseline.body or "").lower()
        inj_text = (injected.body or "").lower()

        inj_has_db_error = any(k in inj_text for k in COUCHDB_ERROR_KEYWORDS)
        base_has_db_error = any(k in base_text for k in COUCHDB_ERROR_KEYWORDS)

        if inj_has_db_error and not base_has_db_error:
            return True, "error-based: palabra clave de error CouchDB detectada"

        inj_has_hint = any(h in inj_text for h in COUCHDB_ERROR_HINTS)
        base_has_hint = any(h in base_text for h in COUCHDB_ERROR_HINTS)

        if inj_has_hint and not base_has_hint:
            return True, "error-based: indicios de error en respuesta"

        if baseline.status_code != injected.status_code and baseline.status_code != 0:
            return True, "error-based: cambio de status code"

        return False, None

    def analyze_time_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Analiza señales de degradación Mango por tiempo HTTP y execution_stats."""
        vulnerable, reason = super().analyze_time_based(baseline, injected)
        if vulnerable:
            return vulnerable, reason

        baseline_stats = self._extract_execution_stats(baseline.body)
        injected_stats = self._extract_execution_stats(injected.body)

        if not baseline_stats or not injected_stats:
            return False, None

        base_time = baseline_stats.get("execution_time_ms")
        injected_time = injected_stats.get("execution_time_ms")
        if base_time is not None and injected_time is not None:
            delta = injected_time - base_time
            threshold = max(50.0, base_time * 2.0)
            if delta >= threshold:
                return True, (
                    "time-based: execution_stats indica degradacion "
                    f"({base_time:.2f}ms -> {injected_time:.2f}ms)"
                )

        docs_delta = self._stat_delta(baseline_stats, injected_stats, "total_docs_examined")
        keys_delta = self._stat_delta(baseline_stats, injected_stats, "total_keys_examined")
        if docs_delta >= 100 or keys_delta >= 100:
            return True, (
                "time-based: execution_stats indica mayor trabajo de consulta "
                f"(docs +{docs_delta:.0f}, keys +{keys_delta:.0f})"
            )

        return False, None

    @staticmethod
    def _neutral_variant(obj: Any) -> Optional[Any]:
        """Elimina condiciones booleanas en CouchDB.

        Filtra operadores de comparación para dejar solo identificadores
        simples sin condiciones.

        Args:
            obj: El objeto parsed del JSON

        Returns:
            Diccionario sin operadores booleanos o None
        """
        if isinstance(obj, dict):
            result = {}

            for key, value in obj.items():
                if isinstance(value, dict):
                    # Omitir selectores con operadores de comparación
                    comparison_operators = (
                        "$eq",
                        "$ne",
                        "$gt",
                        "$lt",
                        "$regex",
                        "$gte",
                        "$lte",
                        "$exists",
                        "$in",
                        "$nin",
                        "$not",
                    )
                    if not any(op in value for op in comparison_operators):
                        nested = CouchDBStrategy._neutral_variant(value)
                        result[key] = nested if nested is not None else value
                else:
                    result[key] = value

            return result if result else None

        return None

    @staticmethod
    def _boolean_variant(obj: Any, is_true: bool) -> Any:
        """Reescribe recursivamente operadores Mango para crear TRUE/FALSE."""
        if not isinstance(obj, dict):
            return copy.deepcopy(obj)

        if "$eq" in obj:
            value = obj["$eq"]
            return {"$eq" if is_true else "$ne": value}
        if "$ne" in obj:
            value = obj["$ne"]
            return {"$ne" if is_true else "$eq": value}
        if "$gt" in obj:
            value = obj["$gt"]
            return {"$gt" if is_true else "$lte": value}
        if "$lt" in obj:
            value = obj["$lt"]
            return {"$lt" if is_true else "$gte": value}
        if "$gte" in obj:
            value = obj["$gte"]
            return {"$gte" if is_true else "$lt": value}
        if "$lte" in obj:
            value = obj["$lte"]
            return {"$lte" if is_true else "$gt": value}
        if "$regex" in obj:
            return {"$regex": ".*" if is_true else "(?!.*)"}
        if "$exists" in obj:
            return {"$exists": bool(obj["$exists"]) if is_true else not bool(obj["$exists"])}

        return {
            key: CouchDBStrategy._boolean_variant(value, is_true)
            for key, value in obj.items()
        }

    @staticmethod
    def _extract_execution_stats(body: str) -> Optional[dict]:
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            return None

        if not isinstance(parsed, dict):
            return None

        stats = parsed.get("execution_stats")
        if isinstance(stats, dict):
            return {
                key: float(value)
                for key, value in stats.items()
                if isinstance(value, (int, float))
            }

        return None

    @staticmethod
    def _stat_delta(baseline_stats: dict, injected_stats: dict, key: str) -> float:
        baseline_value = baseline_stats.get(key)
        injected_value = injected_stats.get(key)
        if baseline_value is None or injected_value is None:
            return 0.0
        return max(0.0, injected_value - baseline_value)
