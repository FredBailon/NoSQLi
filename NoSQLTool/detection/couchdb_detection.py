"""Detección especializada para CouchDB.

Este módulo contiene la estrategia específica para detectar inyecciones NoSQL
en CouchDB usando el lenguaje Mango Query con análisis especializados.
"""

import json
from typing import Any, Optional, Tuple

from .engines import NoSQLEngineStrategy
from .detection import ResponseInfo

# Palabras clave y pistas específicas para errores de CouchDB
COUCHDB_ERROR_KEYWORDS = (
    "couchdb",
    "bad_request",
    "invalid_json",
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
)


class CouchDBStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para CouchDB (Mango Query).
    
    CouchDB utiliza Mango Query Language con operadores específicos.
    Esta implementación proporciona análisis adaptados a CouchDB.
    """

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

            true_variant = payload_dict.copy()
            false_variant = payload_dict.copy()

            # Intercambiar operadores $eq ↔ $ne y comparadores
            for key, value in payload_dict.items():
                if isinstance(value, dict):
                    if "$eq" in value:
                        false_variant[key] = {"$ne": value["$eq"]}
                    elif "$ne" in value:
                        true_variant[key] = {"$eq": value["$ne"]}
                    elif "$gt" in value:
                        false_variant[key] = {"$lte": value["$gt"]}
                    elif "$lt" in value:
                        false_variant[key] = {"$gte": value["$lt"]}
                    elif "$regex" in value:
                        # Para regex, usar patrones que siempre/nunca coinciden
                        true_variant[key] = {"$regex": ".*"}
                        false_variant[key] = {"$regex": "(?!.*)"}

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
                    comparison_operators = ("$eq", "$ne", "$gt", "$lt", "$regex", "$gte", "$lte")
                    if not any(op in value for op in comparison_operators):
                        result[key] = value
                else:
                    result[key] = value

            return result if result else None

        return None
