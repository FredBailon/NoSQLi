"""Estrategias especializadas de detección para diferentes motores NoSQL.

Este módulo define la interfaz base y las implementaciones específicas para
cada motor NoSQL (MongoDB, Neo4j, etc.). Cada estrategia encapsula:
- Generación de variantes booleanas (TRUE/FALSE)
- Generación de payloads neutros
- Análisis especializado si es necesario
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from .base_analysis import ResponseInfo, BooleanBasedAnalyzer, TimeBasedAnalyzer


class NoSQLEngineStrategy(ABC):
    """Interfaz base para estrategias especializadas de detección por motor NoSQL.
    
    Cada estrategia define cómo generar payloads modificados y cómo analizar
    respuestas para su motor específico.
    """

    @abstractmethod
    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE y FALSE de un payload.

        Args:
            payload: El payload original (puede ser JSON o string)

        Returns:
            Tupla (true_payload, false_payload) o (None, None) si no es posible
        """
        pass

    @abstractmethod
    def generate_neutral_payload(self, payload: str) -> str:
        """Genera una versión neutral/sin condiciones del payload.

        Args:
            payload: El payload original

        Returns:
            Payload neutro o "test" si no es posible crear uno
        """
        pass

    def analyze_error_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis de inyección basada en errores. Puede ser overrideado por subclases.
        
        Implementation por defecto: usa análisis genérico sin palabras clave específicas.
        
        Args:
            baseline: Respuesta sin inyección
            injected: Respuesta con payload inyectado
            
        Returns:
            Tupla (vulnerable, reason)
        """
        # Análisis genérico: cambios significativos en status code
        if baseline.status_code < 500 <= injected.status_code:
            return True, "error-based: 5xx nuevo en respuesta"

        if baseline.status_code != injected.status_code and baseline.status_code != 0:
            return True, "error-based: cambio de status code"

        return False, None

    def analyze_time_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis de inyección basada en tiempo. Usa TimeBasedAnalyzer por defecto."""
        return TimeBasedAnalyzer.analyze(baseline, injected)

    def analyze_boolean_based(
        self, baseline: ResponseInfo, injected: ResponseInfo, payload: str
    ) -> Tuple[bool, Optional[str]]:
        """Análisis básico de inyección boolean-based. Usa BooleanBasedAnalyzer por defecto."""
        return BooleanBasedAnalyzer.analyze_basic(baseline, injected, payload)

    def analyze_boolean_based_advanced(
        self, neutral: ResponseInfo, true_injected: ResponseInfo, false_injected: ResponseInfo
    ) -> Tuple[bool, Optional[str]]:
        """Análisis avanzado boolean-based. Usa BooleanBasedAnalyzer por defecto."""
        return BooleanBasedAnalyzer.analyze_advanced(neutral, true_injected, false_injected)


class MongoDBStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para MongoDB."""

    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE/FALSE para MongoDB."""
        try:
            payload_dict = json.loads(payload)
            true_variant = self._boolean_variant(payload_dict, True)
            false_variant = self._boolean_variant(payload_dict, False)
            return (json.dumps(true_variant), json.dumps(false_variant))
        except (json.JSONDecodeError, TypeError):
            # Si no es JSON válido, intentar con strings
            return self._string_variant(payload)

    def generate_neutral_payload(self, payload: str) -> str:
        """Elimina condiciones booleanas en MongoDB."""
        try:
            payload_dict = json.loads(payload)
            neutral = self._neutral_variant(payload_dict)
            return json.dumps(neutral) if neutral else "test"
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: intentar eliminar operadores booleanos comunes
        neutral = re.sub(r"(\s*&&\s*)?'1'\s*=\s*'1'", "", payload)
        neutral = re.sub(r"(\s*\|\|\s*)?'1'\s*=\s*'0'", "", neutral)
        neutral = re.sub(r"(\s*&&\s*)?1\s*==\s*1", "", neutral)
        neutral = re.sub(r"(\s*\|\|\s*)?1\s*==\s*0", "", neutral)

        return neutral.strip() if neutral.strip() else "test"

    @staticmethod
    def _boolean_variant(obj: Any, is_true: bool) -> Any:
        """Genera variante true/false para MongoDB."""
        if isinstance(obj, dict):
            result = obj.copy()

            for key, value in list(result.items()):
                if key == "$where":
                    expr = str(value)
                    if "==" in expr or "!=" in expr:
                        if is_true:
                            expr = re.sub(r"1==0", "1==1", expr)
                            expr = re.sub(r"'1'='0'", "'1'='1'", expr)
                        else:
                            expr = re.sub(r"1==1", "1==0", expr)
                            expr = re.sub(r"'1'='1'", "'1'='0'", expr)
                        result[key] = expr

                elif key == "$ne":
                    if is_true:
                        result["$eq"] = value
                        del result[key]
                    else:
                        result[key] = value

                elif key == "$gt":
                    if is_true:
                        result["$gt"] = value
                    else:
                        result["$lte"] = value
                        del result[key]

                elif key == "$lt":
                    if is_true:
                        result["$lt"] = value
                    else:
                        result["$gte"] = value
                        del result[key]

                elif isinstance(value, dict):
                    result[key] = MongoDBStrategy._boolean_variant(value, is_true)

            return result

        return obj

    @staticmethod
    def _string_variant(payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Intenta generar variantes a partir de un payload string."""
        true_variant = payload.replace("1==0", "1==1").replace("'1'='0'", "'1'='1'")
        false_variant = payload.replace("1==1", "1==0").replace("'1'='1'", "'1'='0'")

        if true_variant != payload or false_variant != payload:
            return (true_variant, false_variant)

        return (None, None)

    @staticmethod
    def _neutral_variant(obj: Any) -> Optional[Any]:
        """Elimina condiciones booleanas en MongoDB."""
        if isinstance(obj, dict):
            result = {}

            for key, value in obj.items():
                if key in ("$where", "$expr"):
                    continue
                elif key in ("$ne", "$gt", "$lt", "$eq", "$gte", "$lte"):
                    continue
                elif isinstance(value, dict):
                    nested = MongoDBStrategy._neutral_variant(value)
                    if nested:
                        result[key] = nested
                else:
                    result[key] = value

            return result if result else None

        return None


class Neo4jStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para Neo4j."""

    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE/FALSE para Neo4j (Cypher)."""
        true_variant = payload.replace("false", "TRUE_PLACEHOLDER").replace("true", "false").replace(
            "TRUE_PLACEHOLDER", "true"
        )
        false_variant = payload.replace("true", "FALSE_PLACEHOLDER").replace("false", "true").replace(
            "FALSE_PLACEHOLDER", "false"
        )

        if true_variant != payload or false_variant != payload:
            return (true_variant, false_variant)

        return (None, None)

    def generate_neutral_payload(self, payload: str) -> str:
        """Elimina condiciones booleanas en Neo4j."""
        neutral = payload
        neutral = re.sub(r"\s+(true|false)\s*$", "", neutral)
        neutral = re.sub(r"where\s+(true|false)", "where 1=1", neutral)

        return neutral.strip() if neutral.strip() else "test"


def get_engine_strategy(engine: str) -> NoSQLEngineStrategy:
    """Obtiene la estrategia especializada para un motor NoSQL.

    Args:
        engine: Nombre del motor (mongodb, couchdb, neo4j, etc.)

    Returns:
        Instancia de NoSQLEngineStrategy específica del motor

    Raises:
        ValueError: Si el motor no es soportado
    """
    engine_lower = engine.lower()

    if "mongodb" in engine_lower or "mongo" in engine_lower:
        return MongoDBStrategy()

    elif "neo4j" in engine_lower:
        return Neo4jStrategy()

    # No incluimos CouchDB aquí, será importado desde couchdb_detection
    else:
        raise ValueError(f"Motor NoSQL no soportado: {engine}. Use un motor conocido o cree una estrategia personalizada.")
